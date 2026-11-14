"""Centralized SQLite event database (Phase 2, Step 7).

``EventStore`` is the only component that writes events. It

* creates the schema (``schema.sql``) and registers the devices,
* validates and normalises every incoming event (``normalize.py``),
* stores telemetry and security events in separate append-only tables,
* records the status of each security event in an append-only history,
* rejects invalid events into ``rejected_events`` instead of silently dropping them,
* ignores duplicates (same source event ID), so re-importing a log is safe,
* can re-verify every stored event against its SHA-256 hash.
"""

from __future__ import annotations

import heapq
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from fridgeguard.models import Event, iso_utc
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage.normalize import STATUSES, ValidationError, event_from_json, normalize

SCHEMA_VERSION = "2"

SECURITY_FILTERS = {
    "device": "device = ?",
    "event_type": "event_type = ?",
    "user": "user = ?",
    "status": "status = ?",
    "scenario": "scenario = ?",
    "since": "timestamp >= ?",
    "until": "timestamp < ?",
}
ALERT_FILTERS = {
    "rule_id": "rule_id = ?",
    "severity": "severity = ?",
    "device": "device_id = ?",
    "status": "status = ?",
    "since": "first_seen >= ?",
    "until": "first_seen < ?",
}
TELEMETRY_FILTERS = {
    "device": "device_id = ?",
    "device_status": "device_status = ?",
    "since": "ts_device >= ?",
    "until": "ts_device < ?",
}


@dataclass
class IngestResult:
    table: str | None  # "telemetry", "security_events", None if rejected/duplicate
    ref: int | None = None
    duplicate: bool = False
    error: str | None = None


def _load_schema() -> str:
    return resources.files("fridgeguard.storage").joinpath("schema.sql").read_text("utf-8")


class EventStore:
    def __init__(self, path: Path | str, *, read_only: bool = False):
        self.path = Path(path) if str(path) != ":memory:" else path
        self.read_only = read_only
        if read_only:
            uri = f"file:{Path(path).as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            if isinstance(self.path, Path):
                self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(path), check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.executescript(_load_schema())
            self.conn.execute(
                "INSERT INTO schema_info (key, value) VALUES ('version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (SCHEMA_VERSION,),
            )
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._devices = {r[0] for r in self.conn.execute("SELECT device_id FROM devices")}

    # ---- setup -----------------------------------------------------------------------
    def register_devices(self, fleet: Fleet) -> None:
        rows = [
            (
                f.device_id,
                f.spec.name,
                f.spec.location,
                f.spec.device_type,
                f.spec.safe_min_c,
                f.spec.safe_max_c,
            )
            for f in fleet
        ]
        self.conn.executemany(
            """INSERT INTO devices (device_id, name, location, device_type, safe_min_c, safe_max_c)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_id) DO UPDATE SET
                 name = excluded.name, location = excluded.location,
                 device_type = excluded.device_type,
                 safe_min_c = excluded.safe_min_c, safe_max_c = excluded.safe_max_c""",
            rows,
        )
        self.conn.commit()
        self._devices.update(r[0] for r in rows)

    # ---- writing ---------------------------------------------------------------------
    def ingest(self, event: Event, ts_ingest: datetime | None = None) -> IngestResult:
        """Validate and store one event. Call :meth:`commit` to make it durable."""
        received = iso_utc(ts_ingest or datetime.now(UTC))
        try:
            item = normalize(event, self._devices, received)
        except (ValidationError, ValueError, TypeError) as exc:
            self._reject(event.to_json(), str(exc), received)
            return IngestResult(None, error=str(exc))

        columns = ", ".join(item.row)
        marks = ", ".join("?" for _ in item.row)
        cur = self.conn.execute(
            f"INSERT OR IGNORE INTO {item.table} ({columns}) VALUES ({marks})",
            list(item.row.values()),
        )
        if cur.rowcount == 0:
            return IngestResult(item.table, duplicate=True)
        ref = cur.lastrowid
        if item.status is not None:
            reason = "; ".join(item.status_reasons) or "no issues found at ingest"
            self._add_status(ref, item.status, reason, "ingest", received)
        return IngestResult(item.table, ref)

    def ingest_json_line(self, line: str, ts_ingest: datetime | None = None) -> IngestResult:
        received = ts_ingest or datetime.now(UTC)
        try:
            event = event_from_json(line)
        except (ValidationError, ValueError) as exc:
            self._reject(line, str(exc), iso_utc(received))
            return IngestResult(None, error=str(exc))
        return self.ingest(event, received)

    def set_status(self, event_id: str, status: str, reason: str, set_by: str) -> None:
        """Append a new status for a security event (detection rule or analyst)."""
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        row = self.conn.execute(
            "SELECT id FROM security_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown event {event_id}")
        self._add_status(row[0], status, reason, set_by, iso_utc(datetime.now(UTC)))
        self.commit()

    def commit(self) -> None:
        self.conn.commit()

    # ---- detection support (Step 8) ----------------------------------------------------
    def raise_status(self, record_id: str, status: str, reason: str, set_by: str, ts: str) -> bool:
        """Record a rule's verdict on a security event.

        The status is appended only if it is not lower than the current one and this rule
        has not already judged the event (so re-running detection adds nothing).
        Returns True if a row was appended.
        """
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        row = self.conn.execute(
            """SELECT e.id, COALESCE(s.status, 'normal') AS current
               FROM security_events e LEFT JOIN v_event_status s ON s.event_ref = e.id
               WHERE e.event_id = ?""",
            (record_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown event {record_id}")
        if STATUSES.index(status) < STATUSES.index(row["current"]):
            return False
        seen = self.conn.execute(
            "SELECT 1 FROM event_status_history WHERE event_ref = ? AND set_by = ?",
            (row["id"], set_by),
        ).fetchone()
        if seen:
            return False
        self._add_status(row["id"], status, reason, set_by, ts)
        return True

    def get_or_create_alert(self, alert: dict[str, Any]) -> tuple[str, bool]:
        """Insert an alert unless one with the same ``alert_key`` exists.

        Returns ``(alert_id, created)``.
        """
        columns = ", ".join(alert)
        marks = ", ".join("?" for _ in alert)
        cur = self.conn.execute(
            f"INSERT OR IGNORE INTO alerts ({columns}) VALUES ({marks})", list(alert.values())
        )
        alert_id = self.conn.execute(
            "SELECT alert_id FROM alerts WHERE alert_key = ?", (alert["alert_key"],)
        ).fetchone()[0]
        return alert_id, cur.rowcount == 1

    def add_evidence(self, alert_id: str, record_id: str, kind: str, ts: str, note: str) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO alert_evidence (alert_ref, record_id, kind, ts, note)
               SELECT id, ?, ?, ?, ? FROM alerts WHERE alert_id = ?""",
            (record_id, kind, ts, note, alert_id),
        )

    def iter_records(self):
        """All stored telemetry and security events, merged in time order.

        Yields ``(kind, row)`` with kind ``"telemetry"`` or ``"security"``. Within the same
        timestamp, security events come first (they happened between two readings).
        """
        sec = self.conn.execute(
            """SELECT e.*, COALESCE(s.status, 'normal') AS status
               FROM security_events e LEFT JOIN v_event_status s ON s.event_ref = e.id
               ORDER BY e.ts_device, e.id"""
        )
        tel = self.conn.execute("SELECT * FROM telemetry ORDER BY ts_device, id")
        tagged_sec = ((r["ts_device"], 0, r["id"], "security", dict(r)) for r in sec)
        tagged_tel = ((r["ts_device"], 1, r["id"], "telemetry", dict(r)) for r in tel)
        for _, _, _, kind, row in heapq.merge(tagged_sec, tagged_tel):
            yield kind, row

    def record_row(self, kind: str, ref: int) -> dict[str, Any]:
        """One stored record by internal row id (used by the live pipeline)."""
        if kind == "telemetry":
            sql = "SELECT * FROM telemetry WHERE id = ?"
        else:
            sql = """SELECT e.*, COALESCE(s.status, 'normal') AS status
                     FROM security_events e LEFT JOIN v_event_status s ON s.event_ref = e.id
                     WHERE e.id = ?"""
        return dict(self.conn.execute(sql, (ref,)).fetchone())

    def alerts(self, limit: int | None = None, newest_first: bool = False, **filters):
        return self._query(
            "v_alerts", "first_seen, ref", ALERT_FILTERS, filters, limit, newest_first
        )

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM v_alerts WHERE alert_id = ?", (alert_id,))
        found = row.fetchone()
        return dict(found) if found else None

    def alert_evidence(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT ev.record_id, ev.kind, ev.ts, ev.note FROM alert_evidence ev
               JOIN alerts a ON a.id = ev.alert_ref
               WHERE a.alert_id = ? ORDER BY ev.ts, ev.record_id""",
            (alert_id,),
        )
        return [dict(r) for r in rows]

    def close(self) -> None:
        if not self.read_only:
            self.conn.commit()
        self.conn.close()

    def _add_status(self, ref: int, status: str, reason: str, set_by: str, ts: str) -> None:
        self.conn.execute(
            "INSERT INTO event_status_history (event_ref, ts, status, reason, set_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (ref, ts, status, reason, set_by),
        )

    def _reject(self, raw: str, error: str, ts: str) -> None:
        self.conn.execute(
            "INSERT INTO rejected_events (ts_ingest, error, raw_json) VALUES (?, ?, ?)",
            (ts, error, raw),
        )

    # ---- reading ---------------------------------------------------------------------
    def security_events(self, limit: int | None = None, newest_first: bool = False, **filters):
        return self._query(
            "v_security_events", "timestamp, ref", SECURITY_FILTERS, filters, limit, newest_first
        )

    def telemetry(self, limit: int | None = None, newest_first: bool = False, **filters):
        return self._query(
            "telemetry", "ts_device, id", TELEMETRY_FILTERS, filters, limit, newest_first
        )

    def status_history(self, event_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT h.ts, h.status, h.reason, h.set_by FROM event_status_history h
               JOIN security_events e ON e.id = h.event_ref
               WHERE e.event_id = ? ORDER BY h.id""",
            (event_id,),
        )
        return [dict(r) for r in rows]

    def rejected(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM rejected_events ORDER BY id")]

    def stats(self) -> dict[str, Any]:
        q = self.conn.execute
        return {
            "devices": q("SELECT COUNT(*) FROM devices").fetchone()[0],
            "telemetry": q("SELECT COUNT(*) FROM telemetry").fetchone()[0],
            "security_events": q("SELECT COUNT(*) FROM security_events").fetchone()[0],
            "rejected": q("SELECT COUNT(*) FROM rejected_events").fetchone()[0],
            "alerts": q("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "by_type": dict(
                q("SELECT event_type, COUNT(*) FROM security_events GROUP BY 1 ORDER BY 2 DESC")
            ),
            "by_status": dict(
                q("SELECT status, COUNT(*) FROM v_security_events GROUP BY 1 ORDER BY 2 DESC")
            ),
            "time_range": tuple(
                q("SELECT MIN(ts_device), MAX(ts_device) FROM telemetry").fetchone()
            ),
        }

    def verify_integrity(self) -> list[str]:
        """Recompute every stored event's SHA-256 hash. Returns a list of problems."""
        problems = []
        for table, id_col in (("telemetry", "reading_id"), ("security_events", "event_id")):
            for row in self.conn.execute(f"SELECT {id_col}, hash, raw_json FROM {table}"):
                try:
                    event = Event(**json.loads(row["raw_json"]))
                except (TypeError, ValueError):
                    problems.append(f"{row[id_col]}: stored record cannot be parsed")
                    continue
                if event.compute_hash() != row["hash"] or event.hash != row["hash"]:
                    problems.append(f"{row[id_col]}: hash mismatch")
        return problems

    def _query(self, source, order, allowed, filters, limit, newest_first):
        clauses, params = [], []
        for key, value in filters.items():
            if value is None:
                continue
            if key not in allowed:
                raise ValueError(f"unknown filter {key!r}")
            clauses.append(allowed[key])
            params.append(value)
        sql = f"SELECT * FROM {source}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        direction = " DESC" if newest_first else ""
        sql += " ORDER BY " + ", ".join(col + direction for col in order.split(", "))
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return [dict(r) for r in self.conn.execute(sql, params)]


def import_jsonl(store: EventStore, lines: Iterable[str]) -> dict[str, int]:
    """Load a JSON Lines event log; the ingest time is the event's own timestamp."""
    counts = {"telemetry": 0, "security_events": 0, "duplicates": 0, "rejected": 0}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ts = json.loads(line).get("ts_device")
            received = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
        except (ValueError, AttributeError):
            received = None
        result = store.ingest_json_line(line, received)
        if result.error:
            counts["rejected"] += 1
        elif result.duplicate:
            counts["duplicates"] += 1
        else:
            counts[result.table] += 1
    store.commit()
    return counts
