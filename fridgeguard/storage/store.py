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
import re
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

SCHEMA_VERSION = "3"

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
    "alert_ids": None,  # list of alert IDs, handled in _query
    "rule_id": "rule_id = ?",
    "assigned_to": "assigned_to = ?",
    "min_severity": "severity_rank >= ?",
    "severity": "severity = ?",
    "device": "device_id = ?",
    "status": "status = ?",
    "since": "first_seen >= ?",
    "until": "first_seen < ?",
}
SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")  # lowest first

# Alert triage workflow (Step 10). A note is required for every move marked True.
ALERT_STATUSES = ("new", "under_investigation", "confirmed", "false_positive", "resolved")
ALERT_TRANSITIONS: dict[str, dict[str, bool]] = {
    "new": {"under_investigation": False, "false_positive": True, "resolved": True},
    "under_investigation": {"confirmed": True, "false_positive": True, "resolved": True},
    "confirmed": {"resolved": True},
    "false_positive": {"under_investigation": True},  # reopen
    "resolved": {"under_investigation": True},  # reopen
}
# Status names used before Step 10, mapped when an older database is opened.
LEGACY_ALERT_STATUS = {"open": "new", "acknowledged": "under_investigation"}

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
            schema = _load_schema()
            self._migrate_alerts(schema)
            self.conn.executescript(schema)
            self.conn.execute(
                "INSERT INTO schema_info (key, value) VALUES ('version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (SCHEMA_VERSION,),
            )
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._devices = {r[0] for r in self.conn.execute("SELECT device_id FROM devices")}

    def _migrate_alerts(self, schema: str) -> None:
        """Upgrade an alerts table created before Step 10 (new severity level, statuses
        and triage columns). SQLite cannot change a CHECK constraint in place, so the
        table is rebuilt with the same row IDs; alert_evidence keeps pointing at them."""
        columns = {r[1] for r in self.conn.execute("PRAGMA table_info(alerts)")}
        if not columns or "base_severity" in columns:
            return
        create = re.search(r"CREATE TABLE IF NOT EXISTS alerts \(.*?\n\);", schema, re.S)
        if create is None:
            raise RuntimeError("alerts definition not found in schema.sql")
        legacy = " ".join(f"WHEN '{old}' THEN '{new}'" for old, new in LEGACY_ALERT_STATUS.items())
        copied = (
            "id, alert_key, rule_id, rule_name, severity, device_id, subject, title, "
            "description, attack_ids, implements, first_seen, created_at"
        )
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.executescript(
            f"""BEGIN;
            DROP VIEW IF EXISTS v_alerts;
            {create.group(0).replace("IF NOT EXISTS alerts", "alerts_v3")}
            INSERT INTO alerts_v3 ({copied}, status, base_severity)
                SELECT {copied}, CASE status {legacy} ELSE status END, severity FROM alerts;
            DROP TABLE alerts;
            ALTER TABLE alerts_v3 RENAME TO alerts;
            COMMIT;"""
        )
        self.conn.execute("PRAGMA foreign_keys = ON")

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
        alert = {"base_severity": alert["severity"], **alert}
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

    # ---- prioritization support (Step 10) ----------------------------------------------
    def security_rows(self, event_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """Security events by event ID (``EVT-…``); other IDs are ignored."""
        ids = sorted({i for i in event_ids if i.startswith("EVT-")})
        found: dict[str, dict[str, Any]] = {}
        for start in range(0, len(ids), 500):
            part = ids[start : start + 500]
            marks = ", ".join("?" for _ in part)
            rows = self.conn.execute(
                f"SELECT * FROM security_events WHERE event_id IN ({marks})", part
            )
            found.update((r["event_id"], dict(r)) for r in rows)
        return found

    def readings_from(self, device_id: str, since: datetime, until: datetime):
        """Readings of one device from ``since`` to ``until`` (inclusive), oldest first."""
        rows = self.conn.execute(
            """SELECT * FROM telemetry WHERE device_id = ? AND ts_device >= ? AND ts_device <= ?
               ORDER BY ts_device, id""",
            (device_id, iso_utc(since), iso_utc(until)),
        )
        return [dict(r) for r in rows]

    # ---- alert management (Step 10) ------------------------------------------------------
    def alert_queue(self, min_severity: str = "LOW", limit: int | None = None, **filters):
        """Open alerts (new, under investigation), most severe first, then oldest first."""
        rows = [
            r
            for r in self.alerts(min_severity=SEVERITY_LEVELS.index(min_severity), **filters)
            if r["status"] in ("new", "under_investigation")
        ]
        rows.sort(key=lambda r: (-r["severity_rank"], r["first_seen"], r["ref"]))
        return rows[:limit] if limit else rows

    def set_alert_status(
        self,
        alert_id: str,
        status: str,
        actor: str,
        note: str = "",
        *,
        assign: bool = True,
    ) -> dict[str, Any]:
        """Move an alert through the triage workflow and record it in alert_history.

        Confirming an alert marks the security events in its evidence ``malicious``;
        calling it a false positive marks them ``normal`` (set by the analyst).
        """
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        alert = self.alert(alert_id)
        if alert is None:
            raise KeyError(f"unknown alert {alert_id}")
        current = alert["status"]
        allowed = ALERT_TRANSITIONS[current]
        if status not in allowed:
            options = ", ".join(allowed) or "none"
            raise ValueError(f"{alert_id} is '{current}'; it can move to: {options}")
        note = note.strip()
        if allowed[status] and not note:
            raise ValueError(f"a note is required to mark an alert '{status}'")
        now = iso_utc(datetime.now(UTC))
        self._alert_history(alert["ref"], now, actor, "status", current, status, note)
        self.conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, alert["ref"]),
        )
        if status == "under_investigation" and assign and alert["assigned_to"] != actor:
            self._alert_history(
                alert["ref"],
                now,
                actor,
                "assigned_to",
                alert["assigned_to"],
                actor,
                "assigned when the investigation started",
            )
            self.conn.execute(
                "UPDATE alerts SET assigned_to = ? WHERE id = ?", (actor, alert["ref"])
            )
        verdict = {"confirmed": "malicious", "false_positive": "normal"}.get(status)
        if verdict:
            reason = f"analyst marked {alert_id} {status}: {note}"
            for ev in self.alert_evidence(alert_id):
                if ev["kind"] == "security":
                    self._add_status(
                        self._event_ref(ev["record_id"]), verdict, reason, f"analyst:{actor}", now
                    )
        self.commit()
        return self.alert(alert_id)

    def set_alert_severity(
        self, alert_id: str, severity: str, actor: str, note: str, *, lock: bool = True
    ) -> bool:
        """Change an alert's severity. Analyst changes (``lock=True``) need a note and
        stop automatic re-prioritization; the prioritizer calls this with ``lock=False``.
        Returns True if the severity changed."""
        if severity not in SEVERITY_LEVELS:
            raise ValueError(f"severity must be one of {SEVERITY_LEVELS}")
        alert = self.alert(alert_id)
        if alert is None:
            raise KeyError(f"unknown alert {alert_id}")
        note = note.strip()
        if lock and not note:
            raise ValueError("a note is required to change an alert's severity")
        if not lock and alert["severity_locked"]:
            return False
        if severity == alert["severity"] and (not lock or alert["severity_locked"]):
            if not lock and note != alert["severity_reason"]:
                self.conn.execute(
                    "UPDATE alerts SET severity_reason = ? WHERE id = ?", (note, alert["ref"])
                )
            return False
        now = iso_utc(datetime.now(UTC))
        self._alert_history(alert["ref"], now, actor, "severity", alert["severity"], severity, note)
        self.conn.execute(
            """UPDATE alerts SET severity = ?, severity_reason = ?, severity_locked = ?,
               updated_at = ? WHERE id = ?""",
            (severity, note, int(lock or alert["severity_locked"]), now, alert["ref"]),
        )
        if lock:
            self.commit()
        return True

    def alert_history(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT h.ts, h.actor, h.field, h.old_value, h.new_value, h.note
               FROM alert_history h JOIN alerts a ON a.id = h.alert_ref
               WHERE a.alert_id = ? ORDER BY h.id""",
            (alert_id,),
        )
        return [dict(r) for r in rows]

    def alert_counts(self) -> dict[str, dict[str, int]]:
        q = self.conn.execute
        return {
            "by_severity": dict(q("SELECT severity, COUNT(*) FROM alerts GROUP BY 1")),
            "by_status": dict(q("SELECT status, COUNT(*) FROM alerts GROUP BY 1")),
        }

    def _alert_history(self, ref, ts, actor, field, old, new, note) -> None:
        self.conn.execute(
            """INSERT INTO alert_history (alert_ref, ts, actor, field, old_value, new_value, note)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ref, ts, actor, field, old, new, note),
        )

    def _event_ref(self, event_id: str) -> int:
        row = self.conn.execute(
            "SELECT id FROM security_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown event {event_id}")
        return row[0]

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
            if key.endswith("_ids"):
                values = list(value)
                column = key[:-1]  # alert_ids -> alert_id
                clauses.append(f"{column} IN ({', '.join('?' for _ in values)})" if values else "0")
                params.extend(values)
                continue
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
