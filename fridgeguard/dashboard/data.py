"""Data access for the SOC dashboard (Phase 3, Step 11).

Pure functions that turn the event database into pandas DataFrames. They have no
Streamlit dependency, so they are unit-tested directly; the dashboard pages add caching
and presentation on top.

All timestamps are returned as timezone-aware UTC ``datetime64`` columns; ``local_*``
columns use the site timezone from ``config/devices.yaml``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pandas as pd

from fridgeguard.config import load_yaml
from fridgeguard.models import iso_utc
from fridgeguard.storage import EventStore
from fridgeguard.timeutil import TimeWindow, parse_hhmm

PRIVILEGED_ROLES = {"technician", "admin"}
OPEN_ALERT_STATUSES = ("new", "under_investigation")
WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


# ---- site configuration ---------------------------------------------------------------
@dataclass(frozen=True)
class Site:
    name: str
    tz: ZoneInfo
    opening_start: str
    opening_end: str
    maintenance: TimeWindow
    maintenance_text: str
    devices: dict[str, dict[str, Any]]

    @classmethod
    def from_config(cls, config_dir: Path | None = None) -> Site:
        dev = load_yaml("devices.yaml", config_dir)
        users = load_yaml("users.yaml", config_dir)
        site = dev["site"]
        tz = ZoneInfo(site["timezone"])
        mw = users["maintenance_window"]
        days = mw.get("days") or []
        return cls(
            name=site["name"],
            tz=tz,
            opening_start=site["opening_hours"]["start"],
            opening_end=site["opening_hours"]["end"],
            maintenance=TimeWindow(mw["start"], mw["end"], tz, days),
            maintenance_text=f"{', '.join(d.capitalize() for d in days)} {mw['start']}-{mw['end']}",
            devices={d["device_id"]: d for d in dev["devices"]},
        )

    def allowed_ips(self, device_id: str) -> set[str]:
        return set(self.devices.get(device_id, {}).get("allowed_ips") or [])

    def store_open(self, ts: datetime) -> bool:
        t = ts.astimezone(self.tz).time()
        return parse_hhmm(self.opening_start) <= t < parse_hhmm(self.opening_end)


def _utc(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True, format="ISO8601")


def _frame(rows: list[dict[str, Any]], columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=columns) if not rows else pd.DataFrame(rows)


# ---- time range -------------------------------------------------------------------------
def data_bounds(store: EventStore) -> tuple[datetime, datetime] | None:
    """Oldest and newest record in the database (UTC), or None if it is empty."""
    q = store.conn.execute
    lo = q(
        "SELECT MIN(ts) FROM (SELECT MIN(ts_device) AS ts FROM telemetry "
        "UNION ALL SELECT MIN(ts_device) FROM security_events)"
    ).fetchone()[0]
    hi = q(
        "SELECT MAX(ts) FROM (SELECT MAX(ts_device) AS ts FROM telemetry "
        "UNION ALL SELECT MAX(ts_device) FROM security_events)"
    ).fetchone()[0]
    if lo is None or hi is None:
        return None
    return pd.Timestamp(lo).to_pydatetime(), pd.Timestamp(hi).to_pydatetime()


# ---- devices and temperature ---------------------------------------------------------------
def devices(store: EventStore) -> pd.DataFrame:
    rows = [dict(r) for r in store.conn.execute("SELECT * FROM devices ORDER BY device_id")]
    return _frame(
        rows, ["device_id", "name", "location", "device_type", "safe_min_c", "safe_max_c"]
    )


TELEMETRY_COLUMNS = [
    "reading_id",
    "ts",
    "device_id",
    "temperature_c",
    "setpoint_c",
    "expected_min_c",
    "expected_max_c",
    "device_status",
    "door_open",
    "compressor_on",
]


def telemetry(
    store: EventStore,
    since: datetime | None = None,
    until: datetime | None = None,
    device_ids: list[str] | None = None,
) -> pd.DataFrame:
    sql = (
        "SELECT reading_id, ts_device AS ts, device_id, temperature_c, setpoint_c, "
        "expected_min_c, expected_max_c, device_status, door_open, compressor_on "
        "FROM telemetry WHERE 1 = 1"
    )
    params: list[Any] = []
    if since:
        sql += " AND ts_device >= ?"
        params.append(iso_utc(since))
    if until:
        sql += " AND ts_device <= ?"
        params.append(iso_utc(until))
    if device_ids:
        sql += f" AND device_id IN ({', '.join('?' for _ in device_ids)})"
        params.extend(device_ids)
    sql += " ORDER BY ts_device, id"
    df = pd.read_sql_query(sql, store.conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=TELEMETRY_COLUMNS)
    df["ts"] = _utc(df["ts"])
    df["out_of_range"] = (df["temperature_c"] < df["expected_min_c"]) | (
        df["temperature_c"] > df["expected_max_c"]
    )
    df["deviation_c"] = (
        (df["temperature_c"] - df["expected_max_c"]).clip(lower=0)
        + (df["expected_min_c"] - df["temperature_c"]).clip(lower=0)
    ).round(2)
    return df


def abnormal_readings(tel: pd.DataFrame) -> pd.DataFrame:
    """Readings outside the expected range, worst first within each excursion."""
    if tel.empty or "out_of_range" not in tel:
        return pd.DataFrame(columns=[*TELEMETRY_COLUMNS, "deviation_c"])
    out = tel[tel["out_of_range"]].copy()
    return out.sort_values(["ts"], ascending=False)


def excursions(tel: pd.DataFrame) -> pd.DataFrame:
    """Continuous runs of out-of-range readings per device."""
    columns = ["device_id", "start", "end", "minutes", "readings", "worst_c", "max_deviation_c"]
    if tel.empty or "out_of_range" not in tel:
        return pd.DataFrame(columns=columns)
    rows = []
    for device_id, g in tel.sort_values("ts").groupby("device_id"):
        run_id = (g["out_of_range"] != g["out_of_range"].shift()).cumsum()
        for _, run in g[g["out_of_range"]].groupby(run_id[g["out_of_range"]]):
            worst = run.loc[run["deviation_c"].idxmax()]
            rows.append(
                {
                    "device_id": device_id,
                    "start": run["ts"].iloc[0],
                    "end": run["ts"].iloc[-1],
                    "minutes": round((run["ts"].iloc[-1] - run["ts"].iloc[0]).total_seconds() / 60)
                    + 1,
                    "readings": len(run),
                    "worst_c": worst["temperature_c"],
                    "max_deviation_c": worst["deviation_c"],
                }
            )
    return pd.DataFrame(rows, columns=columns)


def device_comparison(tel: pd.DataFrame, devs: pd.DataFrame) -> pd.DataFrame:
    """One row per device: range, observed min/mean/max, time in range, excursions."""
    columns = [
        "device_id",
        "name",
        "expected_range",
        "readings",
        "min_c",
        "mean_c",
        "max_c",
        "in_range_pct",
        "minutes_out",
        "excursions",
        "latest_c",
        "latest_status",
    ]
    if tel.empty:
        return pd.DataFrame(columns=columns)
    exc = excursions(tel)
    rows = []
    for device_id, g in tel.groupby("device_id"):
        info = (
            devs.set_index("device_id").loc[device_id]
            if device_id in set(devs["device_id"])
            else None
        )
        last = g.iloc[-1]
        rows.append(
            {
                "device_id": device_id,
                "name": info["name"] if info is not None else device_id,
                "expected_range": (
                    f"{last['expected_min_c']:.1f} .. {last['expected_max_c']:.1f} °C"
                ),
                "readings": len(g),
                "min_c": round(g["temperature_c"].min(), 2),
                "mean_c": round(g["temperature_c"].mean(), 2),
                "max_c": round(g["temperature_c"].max(), 2),
                "in_range_pct": round(100 * (1 - g["out_of_range"].mean()), 1),
                "minutes_out": int(exc.loc[exc["device_id"] == device_id, "minutes"].sum()),
                "excursions": int((exc["device_id"] == device_id).sum()),
                "latest_c": last["temperature_c"],
                "latest_status": last["device_status"],
            }
        )
    return pd.DataFrame(rows, columns=columns)


# ---- security monitoring ------------------------------------------------------------------
SECURITY_COLUMNS = [
    "event_id",
    "ts",
    "device_id",
    "event_type",
    "category",
    "user",
    "role",
    "source_ip",
    "parameter",
    "previous_value",
    "new_value",
    "unit",
    "result",
    "reason",
    "authorized",
    "within_maintenance_window",
    "session_id",
    "status",
]


def security_events(
    store: EventStore,
    site: Site,
    since: datetime | None = None,
    until: datetime | None = None,
) -> pd.DataFrame:
    sql = (
        "SELECT e.event_id, e.ts_device AS ts, e.device_id, e.event_type, e.category, e.user, "
        "e.role, e.source_ip, e.parameter, e.previous_value, e.new_value, e.unit, e.result, "
        "e.reason, e.authorized, e.within_maintenance_window, e.session_id, "
        "COALESCE(s.status, 'normal') AS status "
        "FROM security_events e LEFT JOIN v_event_status s ON s.event_ref = e.id WHERE 1 = 1"
    )
    params: list[Any] = []
    if since:
        sql += " AND e.ts_device >= ?"
        params.append(iso_utc(since))
    if until:
        sql += " AND e.ts_device <= ?"
        params.append(iso_utc(until))
    sql += " ORDER BY e.ts_device, e.id"
    df = pd.read_sql_query(sql, store.conn, params=params)
    if df.empty:
        return pd.DataFrame(
            columns=[
                *SECURITY_COLUMNS,
                *("local_ts", "hour", "weekday", "allowed_ip", "store_open", "in_maintenance"),
            ]
        )
    df["ts"] = _utc(df["ts"])
    local = df["ts"].dt.tz_convert(site.tz)
    df["local_ts"] = local
    df["hour"] = local.dt.hour
    df["weekday"] = local.dt.day_of_week
    df["allowed_ip"] = [
        ip in site.allowed_ips(d) for ip, d in zip(df["source_ip"], df["device_id"], strict=True)
    ]
    df["store_open"] = [site.store_open(t.to_pydatetime()) for t in df["ts"]]
    df["in_maintenance"] = [site.maintenance.contains(t.to_pydatetime()) for t in df["ts"]]
    return df


def auth_per_hour(sec: pd.DataFrame, freq: str = "h") -> pd.DataFrame:
    """Successful and failed logins per time bucket (default one hour, UTC)."""
    auth = sec[sec["event_type"].isin(["LOGIN_SUCCESS", "LOGIN_FAILURE"])]
    if auth.empty:
        return pd.DataFrame(columns=["hour", "outcome", "count"])
    out = (
        auth.assign(
            hour=auth["ts"].dt.floor(freq),
            outcome=auth["event_type"].map(
                {"LOGIN_SUCCESS": "Successful", "LOGIN_FAILURE": "Failed"}
            ),
        )
        .groupby(["hour", "outcome"])
        .size()
        .reset_index(name="count")
    )
    return out


def suspicious_ips(sec: pd.DataFrame) -> pd.DataFrame:
    """Source IPs that are off the device allow-list or produced failed logins."""
    columns = [
        "source_ip",
        "on_allow_list",
        "failed",
        "successful",
        "changes",
        "usernames_tried",
        "devices",
        "first_seen",
        "last_seen",
        "suspicious_events",
    ]
    if sec.empty:
        return pd.DataFrame(columns=columns)
    rows = []
    for ip, g in sec.groupby("source_ip"):
        failed = g[g["event_type"] == "LOGIN_FAILURE"]
        allowed = bool(g["allowed_ip"].all())
        if allowed and failed.empty:
            continue
        rows.append(
            {
                "source_ip": ip,
                "on_allow_list": allowed,
                "failed": len(failed),
                "successful": int((g["event_type"] == "LOGIN_SUCCESS").sum()),
                "changes": int((g["category"] == "configuration").sum()),
                "usernames_tried": ", ".join(sorted(failed["user"].unique())),
                "devices": ", ".join(sorted(g["device_id"].unique())),
                "first_seen": g["ts"].min(),
                "last_seen": g["ts"].max(),
                "suspicious_events": int(g["status"].isin(["suspicious", "malicious"]).sum()),
            }
        )
    df = pd.DataFrame(rows, columns=columns)
    return df.sort_values(["on_allow_list", "failed"], ascending=[True, False]).reset_index(
        drop=True
    )


def unusual_access(sec: pd.DataFrame) -> pd.DataFrame:
    """Logins and changes while the store is closed (outside the maintenance window), or
    privileged activity outside the maintenance window, with the reason."""
    acted = sec[(sec["event_type"] == "LOGIN_SUCCESS") | (sec["category"] == "configuration")]
    if acted.empty:
        return acted.assign(why=pd.Series(dtype=str))
    reasons = []
    for _, r in acted.iterrows():
        why = []
        if not r["store_open"] and not r["in_maintenance"]:
            why.append("store closed")
        if r["role"] in PRIVILEGED_ROLES and r["within_maintenance_window"] == 0:
            why.append("privileged, outside maintenance window")
        reasons.append("; ".join(why))
    out = acted.assign(why=reasons)
    return out[out["why"] != ""].sort_values("ts", ascending=False)


def access_heatmap(sec: pd.DataFrame) -> pd.DataFrame:
    """Successful logins and changes by local weekday x hour (7 x 24, zeros filled)."""
    acted = sec[(sec["event_type"] == "LOGIN_SUCCESS") | (sec["category"] == "configuration")]
    grid = pd.DataFrame(0, index=range(7), columns=range(24))
    if not acted.empty:
        counts = acted.groupby(["weekday", "hour"]).size()
        for (day, hour), n in counts.items():
            grid.loc[day, hour] = n
    grid.index = WEEKDAY_NAMES
    return grid


# ---- alerts -------------------------------------------------------------------------------
def alert_users(store: EventStore) -> dict[str, str]:
    """Users behind each alert's security evidence (failed-login names marked 'tried')."""
    rows = store.conn.execute(
        """SELECT a.alert_id, e.user, e.event_type FROM alert_evidence ev
           JOIN alerts a ON a.id = ev.alert_ref
           JOIN security_events e ON e.event_id = ev.record_id
           WHERE ev.kind = 'security'"""
    )
    acting: dict[str, set[str]] = {}
    tried: dict[str, set[str]] = {}
    for alert_id, user, event_type in rows:
        (tried if event_type == "LOGIN_FAILURE" else acting).setdefault(alert_id, set()).add(user)
    result = {}
    for alert_id in set(acting) | set(tried):
        if alert_id in acting:
            result[alert_id] = ", ".join(sorted(acting[alert_id]))
        else:
            result[alert_id] = "tried: " + ", ".join(sorted(tried[alert_id]))
    return result


ALERT_COLUMNS = [
    "alert_id",
    "first_seen",
    "last_seen",
    "severity",
    "severity_rank",
    "rule_id",
    "rule_name",
    "device_id",
    "user",
    "status",
    "assigned_to",
    "evidence_count",
    "title",
    "severity_reason",
]


def alerts(store: EventStore) -> pd.DataFrame:
    rows = store.alerts()
    if not rows:
        return pd.DataFrame(columns=[*ALERT_COLUMNS, "incident_id"])
    df = pd.DataFrame(rows)
    users = alert_users(store)
    df["user"] = df["alert_id"].map(users).fillna("-")
    df["first_seen"] = _utc(df["first_seen"])
    df["last_seen"] = _utc(df["last_seen"])
    df["incident_id"] = df["alert_id"].map(alert_incidents(store)).fillna("")
    return df


def alert_incidents(store: EventStore) -> dict[str, str]:
    rows = store.conn.execute(
        """SELECT m.record_id, i.incident_id FROM incident_members m
           JOIN incidents i ON i.id = m.incident_ref
           WHERE m.kind = 'alert' AND i.merged_into IS NULL"""
    )
    return dict(rows.fetchall())


# ---- incidents --------------------------------------------------------------------------
JSON_COLUMNS = (
    "steps",
    "confidence_factors",
    "entities",
    "links",
    "attack_ids",
    "implements",
    "questions",
    "response",
)


def incidents(store: EventStore) -> pd.DataFrame:
    rows = store.incidents()
    if not rows:
        return pd.DataFrame(
            columns=[
                "incident_id",
                "first_seen",
                "last_seen",
                "severity",
                "severity_rank",
                "pattern_id",
                "title",
                "confidence",
                "status",
                "verdict",
            ]
        )
    df = pd.DataFrame(rows)
    df["first_seen"] = _utc(df["first_seen"])
    df["last_seen"] = _utc(df["last_seen"])
    return df.sort_values(["severity_rank", "first_seen"], ascending=[False, False])


def incident_detail(store: EventStore, incident_id: str) -> dict[str, Any] | None:
    """Everything the investigation page needs about one incident."""
    inc = store.incident(incident_id)
    if inc is None:
        return None
    for key in JSON_COLUMNS:
        inc[key] = json.loads(inc[key])
    members = pd.DataFrame(store.incident_members(incident_id))
    sec = store.security_rows_with_status(members["record_id"]) if not members.empty else {}
    tel = store.telemetry_rows(members["record_id"]) if not members.empty else {}
    alert_rows = (
        {a["alert_id"]: a for a in store.alerts(alert_ids=list(members["record_id"]))}
        if not members.empty
        else {}
    )
    detail = []
    for _, m in members.iterrows():
        rid = m["record_id"]
        if rid in alert_rows:
            a = alert_rows[rid]
            what = f"{a['rule_id']} {a['severity']}: {a['title']}"
            detail.append(("Alert", a["device_id"], "", "", what, a["severity"]))
        elif rid in sec:
            e = sec[rid]
            change = ""
            if e["parameter"]:
                unit = e["unit"] or ""
                change = (
                    f" {e['parameter']} {e['previous_value']} -> {e['new_value']}{unit}"
                    f" ({e['result']})"
                )
            what = f"{e['event_type']}{change}"
            detail.append(
                ("Security event", e["device_id"], e["user"], e["source_ip"], what, e["status"])
            )
        elif rid in tel:
            t = tel[rid]
            what = (
                f"{t['temperature_c']:.1f} °C "
                f"(range {t['expected_min_c']:.1f}..{t['expected_max_c']:.1f})"
            )
            detail.append(("Telemetry", t["device_id"], "", "", what, t["device_status"]))
        else:
            detail.append(("Record", "", "", "", "", ""))
    if not members.empty:
        extra = pd.DataFrame(
            detail, columns=["type", "device_id", "user", "source_ip", "what", "state"]
        )
        members = pd.concat([members.reset_index(drop=True), extra], axis=1)
        members["ts"] = _utc(members["ts"])
    inc["members"] = members
    inc["alerts"] = list(alert_rows.values())
    inc["reviews"] = store.incident_reviews(incident_id)
    return inc


def incident_context(
    store: EventStore, inc: dict[str, Any], pad: timedelta = timedelta(minutes=30)
) -> pd.DataFrame:
    """Temperature of the incident's devices from ``pad`` before to ``pad`` after it."""
    start = pd.Timestamp(inc["first_seen"]).to_pydatetime() - pad
    end = pd.Timestamp(inc["last_seen"]).to_pydatetime() + pad
    return telemetry(store, start, end, inc["entities"].get("devices") or None)


def incident_report(inc: dict[str, Any]) -> str:
    """A Markdown investigation report for one incident (download from the dashboard)."""
    ent = inc["entities"]
    lines = [
        f"# Incident report {inc['incident_id']}",
        "",
        f"**{inc['title']}**",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Pattern | {inc['pattern_id']} {inc['pattern_name']} |",
        f"| Severity | {inc['severity']} |",
        f"| Confidence | {inc['confidence']} ({inc['confidence_level']}) |",
        f"| Status / verdict | {inc['status']} / {inc['verdict']} |",
        f"| First / last seen (UTC) | {inc['first_seen']} / {inc['last_seen']} |",
        f"| Devices | {', '.join(ent.get('devices', [])) or '-'} |",
        f"| Users | {', '.join(ent.get('users', [])) or '-'} |",
        f"| Source IPs | {', '.join(ent.get('source_ips', [])) or '-'} |",
        f"| ATT&CK | {', '.join(inc['attack_ids'])} |",
        f"| Requirements | {', '.join(inc['implements'])} |",
        "",
        "## Summary",
        "",
        inc["description"],
        "",
        "## Confidence",
        "",
        *[f"- {p:+d} {reason}" for p, reason in inc["confidence_factors"]],
        "",
        "## Event timeline",
        "",
        "| Time (UTC) | Record | Type | Detail | Why it belongs |",
        "|---|---|---|---|---|",
    ]
    members = inc["members"]
    if not members.empty:
        for _, m in members.iterrows():
            ts = m["ts"].strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"| {ts} | {m['record_id']} | {m['type']} | {m['what']} | {m['note']} |")
    lines += [
        "",
        "## Related alerts",
        "",
        *[
            f"- {a['alert_id']} {a['severity']} {a['rule_id']}: {a['title']} ({a['status']})"
            for a in inc["alerts"]
        ],
        "",
        "## Analyst findings",
        "",
    ]
    if inc["reviews"]:
        lines += [
            f"- {r['ts']} {r['analyst']}: {r['status']}, {r['verdict']} - {r['note']}"
            for r in inc["reviews"]
        ]
    else:
        lines.append("- No analyst review yet. Verdict: unverified.")
    lines += [
        "",
        "## Questions to verify",
        "",
        *[f"- [ ] {q}" for q in inc["questions"]],
        "",
        "## Recommended response",
        "",
        *[f"1. {r}" for r in inc["response"]],
        "",
        "_Correlation shows that the events are related; it is not proof of compromise._",
        "",
    ]
    return "\n".join(lines)


# ---- convenience loaders (one database round trip each, used by the cached pages) --------
def device_comparison_frame(store, since=None, until=None, device_ids=None) -> pd.DataFrame:
    ids = list(device_ids) if device_ids else None
    return device_comparison(telemetry(store, since, until, ids), devices(store))


def excursions_frame(store, since=None, until=None, device_ids=None) -> pd.DataFrame:
    ids = list(device_ids) if device_ids else None
    return excursions(telemetry(store, since, until, ids))
