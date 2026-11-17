"""Evidence gathering for an L1 alert investigation (Phase 3, Step 12).

``build_case`` collects everything an analyst needs for one alert, following the steps
of the investigation workflow:

1. review the alert            the alert, its evidence and its triage history
2. identify the refrigerator   device facts and the temperature around the alert
3. examine related events      security events and alerts on the device around the alert
4. investigate user and IP     account profile, permissions, known IPs, recent history
5. authorized?                 a *suggested* answer with the reasons for it
6. potential impact            a *suggested* level with the reasons for it
7. escalation                  *suggested* teams with the reasons for them
8. documentation               the analyst's own entries (``investigation_entries``)

The suggestions are deterministic rules over the stored data. They are there to make the
analyst's reasoning explicit and checkable; the analyst's recorded decision always wins,
and the report says which is which.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fridgeguard.config import load_yaml
from fridgeguard.generator.auth import PARAMETER_PERMISSIONS
from fridgeguard.models import Event, iso_utc
from fridgeguard.storage import EventStore
from fridgeguard.storage.store import INVESTIGATION_STEPS

STEP_LABELS = {
    "review_alert": "Review the alert",
    "affected_device": "Identify the affected refrigerator",
    "related_events": "Examine the related events",
    "user_and_ip": "Investigate the user and source IP",
    "authorization": "Determine whether the activity was authorized",
    "impact": "Assess the potential impact",
    "escalation": "Escalate to the appropriate team if necessary",
    "documentation": "Document the investigation",
}
IMPACT_ORDER = list(INVESTIGATION_STEPS["impact"])
TEMPERATURE_RULES = {"DET-003"}
HEARTBEAT_RULES = {"DET-005"}
HIGH_DEVIATION_C = 2.0  # same threshold as config/prioritization.yaml (HIGH vs LOW)
SUSTAINED_MIN = 15
SUGGESTED_STEPS = ("authorization", "impact", "escalation")


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Settings:
    context_before: timedelta
    context_after: timedelta
    history: timedelta
    critical_device_types: set[str]
    teams: dict[str, dict[str, str]]
    impact_levels: dict[str, str]
    playbooks: dict[str, dict[str, list[str]]]
    users: dict[str, dict[str, Any]]
    roles: dict[str, set[str]]
    devices: dict[str, dict[str, Any]]
    maintenance_text: str
    timezone: str = "UTC"

    @classmethod
    def from_config(cls, config_dir: Path | None = None) -> Settings:
        cfg = load_yaml("investigation.yaml", config_dir)
        users = load_yaml("users.yaml", config_dir)
        devs = load_yaml("devices.yaml", config_dir)
        mw = users["maintenance_window"]
        unknown = set(cfg["teams"]) ^ set(INVESTIGATION_STEPS["escalation"][1:])
        if unknown:
            raise ValueError(f"investigation.yaml teams do not match the workflow: {unknown}")
        return cls(
            context_before=timedelta(seconds=cfg["context_before_s"]),
            context_after=timedelta(seconds=cfg["context_after_s"]),
            history=timedelta(days=cfg["history_days"]),
            critical_device_types=set(cfg.get("critical_device_types") or []),
            teams=cfg["teams"],
            impact_levels=cfg["impact_levels"],
            playbooks=cfg["playbooks"],
            users={u["username"]: u for u in users["users"]},
            roles={k: set(v.get("permissions") or []) for k, v in users["roles"].items()},
            devices={d["device_id"]: d for d in devs["devices"]},
            maintenance_text=(
                f"{', '.join(d.capitalize() for d in mw.get('days') or [])} "
                f"{mw['start']}-{mw['end']} {devs['site']['timezone']}"
            ),
            timezone=devs["site"]["timezone"],
        )

    def registered(self, username: str) -> bool:
        u = self.users.get(username)
        return bool(u) and u.get("registered", True)


@dataclass
class Suggestion:
    decision: str
    reasons: list[str]
    teams: list[str] = field(default_factory=list)  # escalation only


@dataclass
class Case:
    investigation: dict[str, Any] | None
    alert: dict[str, Any]
    alert_history: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    device: dict[str, Any] | None
    related_events: list[dict[str, Any]]
    related_alerts: list[dict[str, Any]]
    users: list[dict[str, Any]]
    source_ips: list[dict[str, Any]]
    incident: dict[str, Any] | None
    playbook: dict[str, list[str]]
    authorization: Suggestion
    impact: Suggestion
    escalation: Suggestion
    timeline: list[dict[str, Any]]
    integrity: dict[str, Any]
    entries: list[dict[str, Any]]
    settings: Settings

    @property
    def investigation_id(self) -> str | None:
        return self.investigation["investigation_id"] if self.investigation else None

    def latest(self, step: str) -> dict[str, Any] | None:
        """The analyst's current answer for a step (latest entry), or None."""
        found = [e for e in self.entries if e["step"] == step]
        return found[-1] if found else None

    @property
    def steps_done(self) -> list[str]:
        return [s for s in INVESTIGATION_STEPS if self.latest(s)]

    @property
    def final_status(self) -> str:
        doc = self.latest("documentation")
        if doc:
            return doc["decision"]
        return "in_progress" if self.entries else "open"

    def suggestion(self, step: str) -> Suggestion | None:
        """The rule-based suggestion for a decision step (None for notes-only steps)."""
        return getattr(self, step) if step in SUGGESTED_STEPS else None

    def decision(self, step: str) -> tuple[str, bool]:
        """(decision, confirmed by the analyst) for a decision step."""
        entry = self.latest(step)
        if entry:
            return entry["decision"], True
        suggestion = self.suggestion(step)
        return (suggestion.decision if suggestion else "-"), False


# ---- gathering ----------------------------------------------------------------------------
def build_case(
    store: EventStore,
    alert_id: str,
    settings: Settings | None = None,
) -> Case:
    settings = settings or Settings.from_config()
    alert = store.alert(alert_id)
    if alert is None:
        raise KeyError(f"unknown alert {alert_id}")
    alert["attack_ids"] = json.loads(alert["attack_ids"])
    alert["implements"] = json.loads(alert["implements"])
    investigation = store.investigation_for_alert(alert_id)
    entries = (
        store.investigation_entries(investigation["investigation_id"]) if investigation else []
    )

    evidence = _evidence(store, alert_id)
    acts = [e["row"] for e in evidence if e["kind"] == "security" and e.get("row")]
    first, last = _ts(alert["first_seen"]), _ts(alert["last_seen"])
    since, until = first - settings.context_before, last + settings.context_after

    device = _device(store, settings, alert["device_id"], first, since, until)
    related = _related_events(store, alert, acts, since, until, {e["record_id"] for e in evidence})
    if not acts and alert["rule_id"] in TEMPERATURE_RULES | HEARTBEAT_RULES:
        # sensor / device alert: the user activity to judge is the configuration changes
        # made on the device before it started
        acts = [
            r for r in related if r["category"] == "configuration" and _ts(r["ts_device"]) <= last
        ]
    related_alerts = (
        [
            a
            for a in store.alerts(
                device=alert["device_id"], since=iso_utc(since), until=iso_utc(until)
            )
            if a["alert_id"] != alert_id
        ]
        if alert["device_id"]
        else []
    )
    users = [_user_profile(store, settings, u, last) for u in sorted({a["user"] for a in acts})]
    ips = [
        _ip_profile(store, settings, ip, alert["device_id"], last)
        for ip in sorted({a["source_ip"] for a in acts})
    ]
    incident = _incident(store, alert_id)
    playbook = dict(settings.playbooks.get(alert["rule_id"]) or settings.playbooks["default"])
    if incident:
        playbook = {
            "verify": [*playbook.get("verify", []), *incident["questions"]],
            "response": incident["response"] or playbook.get("response", []),
        }

    authorization = suggest_authorization(settings, alert, acts)
    impact = suggest_impact(settings, alert, acts, device, authorization)
    escalation = suggest_escalation(alert, acts, device, authorization, impact, ips)
    timeline = _timeline(alert, evidence, related, device, store.alert_history(alert_id), entries)
    return Case(
        investigation=investigation,
        alert=alert,
        alert_history=store.alert_history(alert_id),
        evidence=evidence,
        device=device,
        related_events=related,
        related_alerts=related_alerts,
        users=users,
        source_ips=ips,
        incident=incident,
        playbook=playbook,
        authorization=authorization,
        impact=impact,
        escalation=escalation,
        timeline=timeline,
        integrity=evidence_integrity(evidence),
        entries=entries,
        settings=settings,
    )


def _describe_event(e: dict[str, Any]) -> str:
    text = f"{e['event_type']} {e['user']} from {e['source_ip']}"
    if e.get("parameter"):
        text += f": {e['parameter']} {e['previous_value']} -> {e['new_value']}{e['unit'] or ''}"
    if e.get("result"):
        text += f" ({e['result']}{', ' + e['reason'] if e.get('reason') else ''})"
    return text


def evidence_integrity(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-verify each evidence record against its stored SHA-256 hash (control C-15) and
    hash the whole evidence set, so a report can later be checked against the database."""
    verified, problems, lines = 0, [], []
    for e in evidence:
        row = e.get("row")
        if not row:
            problems.append(f"{e['record_id']}: record not found")
            continue
        try:
            ok = Event(**json.loads(row["raw_json"])).compute_hash() == row["hash"]
        except (TypeError, ValueError):
            ok = False
        if ok:
            verified += 1
        else:
            problems.append(f"{e['record_id']}: hash mismatch")
        lines.append(f"{e['record_id']}:{row['hash']}")
    digest = hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()
    return {"records": len(evidence), "verified": verified, "problems": problems, "sha256": digest}


def _evidence(store: EventStore, alert_id: str) -> list[dict[str, Any]]:
    rows = store.alert_evidence(alert_id)
    sec = store.security_rows_with_status(r["record_id"] for r in rows)
    tel = store.telemetry_rows(r["record_id"] for r in rows if r["kind"] == "telemetry")
    out = []
    for r in rows:
        item = dict(r)
        if r["record_id"] in sec:
            e = sec[r["record_id"]]
            item["row"] = e
            item["detail"] = _describe_event(e)
        elif r["record_id"] in tel:
            t = tel[r["record_id"]]
            item["row"] = t
            item["detail"] = (
                f"{t['temperature_c']:.1f} °C (expected {t['expected_min_c']:.1f}.."
                f"{t['expected_max_c']:.1f}), compressor {'on' if t['compressor_on'] else 'off'}"
                f", door {'open' if t['door_open'] else 'closed'}"
            )
        else:
            item["row"] = None
            item["detail"] = r["note"]
        out.append(item)
    return out


def _device(store, settings, device_id, at, since, until) -> dict[str, Any] | None:
    if not device_id:
        return None
    cfg = settings.devices.get(device_id, {})
    readings = store.readings_between(device_id, iso_utc(since), iso_utc(until))
    runs: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for r in readings:
        dev = max(
            r["temperature_c"] - r["expected_max_c"], r["expected_min_c"] - r["temperature_c"]
        )
        if dev > 0:
            if current is None:
                current = {
                    "start": r["ts_device"],
                    "end": r["ts_device"],
                    "worst_c": r["temperature_c"],
                    "max_deviation_c": dev,
                }
                runs.append(current)
            current["end"] = r["ts_device"]
            if dev > current["max_deviation_c"]:
                current.update(worst_c=r["temperature_c"], max_deviation_c=dev)
        else:
            current = None
    for run in runs:
        run["minutes"] = round((_ts(run["end"]) - _ts(run["start"])).total_seconds() / 60) + 1
        run["max_deviation_c"] = round(run["max_deviation_c"], 2)
    temps = [r["temperature_c"] for r in readings]
    at_alert = store.reading_before(device_id, iso_utc(at))
    gap = _longest_gap(readings, at)
    return {
        "device_id": device_id,
        "name": cfg.get("name", device_id),
        "location": cfg.get("location", "-"),
        "device_type": cfg.get("device_type", "-"),
        "critical": cfg.get("device_type") in settings.critical_device_types,
        "expected_range": f"{cfg.get('safe_min_c', '?')} .. {cfg.get('safe_max_c', '?')} °C",
        "configured_setpoint_c": cfg.get("setpoint_c"),
        "allowed_ips": list(cfg.get("allowed_ips") or []),
        "window": (iso_utc(since), iso_utc(until)),
        "readings": len(readings),
        "min_c": min(temps) if temps else None,
        "max_c": max(temps) if temps else None,
        "excursions": runs,
        "minutes_out": sum(r["minutes"] for r in runs),
        "max_deviation_c": max((r["max_deviation_c"] for r in runs), default=0.0),
        "longest_gap_min": gap,
        "at_alert": at_alert,
    }


def _longest_gap(readings: list[dict[str, Any]], at: datetime) -> float:
    """Longest silence between readings, counting the silence up to the alert itself."""
    times = sorted({_ts(r["ts_device"]) for r in readings} | {at})
    gaps = [(b - a).total_seconds() / 60 for a, b in zip(times, times[1:], strict=False)]
    return round(max(gaps, default=0.0), 1)


def _related_events(store, alert, acts, since, until, evidence_ids) -> list[dict[str, Any]]:
    """Security events on the affected device (or from the same sources) around the alert."""
    q = store.conn.execute
    device = alert["device_id"]
    ips = sorted({a["source_ip"] for a in acts})
    sessions = sorted({a["session_id"] for a in acts if a["session_id"]})
    where = ["e.device_id = ?"] if device else []
    params: list[Any] = [device] if device else []
    if ips:
        where.append(f"e.source_ip IN ({', '.join('?' for _ in ips)})")
        params.extend(ips)
    if sessions:
        where.append(f"e.session_id IN ({', '.join('?' for _ in sessions)})")
        params.extend(sessions)
    if not where:
        return []
    rows = q(
        store._SEC_SELECT
        + f" WHERE ({' OR '.join(where)}) AND e.ts_device >= ? AND e.ts_device <= ?"
        " ORDER BY e.ts_device, e.id",
        [*params, iso_utc(since), iso_utc(until)],
    )
    out = []
    for r in rows:
        row = dict(r)
        row["in_evidence"] = row["event_id"] in evidence_ids
        row["detail"] = _describe_event(row)
        out.append(row)
    return out


def _user_profile(store, settings, user, until) -> dict[str, Any]:
    cfg = settings.users.get(user, {})
    role = cfg.get("role")
    since = until - settings.history
    rows = store.conn.execute(
        """SELECT event_type, category, device_id, source_ip, within_maintenance_window, ts_device
           FROM security_events WHERE user = ? AND ts_device >= ? AND ts_device <= ?""",
        (user, iso_utc(since), iso_utc(until)),
    ).fetchall()
    logins = [r for r in rows if r["event_type"] == "LOGIN_SUCCESS"]
    return {
        "user": user,
        "registered": settings.registered(user),
        "full_name": cfg.get("full_name", "not in the user directory"),
        "role": role or "none",
        "permissions": sorted(settings.roles.get(role, set())),
        "known_ips": list(cfg.get("known_ips") or []) if settings.registered(user) else [],
        "logins": len(logins),
        "failed_logins": sum(r["event_type"] == "LOGIN_FAILURE" for r in rows),
        "changes": sum(r["category"] == "configuration" for r in rows),
        "logins_outside_window": sum(r["within_maintenance_window"] == 0 for r in logins),
        "devices": sorted({r["device_id"] for r in rows}),
        "source_ips": sorted({r["source_ip"] for r in rows}),
        "history_days": settings.history.days,
    }


def _ip_profile(store, settings, ip, device_id, until) -> dict[str, Any]:
    since = until - settings.history
    rows = store.conn.execute(
        """SELECT event_type, user, device_id, ts_device FROM security_events
           WHERE source_ip = ? AND ts_device >= ? AND ts_device <= ? ORDER BY ts_device""",
        (ip, iso_utc(since), iso_utc(until)),
    ).fetchall()
    allowed = set(settings.devices.get(device_id, {}).get("allowed_ips") or [])
    owners = sorted(
        u
        for u, c in settings.users.items()
        if settings.registered(u) and ip in (c.get("known_ips") or [])
    )
    return {
        "source_ip": ip,
        "on_allow_list": ip in allowed,
        "known_for": owners,
        "failed_logins": sum(r["event_type"] == "LOGIN_FAILURE" for r in rows),
        "logins": sum(r["event_type"] == "LOGIN_SUCCESS" for r in rows),
        "usernames": sorted({r["user"] for r in rows}),
        "devices": sorted({r["device_id"] for r in rows}),
        "first_seen": rows[0]["ts_device"] if rows else None,
        "last_seen": rows[-1]["ts_device"] if rows else None,
    }


def _incident(store, alert_id) -> dict[str, Any] | None:
    row = store.conn.execute(
        """SELECT i.incident_id FROM incident_members m JOIN incidents i ON i.id = m.incident_ref
           WHERE m.record_id = ? AND i.merged_into IS NULL ORDER BY i.id DESC LIMIT 1""",
        (alert_id,),
    ).fetchone()
    if row is None:
        return None
    inc = store.incident(row[0])
    for key in ("questions", "response", "attack_ids"):
        inc[key] = json.loads(inc[key])
    return inc


# ---- suggestions ----------------------------------------------------------------------------
def _grouped(findings: dict[str, list[str]]) -> list[str]:
    """One line per finding, with the events it applies to."""
    return [f"{text} ({', '.join(dict.fromkeys(ids))})" for text, ids in findings.items()]


def suggest_authorization(settings: Settings, alert, acts) -> Suggestion:
    if alert["rule_id"] == "DET-007":
        return Suggestion(
            "authorized", ["Planned maintenance activity inside the maintenance window."]
        )
    if not acts:
        return Suggestion(
            "not_applicable",
            [
                "No user activity behind the alert and no configuration change before it: "
                "a device or sensor condition, not an access question."
            ],
        )
    hard: dict[str, list[str]] = {}
    soft: dict[str, list[str]] = {}
    allowed = set(settings.devices.get(alert["device_id"], {}).get("allowed_ips") or [])
    for a in acts:
        eid = a["event_id"]
        if not settings.registered(a["user"]):
            hard.setdefault(f"'{a['user']}' is not a registered account", []).append(eid)
        if a["event_type"] == "LOGIN_FAILURE":
            why = a["reason"] or "bad credentials"
            hard.setdefault(f"failed login as {a['user']} ({why})", []).append(eid)
        if a["result"] in ("denied", "rejected") or a["authorized"] == 0:
            text = f"change refused: role '{a['role']}' lacks the permission"
            hard.setdefault(text, []).append(eid)
        if allowed and a["source_ip"] not in allowed:
            text = f"source IP {a['source_ip']} is not on the device allow-list"
            hard.setdefault(text, []).append(eid)
        known = settings.users.get(a["user"], {}).get("known_ips") or []
        if settings.registered(a["user"]) and a["source_ip"] not in known:
            text = f"{a['source_ip']} is not a usual address of {a['user']}"
            soft.setdefault(text, []).append(eid)
        if a["role"] in ("technician", "admin") and a["within_maintenance_window"] == 0:
            text = (
                f"privileged activity by {a['user']} outside the maintenance window "
                f"({settings.maintenance_text})"
            )
            soft.setdefault(text, []).append(eid)
        if a["parameter"] and a["result"] == "applied":
            perm = PARAMETER_PERMISSIONS.get(a["parameter"])
            if perm and perm not in settings.roles.get(a["role"] or "", set()):
                hard.setdefault(f"role '{a['role']}' has no '{perm}' permission", []).append(eid)
    if hard:
        return Suggestion("unauthorized", _grouped(hard) + _grouped(soft))
    if soft:
        return Suggestion(
            "unknown",
            [*_grouped(soft), "Confirm with the account owner (directly, not via the account)."],
        )
    return Suggestion(
        "authorized",
        ["Registered user, role holds the permission, usual source IP, inside the window."],
    )


def _applied(acts) -> list[dict[str, Any]]:
    return [a for a in acts if a["category"] == "configuration" and a["result"] == "applied"]


def _access_gained(acts) -> bool:
    """Did the activity get anywhere: a successful login or an applied change?"""
    return bool(_applied(acts)) or any(a["event_type"] == "LOGIN_SUCCESS" for a in acts)


def relevant_excursions(alert, acts, device) -> list[dict[str, Any]]:
    """Excursions the alert can explain: all of them for a temperature alert, otherwise
    only those that start after a configuration change was applied."""
    if not device:
        return []
    if alert["rule_id"] in TEMPERATURE_RULES:
        return device["excursions"]
    applied = _applied(acts)
    if not applied:
        return []
    first = min(_ts(a["ts_device"]) for a in applied)
    return [r for r in device["excursions"] if _ts(r["start"]) >= first]


def suggest_impact(settings, alert, acts, device, authorization) -> Suggestion:
    level = 0
    reasons: list[str] = []

    def at_least(name: str, why: str) -> None:
        nonlocal level
        level = max(level, IMPACT_ORDER.index(name))
        reasons.append(f"{name}: {why}")

    if alert["rule_id"] == "DET-007":
        return Suggestion("none", ["Planned maintenance; nothing to restore."])
    applied = _applied(acts)
    attempts = [a for a in acts if a not in applied]
    if attempts and not _access_gained(acts):
        at_least("low", f"{len(attempts)} attempt(s) without effect (failed or refused).")
    for a in applied:
        at_least("medium", f"{a['parameter']} changed {a['previous_value']} -> {a['new_value']}.")
    unauthorized = authorization.decision == "unauthorized"
    if unauthorized and any(a["event_type"] == "LOGIN_SUCCESS" for a in acts):
        at_least("high", "an unauthorized party logged in (possibly stolen credentials).")
    runs = relevant_excursions(alert, acts, device)
    if runs:
        dev = max(r["max_deviation_c"] for r in runs)
        minutes = sum(r["minutes"] for r in runs)
        text = f"temperature {dev:.1f} °C beyond the range for {minutes} min."
        if dev >= HIGH_DEVIATION_C or minutes >= SUSTAINED_MIN:
            at_least("high", text + " Stock may be unsafe.")
        else:
            at_least("medium", text)
        if device["critical"]:
            at_least("critical", f"{device['name']} holds safety-critical stock.")
        if applied and unauthorized:
            at_least("critical", "an unauthorized change was followed by an excursion.")
    elif device and device["excursions"]:
        reasons.append(
            "context: an excursion in the window is not explained by this alert "
            "(no change applied before it); it has its own DET-003 alert."
        )
    if device and alert["rule_id"] in HEARTBEAT_RULES:
        at_least(
            "medium",
            f"no telemetry for up to {device['longest_gap_min']} min; stock state unknown.",
        )
    if alert["severity"] == "CRITICAL":
        at_least("high", "the alert is CRITICAL.")
    if level == 0:
        reasons.append("none: no change applied and no temperature effect found.")
    return Suggestion(IMPACT_ORDER[level], reasons)


def suggest_escalation(alert, acts, device, authorization, impact, ips) -> Suggestion:
    teams: list[tuple[str, str]] = []
    rank = IMPACT_ORDER.index(impact.decision)
    tampering = authorization.decision == "unauthorized" and _access_gained(acts)
    pending: list[str] = []
    if tampering:
        teams.append(("l2_soc", "unauthorized access got in (login or applied change)"))
    elif alert["severity"] == "CRITICAL":
        teams.append(("l2_soc", "CRITICAL alert"))
    elif authorization.decision == "unknown":
        if rank >= IMPACT_ORDER.index("high"):
            teams.append(("l2_soc", "possible misuse of a valid account with a high impact"))
        else:
            pending.append(
                "Pending owner confirmation: if the account owner does not confirm the "
                "activity, escalate to l2_soc."
            )
    if alert["rule_id"] in TEMPERATURE_RULES | HEARTBEAT_RULES and not tampering:
        teams.append(("maintenance_engineering", "equipment or connectivity problem to inspect"))
    if relevant_excursions(alert, acts, device) and rank >= IMPACT_ORDER.index("high"):
        teams.append(("store_management", "stock was out of range: quarantine / disposal decision"))
    external = [ip["source_ip"] for ip in ips if not ip["on_allow_list"]]
    if external:
        teams.append(("it_network", f"block / review external source IP(s) {', '.join(external)}"))
    if not teams:
        return Suggestion(
            "not_required", pending or ["L1 can close it: no effect and no unauthorized access."]
        )
    return Suggestion(
        teams[0][0], [f"{t}: {why}" for t, why in teams] + pending, [t for t, _ in teams]
    )


# ---- timeline -----------------------------------------------------------------------------
def _timeline(alert, evidence, related, device, history, entries) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen = set()
    for r in related:
        mark = " [evidence]" if r["in_evidence"] else ""
        items.append(
            {
                "ts": r["ts_device"],
                "source": "security event",
                "record": r["event_id"],
                "detail": r["detail"] + mark,
                "status": r["status"],
            }
        )
        seen.add(r["event_id"])
    for e in evidence:
        if e["kind"] == "security" and e["record_id"] not in seen:
            items.append(
                {
                    "ts": e["ts"],
                    "source": "security event",
                    "record": e["record_id"],
                    "detail": e["detail"] + " [evidence]",
                    "status": (e.get("row") or {}).get("status", ""),
                }
            )
    if device:
        for run in device["excursions"]:
            items.append(
                {
                    "ts": run["start"],
                    "source": "telemetry",
                    "record": device["device_id"],
                    "detail": f"temperature leaves the expected range ({device['expected_range']})",
                    "status": "abnormal",
                }
            )
            items.append(
                {
                    "ts": run["end"],
                    "source": "telemetry",
                    "record": device["device_id"],
                    "detail": (
                        f"last abnormal reading; worst {run['worst_c']:.1f} °C, "
                        f"{run['minutes']} min out"
                    ),
                    "status": "abnormal",
                }
            )
    items.append(
        {
            "ts": alert["first_seen"],
            "source": "alert",
            "record": alert["alert_id"],
            "detail": f"{alert['rule_id']} {alert['base_severity']} raised: {alert['title']}",
            "status": alert["severity"],
        }
    )
    for h in history:
        items.append(
            {
                "ts": h["ts"],
                "source": "triage",
                "record": alert["alert_id"],
                "detail": f"{h['actor']}: {h['field']} {h['old_value'] or '-'} -> {h['new_value']}"
                + (f" ({h['note']})" if h["note"] else ""),
                "status": "",
            }
        )
    for e in entries:
        items.append(
            {
                "ts": e["ts"],
                "source": "analyst",
                "record": e["step"],
                "detail": f"{e['analyst']}: {STEP_LABELS[e['step']]}"
                + (f" -> {e['decision']}" if e["decision"] else ""),
                "status": "",
            }
        )
    items.sort(key=lambda i: (_ts(i["ts"]), i["source"] != "security event"))
    return items
