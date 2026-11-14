"""Validation and normalisation of simulator events into database rows (Step 7).

Each incoming :class:`~fridgeguard.models.Event` is either

* a **telemetry** row (temperature reading; no user, no source IP), or
* a **security event** row (who did what, from where, previous/new value), or
* **rejected** with a reason (unknown device, bad schema, hash mismatch, ...).

Security events also get an *initial status* from simple, explainable checks on facts the
device itself reported. The detection engine (Step 8 onwards) can later raise the status
(for example to ``malicious``) by appending to ``event_status_history``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    CONFIG_CHANGE,
    TELEMETRY_TEMPERATURE,
    Event,
)
from fridgeguard.timeutil import parse_utc

STATUS_NORMAL = "normal"
STATUS_SUSPICIOUS = "suspicious"
STATUS_MALICIOUS = "malicious"
STATUSES = (STATUS_NORMAL, STATUS_SUSPICIOUS, STATUS_MALICIOUS)

# Roles allowed to change device settings: for them, activity outside the maintenance
# window is worth a closer look.
PRIVILEGED_ROLES = {"technician", "admin"}

# config.change parameter -> (security event type, unit shown after values)
PARAMETER_TYPES = {
    "setpoint_c": ("SETPOINT_CHANGE", " °C"),
    "alarm_low_c": ("ALARM_THRESHOLD_CHANGE", " °C"),
    "alarm_high_c": ("ALARM_THRESHOLD_CHANGE", " °C"),
    "defrost_interval_h": ("CONFIG_CHANGE", " h"),
    "firmware_version": ("FIRMWARE_UPDATE", ""),
}

AUTH_TYPES = {
    AUTH_LOGIN_SUCCESS: "LOGIN_SUCCESS",
    AUTH_LOGIN_FAILURE: "LOGIN_FAILURE",
    AUTH_LOGOUT: "LOGOUT",
}


class ValidationError(ValueError):
    pass


@dataclass
class Normalized:
    table: str  # "telemetry" or "security_events"
    row: dict[str, Any]
    status: str | None = None
    status_reasons: list[str] = field(default_factory=list)


def _require(payload: dict, *keys: str) -> None:
    missing = [k for k in keys if k not in payload]
    if missing:
        raise ValidationError(f"payload missing {', '.join(missing)}")


def _bool_or_none(value: Any) -> int | None:
    return int(value) if isinstance(value, bool) else None


def _value_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, float):
        return f"{value:g}" if value != int(value) else f"{value:.1f}"
    return str(value)


def normalize(event: Event, known_devices: set[str], ts_ingest: str) -> Normalized:
    """Validate ``event`` and turn it into a row for its table."""
    if event.hash != event.compute_hash():
        raise ValidationError("hash does not match event content (modified in transit?)")
    if event.device_id not in known_devices:
        raise ValidationError(f"unknown device {event.device_id!r}")
    try:
        parse_utc(event.ts_device)
    except ValueError as exc:
        raise ValidationError(f"invalid timestamp {event.ts_device!r}") from exc

    common = {
        "source_event_id": event.event_id,
        "ts_device": event.ts_device,
        "ts_ingest": ts_ingest,
        "device_id": event.device_id,
        "scenario": event.scenario,
        "hash": event.hash,
        "raw_json": event.to_json(),
    }
    p = event.payload

    if event.event_type == TELEMETRY_TEMPERATURE:
        _require(p, "temperature_c", "setpoint_c", "expected_min_c", "expected_max_c", "status")
        if event.actor is not None or event.source_ip is not None:
            raise ValidationError("telemetry must not carry a user or source IP")
        return Normalized(
            "telemetry",
            {
                **common,
                "temperature_c": float(p["temperature_c"]),
                "setpoint_c": float(p["setpoint_c"]),
                "expected_min_c": float(p["expected_min_c"]),
                "expected_max_c": float(p["expected_max_c"]),
                "device_status": str(p["status"]),
                "door_open": int(bool(p.get("door_open", False))),
                "compressor_on": int(bool(p.get("compressor_on", False))),
            },
        )

    if not event.actor or not event.source_ip:
        raise ValidationError("security events need a user and a source IP")

    row = {
        **common,
        "user": event.actor,
        "role": p.get("role"),
        "source_ip": event.source_ip,
        "parameter": None,
        "previous_value": None,
        "new_value": None,
        "unit": None,
        "result": None,
        "reason": p.get("reason"),
        "authorized": None,
        "within_maintenance_window": _bool_or_none(p.get("within_maintenance_window")),
        "session_id": p.get("session_id"),
    }

    if event.event_type in AUTH_TYPES:
        row["event_type"] = AUTH_TYPES[event.event_type]
        row["category"] = "authentication"
        row["result"] = {
            AUTH_LOGIN_SUCCESS: "success",
            AUTH_LOGIN_FAILURE: "failure",
            AUTH_LOGOUT: "logout",
        }[event.event_type]
        if event.event_type == AUTH_LOGIN_FAILURE:
            _require(p, "reason")
    elif event.event_type == CONFIG_CHANGE:
        _require(p, "parameter", "old_value", "new_value", "result")
        if p["parameter"] not in PARAMETER_TYPES:
            raise ValidationError(f"unknown configuration parameter {p['parameter']!r}")
        event_type, unit = PARAMETER_TYPES[p["parameter"]]
        row.update(
            event_type=event_type,
            category="configuration",
            parameter=p["parameter"],
            previous_value=_value_text(p["old_value"]),
            new_value=_value_text(p["new_value"]),
            unit=unit,
            result=p["result"],
            authorized=_bool_or_none(p.get("authorized")),
        )
    else:
        raise ValidationError(f"unsupported event type {event.event_type!r}")

    status, reasons = initial_status(row, p)
    return Normalized("security_events", row, status, reasons)


def initial_status(row: dict[str, Any], payload: dict[str, Any]) -> tuple[str, list[str]]:
    """First-pass status from facts the device reported (not a detection rule).

    * configuration change whose ``authorized`` flag is false        -> suspicious
    * configuration change with a missing/invalid ``authorized`` flag -> suspicious
      (never assume a change was authorised; agreed DR-4 logic)
    * privileged account logged in or changed a setting outside the
      maintenance window                                              -> suspicious
    * login attempt for an account that does not exist               -> suspicious
    * anything else                                                  -> normal
    """
    reasons = []
    if row["category"] == "configuration":
        if "authorized" not in payload or not isinstance(payload["authorized"], bool):
            reasons.append("authorization information missing or invalid")
        elif payload["authorized"] is False:
            reasons.append(f"role '{row['role']}' lacks permission '{payload.get('permission')}'")
    acted = row["event_type"] == "LOGIN_SUCCESS" or row["category"] == "configuration"
    if acted and row["role"] in PRIVILEGED_ROLES and row["within_maintenance_window"] == 0:
        reasons.append("privileged account active outside the maintenance window")
    if row["event_type"] == "LOGIN_FAILURE" and row["reason"] == "unknown_user":
        reasons.append("login attempt for a non-existent account")
    return (STATUS_SUSPICIOUS if reasons else STATUS_NORMAL), reasons


def event_from_json(line: str) -> Event:
    """Rebuild an Event from one JSON Lines record (hash is kept, then verified)."""
    data = json.loads(line)
    if not isinstance(data, dict):
        raise ValidationError("record is not a JSON object")
    try:
        return Event(**data)
    except TypeError as exc:
        raise ValidationError(f"record does not match the event schema: {exc}") from exc
