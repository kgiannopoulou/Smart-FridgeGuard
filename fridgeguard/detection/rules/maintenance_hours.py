"""Rule type ``maintenance_hours`` (DET-004).

Fires when an account whose role may only work inside the maintenance window (by
default technicians and admins) logs in or changes a setting outside it. The window is
defined in the detection config, independently of the flag the device reports, so a
device with a wrong clock or a tampered flag cannot hide off-hours access.

Hits for the same user are grouped, so one off-hours session (login + changes) becomes
one alert.
"""

from __future__ import annotations

from fridgeguard.detection.rules.base import Record, Rule, RuleHit, register
from fridgeguard.timeutil import TimeWindow


@register
class MaintenanceHoursRule(Rule):
    type_name = "maintenance_hours"
    defaults = {
        "roles": ["technician", "admin"],
        "event_types": [
            "LOGIN_SUCCESS",
            "SETPOINT_CHANGE",
            "ALARM_THRESHOLD_CHANGE",
            "CONFIG_CHANGE",
            "FIRMWARE_UPDATE",
        ],
    }
    required = ("maintenance_window",)

    def setup(self) -> None:
        mw = self.params["maintenance_window"]
        try:
            self.window = TimeWindow(mw["start"], mw["end"], self.context.tz, mw.get("days"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{self.rule_id}: invalid maintenance_window: {exc}") from exc
        self.roles = set(self.params["roles"])
        self.event_types = set(self.params["event_types"])
        self.description_window = (
            f"{', '.join(d.capitalize() for d in mw.get('days', ['every day']))} "
            f"{mw['start']}-{mw['end']} ({self.context.tz.key})"
        )

    def evaluate(self, record: Record) -> list[RuleHit]:
        if not record.is_security or record["event_type"] not in self.event_types:
            return []
        if record["role"] not in self.roles or self.window.contains(record.ts):
            return []
        local = record.ts.astimezone(self.context.tz)
        if record["event_type"] == "LOGIN_SUCCESS":
            what = "logged in"
        else:
            verb = (
                "changed"
                if record["result"] == "applied"
                else f"tried ({record['result']}) to change"
            )
            what = f"{verb} {record.change_text()}"
        return [
            RuleHit(
                subject=record["user"],
                device_id=record.device_id,
                title=f"{record['user']} {what} on {record.device_id} at "
                f"{local:%a %H:%M} local time, outside maintenance hours",
                description=(
                    f"{record['user']} ({record['role']}) from {record['source_ip']}: {what} "
                    f"on {record.device_id} at {local:%Y-%m-%d %H:%M} local time. "
                    f"Maintenance window: {self.description_window}."
                ),
                evidence=[(record, f"{record['event_type']} at {local:%a %H:%M} local time")],
            )
        ]
