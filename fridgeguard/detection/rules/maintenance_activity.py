"""Rule type ``maintenance_activity`` (DET-007, informational).

Records normal, planned maintenance as an INFO alert: a configuration change that the
role was allowed to make, applied inside the maintenance window. It is not a detection
of anything wrong; it gives the analyst an audit trail of who changed what, so that later
alerts on the same device can be read in context ("the setpoint was changed this morning
during maintenance").

Changes from the same user are grouped, so one maintenance session becomes one alert.
Evidence events keep their status (``event_status=None``): normal work stays normal.
"""

from __future__ import annotations

from fridgeguard.detection.rules.base import Record, Rule, RuleHit, register
from fridgeguard.timeutil import TimeWindow


@register
class MaintenanceActivityRule(Rule):
    type_name = "maintenance_activity"
    defaults = {"roles": ["technician", "admin"]}
    required = ("maintenance_window",)

    def setup(self) -> None:
        mw = self.params["maintenance_window"]
        try:
            self.window = TimeWindow(mw["start"], mw["end"], self.context.tz, mw.get("days"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{self.rule_id}: invalid maintenance_window: {exc}") from exc
        self.roles = set(self.params["roles"])

    def evaluate(self, record: Record) -> list[RuleHit]:
        if not record.is_security or record["category"] != "configuration":
            return []
        if record["result"] != "applied" or record["authorized"] != 1:
            return []
        if record["role"] not in self.roles or not self.window.contains(record.ts):
            return []
        local = record.ts.astimezone(self.context.tz)
        change = record.change_text()
        return [
            RuleHit(
                subject=record["user"],
                device_id=record.device_id,
                title=f"Maintenance: {record['user']} changed {change} on {record.device_id}",
                description=(
                    f"{record['user']} ({record['role']}) from {record['source_ip']} changed "
                    f"{change} on {record.device_id} at {local:%a %H:%M} local time, inside the "
                    "maintenance window and with the required permission. Recorded for the "
                    "audit trail; no action needed."
                ),
                evidence=[(record, f"{record['event_type']} applied during maintenance")],
                event_status=None,
            )
        ]
