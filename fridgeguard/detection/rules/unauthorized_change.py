"""Rule type ``unauthorized_change`` (DET-001, DET-006).

Fires when a configuration change is attempted by a role that lacks the required
permission, or when the authorization information is missing or invalid (agreed DR-4
logic: never assume a change was authorised).

* ``authorized = true``  -> no alert (the change stays in the audit log)
* ``authorized = false`` -> alert
* missing / invalid      -> alert, flagged for investigation

The same rule type runs twice in the default configuration: DET-001 watches setpoint
changes, DET-006 every other configuration parameter. Applied changes mark the event
``malicious``; changes the device denied mark it ``suspicious``.
"""

from __future__ import annotations

from fridgeguard.detection.rules.base import Record, Rule, RuleHit, register


@register
class UnauthorizedChangeRule(Rule):
    type_name = "unauthorized_change"
    required = ("parameters",)

    def setup(self) -> None:
        params = self.params["parameters"]
        if not isinstance(params, list) or not params:
            raise ValueError(f"{self.rule_id}: 'parameters' must be a non-empty list")
        self.parameters = set(params)

    def evaluate(self, record: Record) -> list[RuleHit]:
        if not record.is_security or record["category"] != "configuration":
            return []
        if record["parameter"] not in self.parameters:
            return []
        authorized = record["authorized"]
        if authorized == 1:
            return []

        if authorized == 0:
            permission = record.payload.get("permission", "?")
            why = f"role '{record['role']}' lacks permission '{permission}'"
        else:
            why = "authorization information missing or invalid"
        applied = record["result"] == "applied"
        verb = "changed" if applied else f"tried to change ({record['result']})"
        change = record.change_text()
        return [
            RuleHit(
                subject=record.device_id,
                device_id=record.device_id,
                title=f"{record['user']} {verb} {change} on {record.device_id}",
                description=(
                    f"{record['user']} ({record['role']}) from {record['source_ip']} "
                    f"{verb} {change} on {record.device_id}: {why}."
                ),
                evidence=[(record, f"{record['event_type']} {record['result']}: {why}")],
                event_status="malicious" if applied else "suspicious",
            )
        ]
