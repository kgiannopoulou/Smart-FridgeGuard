"""Rule type ``temperature_limits`` (DET-003).

Fires when a fridge's readings stay outside its configured operating range (the
``expected_min_c`` .. ``expected_max_c`` reported with every reading, widened by an
optional margin) for at least ``min_duration_s``. The duration requirement keeps short
door openings and sensor noise from raising alerts. The rule resets once the
temperature is back in range.
"""

from __future__ import annotations

from datetime import timedelta

from fridgeguard.detection.rules.base import (
    TELEMETRY,
    Record,
    Rule,
    RuleHit,
    minutes,
    register,
    short_time,
)


@register
class TemperatureLimitsRule(Rule):
    type_name = "temperature_limits"
    defaults = {"min_duration_s": 900, "margin_c": 0.0}

    def setup(self) -> None:
        if float(self.params["min_duration_s"]) < 0 or float(self.params["margin_c"]) < 0:
            raise ValueError(f"{self.rule_id}: min_duration_s and margin_c must be >= 0")
        self.min_duration = timedelta(seconds=float(self.params["min_duration_s"]))
        self.margin = float(self.params["margin_c"])
        self.out_since: dict[str, Record] = {}
        self.alerted: set[str] = set()

    def evaluate(self, record: Record) -> list[RuleHit]:
        if record.kind != TELEMETRY:
            return []
        device = record.device_id
        temp = record["temperature_c"]
        low = record["expected_min_c"] - self.margin
        high = record["expected_max_c"] + self.margin
        if low <= temp <= high:
            self.out_since.pop(device, None)
            self.alerted.discard(device)
            return []

        first = self.out_since.setdefault(device, record)
        duration = record.ts - first.ts
        if device in self.alerted or duration < self.min_duration:
            return []
        self.alerted.add(device)
        side = "above" if temp > high else "below"
        limits = f"{record['expected_min_c']:.1f}..{record['expected_max_c']:.1f} °C"
        lasted = minutes(duration.total_seconds())
        return [
            RuleHit(
                subject=device,
                device_id=device,
                title=f"{device} at {temp:.1f} °C, {side} its {limits} range for {lasted}",
                description=(
                    f"{device} has been {side} its configured range ({limits}) since "
                    f"{short_time(first.ts)}: {first['temperature_c']:.1f} °C then, "
                    f"{temp:.1f} °C now (setpoint {record['setpoint_c']:.1f} °C, "
                    f"device status '{record['device_status']}')."
                ),
                evidence=[
                    (first, f"first reading outside the range: {first['temperature_c']:.1f} °C"),
                    (record, f"still outside after {lasted}: {temp:.1f} °C"),
                ],
                event_status=None,
            )
        ]
