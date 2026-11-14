"""Rule type ``missing_heartbeat`` (DET-005).

Every temperature reading counts as a heartbeat. When a device that has reported before
sends nothing for ``missed_intervals x expected_interval_s``, the rule fires once; it
resets when readings resume. Detection time comes from the event stream (the newest
record seen), so the rule works the same live and when re-running over stored data.
"""

from __future__ import annotations

from datetime import datetime, timedelta

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
class MissingHeartbeatRule(Rule):
    type_name = "missing_heartbeat"
    defaults = {"expected_interval_s": 60, "missed_intervals": 3}

    def setup(self) -> None:
        interval = float(self.params["expected_interval_s"])
        missed = int(self.params["missed_intervals"])
        if interval <= 0 or missed < 1:
            raise ValueError(f"{self.rule_id}: expected_interval_s > 0, missed_intervals >= 1")
        self.timeout = timedelta(seconds=interval * missed)
        self.last: dict[str, Record] = {}
        self.alerted: set[str] = set()

    def evaluate(self, record: Record) -> list[RuleHit]:
        if record.kind == TELEMETRY:
            self.last[record.device_id] = record
            self.alerted.discard(record.device_id)
        return []

    def advance(self, now: datetime) -> list[RuleHit]:
        hits = []
        for device, last in self.last.items():
            silent = now - last.ts
            if device in self.alerted or silent <= self.timeout:
                continue
            self.alerted.add(device)
            overdue_at = last.ts + self.timeout
            limit = minutes(self.timeout.total_seconds())
            hits.append(
                RuleHit(
                    subject=device,
                    device_id=device,
                    title=f"No readings from {device} for more than {limit}",
                    description=(
                        f"{device} last reported at {short_time(last.ts)} "
                        f"({last['temperature_c']:.1f} °C, status '{last['device_status']}') and "
                        f"has been silent for over {limit}. "
                        f"Possible network interruption, power loss or blocked telemetry."
                    ),
                    evidence=[(last, "last reading before the silence")],
                    event_status=None,
                    ts=overdue_at,
                )
            )
        return hits
