"""Rule type ``failed_logins`` (DET-002, brute force).

Counts ``LOGIN_FAILURE`` events per group (default: source IP) in a sliding time window.
When the count reaches ``threshold`` the rule fires with every failure in the window as
evidence; further failures in the same burst are added to the same alert.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta

from fridgeguard.detection.rules.base import Record, Rule, RuleHit, minutes, register

GROUP_COLUMNS = {"source_ip": "source_ip", "user": "user", "device_id": "device_id"}
GROUP_LABELS = {"source_ip": "source IP", "user": "user", "device_id": "device"}


@register
class FailedLoginsRule(Rule):
    type_name = "failed_logins"
    defaults = {"threshold": 5, "window_s": 300, "group_by": "source_ip"}

    def setup(self) -> None:
        if self.params["group_by"] not in GROUP_COLUMNS:
            raise ValueError(f"{self.rule_id}: group_by must be one of {list(GROUP_COLUMNS)}")
        if int(self.params["threshold"]) < 2 or float(self.params["window_s"]) <= 0:
            raise ValueError(f"{self.rule_id}: threshold must be >= 2 and window_s > 0")
        self.threshold = int(self.params["threshold"])
        self.window = timedelta(seconds=float(self.params["window_s"]))
        self.column = GROUP_COLUMNS[self.params["group_by"]]
        self.recent: dict[str, deque[Record]] = {}
        self.triggered: set[str] = set()

    def evaluate(self, record: Record) -> list[RuleHit]:
        if not record.is_security or record["event_type"] != "LOGIN_FAILURE":
            return []
        group = str(record[self.column])
        q = self.recent.setdefault(group, deque())
        while q and record.ts - q[0].ts > self.window:
            q.popleft()
        if not q:
            self.triggered.discard(group)  # a new burst starts
        q.append(record)
        if len(q) < self.threshold:
            return []

        if group in self.triggered:
            evidence = [(record, f"failed login #{len(q)} in the window")]
        else:
            self.triggered.add(group)
            evidence = [
                (r, f"failed login #{i} ({r['user']}, {r['reason']})") for i, r in enumerate(q, 1)
            ]
        users = sorted({r["user"] for r in q})
        span = (q[-1].ts - q[0].ts).total_seconds()
        label = GROUP_LABELS[self.params["group_by"]]
        return [
            RuleHit(
                subject=group,
                device_id=record.device_id,
                title=f"{len(q)} failed logins from {label} {group} within {minutes(span)}",
                description=(
                    f"{len(q)} failed login attempts from {label} {group} in {minutes(span)} "
                    f"(threshold {self.threshold} in {minutes(self.window.total_seconds())}). "
                    f"Usernames tried: {', '.join(users)}. Latest target: {record.device_id}."
                ),
                evidence=evidence,
            )
        ]
