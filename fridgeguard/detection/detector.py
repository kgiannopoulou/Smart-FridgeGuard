"""Detection engine (Phase 2, Step 8).

The detector reads stored events in time order, passes each one to every enabled rule,
and turns rule hits into security alerts in the event database.

* **Configurable:** rules, thresholds, windows and severities come from
  ``config/detection.yaml``. Each entry names a rule *type* (a class in
  ``fridgeguard/detection/rules/``), so a new rule of an existing type needs no code.
* **Grouping:** hits of the same rule for the same subject (device, source IP, user)
  within ``dedup_window_s`` of each other become one alert with growing evidence.
* **Evidence:** every alert links to the exact readings and security events behind it.
* **Verdicts:** security events used as evidence get the rule's status
  (``suspicious`` or ``malicious``) appended to their status history.
* **Idempotent:** alert keys are deterministic, so running detection again over the same
  data finds the existing alerts instead of creating duplicates.
* **Prioritized:** with a :class:`~fridgeguard.detection.prioritizer.Prioritizer`
  attached (the default from config), alerts are classified INFO..CRITICAL as they are
  raised and again when detection finishes (Step 10).
* **Live or batch:** :meth:`Detector.process` handles one record at a time (live
  simulation); :meth:`Detector.run` scans everything already stored.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fridgeguard.config import load_yaml
from fridgeguard.detection.prioritizer import Prioritizer
from fridgeguard.detection.rules import RULE_TYPES, Record, Rule, RuleHit
from fridgeguard.detection.rules.base import DetectionContext
from fridgeguard.models import iso_utc
from fridgeguard.storage import EventStore


@dataclass
class Alert:
    """An alert raised or extended by one rule hit."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    device_id: str | None
    subject: str
    title: str
    ts: datetime
    new: bool  # False when the hit was grouped into an existing alert


@dataclass
class DetectionSummary:
    records: int = 0
    hits: int = 0
    new_alerts: list[Alert] = field(default_factory=list)
    by_rule: dict[str, int] = field(default_factory=dict)


def load_rules(config_dir: Path | None = None) -> tuple[list[Rule], float]:
    """Build the enabled rules from ``detection.yaml``. Returns (rules, dedup window)."""
    cfg = load_yaml("detection.yaml", config_dir)
    site = load_yaml("devices.yaml", config_dir)["site"]
    context = DetectionContext(tz=ZoneInfo(site["timezone"]))
    rules = []
    for rule_id, spec in (cfg.get("rules") or {}).items():
        if not isinstance(spec, dict):
            raise ValueError(f"{rule_id}: rule definition must be a mapping")
        if not spec.get("enabled", True):
            continue
        type_name = spec.get("type")
        if type_name not in RULE_TYPES:
            raise ValueError(
                f"{rule_id}: unknown rule type {type_name!r}; known: {sorted(RULE_TYPES)}"
            )
        for key in ("name", "severity"):
            if key not in spec:
                raise ValueError(f"{rule_id}: missing '{key}'")
        rules.append(
            RULE_TYPES[type_name](
                rule_id,
                spec["name"],
                str(spec["severity"]).upper(),
                spec.get("params"),
                context,
                implements=spec.get("implements"),
                attack=spec.get("attack"),
            )
        )
    dedup = float(cfg.get("dedup_window_s", 900))
    if dedup < 0:
        raise ValueError("dedup_window_s must be >= 0")
    return rules, dedup


class Detector:
    def __init__(
        self,
        store: EventStore,
        rules: list[Rule],
        dedup_window_s: float = 900,
        on_alert: Callable[[Alert], None] | None = None,
        prioritizer: Prioritizer | None = None,
        reprioritize_every_s: float = 300,
    ):
        if len({r.rule_id for r in rules}) != len(rules):
            raise ValueError("rule IDs must be unique")
        self.store = store
        self.rules = rules
        self.dedup_window = timedelta(seconds=dedup_window_s)
        self.on_alert = on_alert
        self.prioritizer = prioritizer
        self.reprioritize_every = timedelta(seconds=reprioritize_every_s)
        self._last_regrade: datetime | None = None
        self.now: datetime | None = None
        self.summary = DetectionSummary()
        # (rule_id, subject) -> (alert_id, time of the latest hit)
        self._groups: dict[tuple[str, str], tuple[str, datetime]] = {}

    @classmethod
    def from_config(
        cls,
        store: EventStore,
        config_dir: Path | None = None,
        on_alert: Callable[[Alert], None] | None = None,
        prioritize: bool = True,
    ) -> Detector:
        rules, dedup = load_rules(config_dir)
        prioritizer = Prioritizer.from_config(store, config_dir) if prioritize else None
        every = float(load_yaml("detection.yaml", config_dir).get("reprioritize_every_s", 300))
        return cls(store, rules, dedup, on_alert, prioritizer, every)

    # ---- processing ------------------------------------------------------------------
    def process(self, record: Record) -> list[Alert]:
        """Evaluate one record (records must arrive in time order)."""
        alerts = self._advance(record.ts)
        for rule in self.rules:
            for hit in rule.evaluate(record):
                alerts.append(self._handle(rule, hit))
        self.summary.records += 1
        return alerts

    def process_row(self, kind: str, row: dict[str, Any]) -> list[Alert]:
        return self.process(Record.from_row(kind, row))

    def finish(self, now: datetime | None = None) -> list[Alert]:
        """Run time-based checks up to ``now`` (default: the newest record seen)."""
        alerts = self._advance(now) if now else []
        if self.prioritizer:
            self.prioritizer.run()  # temperatures may have kept rising since the last hit
        self.store.commit()
        return alerts

    def run(self) -> DetectionSummary:
        """Scan every stored event in time order."""
        for kind, row in self.store.iter_records():
            self.process_row(kind, row)
        self.finish()
        return self.summary

    # ---- internals -------------------------------------------------------------------
    def _advance(self, now: datetime) -> list[Alert]:
        if self.now is not None and now <= self.now:
            return []
        self.now = now
        alerts = []
        for rule in self.rules:
            for hit in rule.advance(now):
                alerts.append(self._handle(rule, hit))
        self._regrade(now)
        return alerts

    def _regrade(self, now: datetime) -> None:
        """Re-grade open temperature alerts every ``reprioritize_every`` (Step 14 fix: a
        fridge that keeps warming used to stay LOW until the next hit or the end of the
        run). Severity changes are reported through ``on_alert``."""
        if not self.prioritizer or self.reprioritize_every.total_seconds() <= 0:
            return
        if self._last_regrade is not None and now - self._last_regrade < self.reprioritize_every:
            return
        self._last_regrade = now
        rules = self.prioritizer.settings.temperature_rules
        marks = ", ".join("?" for _ in rules)
        ids = [
            r[0]
            for r in self.store.conn.execute(
                f"""SELECT alert_id FROM alerts WHERE rule_id IN ({marks})
                    AND status IN ('new', 'under_investigation') AND severity_locked = 0
                    AND first_seen >= ?""",
                # the prioritizer grades an excursion over at most 24 h
                [*sorted(rules), iso_utc(now - timedelta(hours=24))],
            )
        ]
        if not ids:
            return
        for alert_id, _old, _new in self.prioritizer.run(ids).changed:
            row = self.store.alert(alert_id)
            if self.on_alert:
                self.on_alert(
                    Alert(
                        alert_id,
                        row["rule_id"],
                        row["rule_name"],
                        row["severity"],
                        row["device_id"],
                        row["subject"],
                        row["title"],
                        now,
                        False,
                    )
                )

    def _handle(self, rule: Rule, hit: RuleHit) -> Alert:
        if not hit.evidence:
            raise ValueError(f"{rule.rule_id}: a hit needs at least one evidence record")
        when = hit.when
        key = (rule.rule_id, hit.subject)
        group = self._groups.get(key)
        if group and when - group[1] <= self.dedup_window:
            alert_id, new = group[0], False
        else:
            first_evidence = min(hit.evidence, key=lambda e: (e[0].ts, e[0].record_id))[0]
            alert_id, new = self.store.get_or_create_alert(
                {
                    "alert_key": f"{rule.rule_id}|{hit.subject}|{first_evidence.record_id}",
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "device_id": hit.device_id,
                    "subject": hit.subject,
                    "title": hit.title,
                    "description": hit.description,
                    "attack_ids": json.dumps(rule.attack),
                    "implements": json.dumps(rule.implements),
                    "first_seen": iso_utc(when),
                    "created_at": iso_utc(datetime.now(UTC)),
                }
            )
        self._groups[key] = (alert_id, when)

        for record, note in hit.evidence:
            self.store.add_evidence(
                alert_id, record.record_id, record.kind, iso_utc(record.ts), note
            )
            if record.is_security and hit.event_status:
                self.store.raise_status(
                    record.record_id,
                    hit.event_status,
                    f"{rule.name}: {note}",
                    rule.rule_id,
                    iso_utc(when),
                )

        severity = rule.severity
        if self.prioritizer:
            # classify this alert and the other alerts on the same device (a temperature
            # alert can make an earlier change alert CRITICAL)
            related = [alert_id]
            if hit.device_id:
                related += [a["alert_id"] for a in self.store.alerts(device=hit.device_id)]
            self.prioritizer.run(related)
            severity = self.store.alert(alert_id)["severity"]

        alert = Alert(
            alert_id,
            rule.rule_id,
            rule.name,
            severity,
            hit.device_id,
            hit.subject,
            hit.title,
            when,
            new,
        )
        self.summary.hits += 1
        self.summary.by_rule[rule.rule_id] = self.summary.by_rule.get(rule.rule_id, 0) + 1
        if new:
            self.summary.new_alerts.append(alert)
        if self.on_alert:
            self.on_alert(alert)
        return alert
