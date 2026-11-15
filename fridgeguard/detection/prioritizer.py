"""Alert prioritization (Phase 2, Step 10).

The :class:`Prioritizer` classifies every alert into INFO, LOW, MEDIUM, HIGH or CRITICAL
using ``config/prioritization.yaml``. The steps, in order:

1. start from the rule's base severity (``config/detection.yaml``);
2. **refused change:** an unauthorized change the device did not apply is lowered;
3. **temperature deviation:** an excursion is serious or minor depending on how far the
   worst reading went beyond the expected range;
4. **critical device:** some rules are raised one level on critical devices (vaccines),
   up to ``max_severity`` (HIGH by default);
5. **change then temperature:** an applied unauthorized change followed on the same
   device by a temperature excursion makes both alerts CRITICAL.

Every decision is written to the alert as a plain-language reason, and every change of
severity to ``alert_history`` (actor ``prioritizer``). Alerts whose severity an analyst
has set by hand are left alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from fridgeguard.config import load_yaml
from fridgeguard.storage import EventStore
from fridgeguard.storage.store import SEVERITY_LEVELS
from fridgeguard.timeutil import parse_utc

ACTOR = "prioritizer"
MAX_EXCURSION = timedelta(hours=24)


def raise_one(severity: str, ceiling: str = "CRITICAL") -> str:
    """One level up, but never above ``ceiling`` and never from INFO or above the ceiling."""
    rank, top = SEVERITY_LEVELS.index(severity), SEVERITY_LEVELS.index(ceiling)
    if severity == "INFO" or rank >= top:
        return severity
    return SEVERITY_LEVELS[rank + 1]


@dataclass
class PrioritySettings:
    chain_enabled: bool = True
    chain_change_rules: set[str] = field(default_factory=lambda: {"DET-001", "DET-006"})
    chain_temperature_rules: set[str] = field(default_factory=lambda: {"DET-003"})
    chain_window: timedelta = timedelta(hours=2)
    chain_severity: str = "CRITICAL"
    refused_rules: set[str] = field(default_factory=lambda: {"DET-001", "DET-006"})
    refused_severity: str = "MEDIUM"
    temperature_rules: set[str] = field(default_factory=lambda: {"DET-003"})
    serious_c: float = 2.0
    serious_severity: str = "HIGH"
    minor_severity: str = "LOW"
    critical_devices: set[str] = field(default_factory=set)
    critical_device_rules: set[str] = field(default_factory=set)
    critical_max_severity: str = "HIGH"

    @classmethod
    def from_config(cls, config_dir: Path | None = None) -> PrioritySettings:
        cfg = load_yaml("prioritization.yaml", config_dir)
        chain = cfg.get("change_then_temperature") or {}
        refused = cfg.get("refused_change") or {}
        temp = cfg.get("temperature_deviation") or {}
        crit = cfg.get("critical_devices") or {}
        d = cls()
        settings = cls(
            chain_enabled=bool(chain.get("enabled", True)),
            chain_change_rules=set(chain.get("change_rules", d.chain_change_rules)),
            chain_temperature_rules=set(chain.get("temperature_rules", d.chain_temperature_rules)),
            chain_window=timedelta(seconds=float(chain.get("window_s", 7200))),
            chain_severity=str(chain.get("severity", d.chain_severity)).upper(),
            refused_rules=set(refused.get("rules", d.refused_rules)),
            refused_severity=str(refused.get("severity", d.refused_severity)).upper(),
            temperature_rules=set(temp.get("rules", d.temperature_rules)),
            serious_c=float(temp.get("serious_c", d.serious_c)),
            serious_severity=str(temp.get("serious_severity", d.serious_severity)).upper(),
            minor_severity=str(temp.get("minor_severity", d.minor_severity)).upper(),
            critical_devices=set(crit.get("devices", [])),
            critical_device_rules=set(crit.get("rules", [])),
            critical_max_severity=str(crit.get("max_severity", d.critical_max_severity)).upper(),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        names = (
            "chain_severity",
            "refused_severity",
            "serious_severity",
            "minor_severity",
            "critical_max_severity",
        )
        for name in names:
            if getattr(self, name) not in SEVERITY_LEVELS:
                raise ValueError(f"prioritization: {name} must be one of {SEVERITY_LEVELS}")
        if self.chain_window.total_seconds() <= 0:
            raise ValueError("prioritization: change_then_temperature.window_s must be > 0")
        if self.serious_c < 0:
            raise ValueError("prioritization: temperature_deviation.serious_c must be >= 0")


@dataclass
class Classification:
    severity: str
    reasons: list[str]

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons)


@dataclass
class PrioritySummary:
    alerts: int = 0
    changed: list[tuple[str, str, str]] = field(default_factory=list)  # (alert, old, new)


class Prioritizer:
    def __init__(self, store: EventStore, settings: PrioritySettings | None = None):
        self.store = store
        self.settings = settings or PrioritySettings()

    @classmethod
    def from_config(cls, store: EventStore, config_dir: Path | None = None) -> Prioritizer:
        return cls(store, PrioritySettings.from_config(config_dir))

    # ---- public ------------------------------------------------------------------------
    def run(self, alert_ids: list[str] | None = None) -> PrioritySummary:
        """Classify all alerts (or the given ones) and store the results."""
        alerts = self.store.alerts(alert_ids=alert_ids) if alert_ids else self.store.alerts()
        context = self._context()
        summary = PrioritySummary(alerts=len(alerts))
        for alert in alerts:
            result = self.classify(alert, context)
            old = alert["severity"]
            if self.store.set_alert_severity(
                alert["alert_id"], result.severity, ACTOR, result.reason, lock=False
            ):
                summary.changed.append((alert["alert_id"], old, result.severity))
        self.store.commit()
        return summary

    def classify(self, alert: dict[str, Any], context: dict | None = None) -> Classification:
        """Severity and reasons for one alert (nothing is stored)."""
        s = self.settings
        context = context if context is not None else self._context()
        rule = alert["rule_id"]
        severity = alert["base_severity"]
        reasons = [f"{rule} base severity {severity}"]

        if rule in s.refused_rules and not self._applied(alert):
            severity = s.refused_severity
            reasons.append(f"change was refused by the device, nothing changed -> {severity}")

        if rule in s.temperature_rules:
            found = self._worst_deviation(alert)
            if found is not None:
                worst, temp = found
                serious = worst >= s.serious_c
                severity = s.serious_severity if serious else s.minor_severity
                grade = "serious" if serious else "minor"
                reasons.append(
                    f"{grade} deviation: worst reading {temp:.1f} °C, {worst:.1f} °C beyond the "
                    f"expected range (serious from {s.serious_c:g} °C) -> {severity}"
                )

        if alert["device_id"] in s.critical_devices and rule in s.critical_device_rules:
            raised = raise_one(severity, s.critical_max_severity)
            if raised != severity:
                severity = raised
                reasons.append(f"{alert['device_id']} is a critical device -> {severity}")
            elif severity != "INFO":
                reasons.append(
                    f"{alert['device_id']} is a critical device, already at "
                    f"{s.critical_max_severity} or above (the most this factor raises to)"
                )

        partner = self._chain_partner(alert, context)
        if partner:
            severity = s.chain_severity
            reasons.append(partner + f" -> {severity}")
        return Classification(severity, reasons)

    # ---- helpers -----------------------------------------------------------------------
    def _context(self) -> dict:
        """Applied unauthorized changes and temperature alerts per device (for the chain)."""
        s = self.settings
        changes: dict[str, list[tuple[Any, str]]] = {}
        temps: dict[str, list[tuple[Any, str]]] = {}
        if not s.chain_enabled:
            return {"changes": changes, "temps": temps}
        for a in self.store.alerts():
            if not a["device_id"]:
                continue
            if a["rule_id"] in s.chain_change_rules:
                when = self._applied(a)
                if when:
                    changes.setdefault(a["device_id"], []).append((when, a["alert_id"]))
            elif a["rule_id"] in s.chain_temperature_rules:
                start = self._excursion_start(a)
                temps.setdefault(a["device_id"], []).append((start, a["alert_id"]))
        return {"changes": changes, "temps": temps}

    def _chain_partner(self, alert: dict[str, Any], context: dict) -> str | None:
        s = self.settings
        device, rule = alert["device_id"], alert["rule_id"]
        if not s.chain_enabled or not device:
            return None
        window = s.chain_window
        if rule in s.chain_change_rules:
            changed = self._applied(alert)
            if not changed:
                return None
            for start, other in context["temps"].get(device, []):
                if changed <= start <= changed + window:
                    return f"followed by temperature excursion {other} on {device}"
        elif rule in s.chain_temperature_rules:
            start = self._excursion_start(alert)
            for changed, other in context["changes"].get(device, []):
                if changed <= start <= changed + window:
                    return f"preceded by unauthorized change {other} on {device}"
        return None

    def _applied(self, alert: dict[str, Any]):
        """Time of the first applied change in the alert's evidence, or None."""
        ids = [e["record_id"] for e in self.store.alert_evidence(alert["alert_id"])]
        rows = self.store.security_rows(ids)
        times = [parse_utc(r["ts_device"]) for r in rows.values() if r["result"] == "applied"]
        return min(times) if times else None

    def _excursion_start(self, alert: dict[str, Any]):
        evidence = self.store.alert_evidence(alert["alert_id"])
        times = [parse_utc(e["ts"]) for e in evidence if e["kind"] == "telemetry"]
        return min(times) if times else parse_utc(alert["first_seen"])

    def _worst_deviation(self, alert: dict[str, Any]) -> tuple[float, float] | None:
        """(°C beyond the expected range, temperature) of the worst reading, from the start
        of the excursion until the device is back in range (at most 24 h)."""
        if not alert["device_id"]:
            return None
        start = self._excursion_start(alert)
        worst: tuple[float, float] | None = None
        for r in self.store.readings_from(alert["device_id"], start, start + MAX_EXCURSION):
            t, low, high = r["temperature_c"], r["expected_min_c"], r["expected_max_c"]
            beyond = max(low - t, t - high)
            if beyond <= 0:
                if worst is not None:
                    break  # back in range: the excursion is over
                continue
            if worst is None or beyond > worst[0]:
                worst = (beyond, t)
        return worst
