"""Controlled test scenarios (Phase 4, Step 14): ``scenarios/TC-*.yaml``.

A scenario is a simulated period plus scripted actions at fixed offsets, and the alerts
and incident the system is expected to produce. See ``scenarios/README.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from fridgeguard.config import PROJECT_ROOT
from fridgeguard.simulation import parse_duration
from fridgeguard.storage.store import SEVERITY_LEVELS
from fridgeguard.timeutil import parse_utc

SCENARIO_DIR = PROJECT_ROOT / "scenarios"
ACTIONS = {"login", "fail_logins", "change", "logout", "compressor_fault", "offline", "door_open"}


@dataclass(frozen=True)
class Step:
    id: str
    at: timedelta
    action: str
    params: dict[str, Any]


@dataclass(frozen=True)
class ExpectedAlert:
    rule: str
    severity: str | None  # exact
    min_severity: str | None
    from_step: str | None

    def matches_severity(self, severity: str) -> bool:
        if self.severity:
            return severity == self.severity
        if self.min_severity:
            return SEVERITY_LEVELS.index(severity) >= SEVERITY_LEVELS.index(self.min_severity)
        return True

    @property
    def wanted(self) -> str:
        return self.severity or (f">= {self.min_severity}" if self.min_severity else "any")


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    expected_result: str
    description: str
    threat: str
    start: datetime
    duration: timedelta
    activity: bool
    steps: list[Step]
    expected: list[ExpectedAlert]
    allow: set[str]
    incident: str | None
    events_status: str | None
    path: Path = field(compare=False)
    # the near-miss must really happen: {"device": ..., "min_readings": n} out of range
    out_of_range: dict[str, Any] | None = None

    def step(self, step_id: str) -> Step:
        for s in self.steps:
            if s.id == step_id:
                return s
        raise KeyError(f"{self.id}: unknown step {step_id!r}")

    @property
    def expectation_text(self) -> str:
        parts = [f"{e.rule} {e.wanted}" for e in self.expected if e.wanted != "INFO"]
        info = [e.rule for e in self.expected if e.wanted == "INFO"]
        if info:
            parts.append(f"{', '.join(info)} INFO (activity recorded)")
        if self.incident:
            parts.append(f"incident {self.incident}")
        if self.events_status:
            parts.append(f"events {self.events_status}")
        if self.out_of_range:
            parts.append(
                f">= {self.out_of_range['min_readings']} out-of-range readings on "
                f"{self.out_of_range['device']} (it really happened)"
            )
        return "; ".join(parts) or "no alert above INFO"

    @classmethod
    def load(cls, path: Path) -> Scenario:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        sid = raw["id"]
        steps = []
        for i, s in enumerate(raw.get("steps") or []):
            s = dict(s)
            action = s.pop("action")
            if action not in ACTIONS:
                raise ValueError(f"{sid}: unknown action {action!r}; known: {sorted(ACTIONS)}")
            step_id = str(s.pop("id", f"step{i + 1}"))
            steps.append(Step(step_id, parse_duration(str(s.pop("at"))), action, s))
        exp = raw.get("expect") or {}
        expected = []
        for e in exp.get("alerts") or []:
            for key in ("severity", "min_severity"):
                if e.get(key) and e[key] not in SEVERITY_LEVELS:
                    raise ValueError(f"{sid}: bad {key} {e[key]!r}")
            expected.append(
                ExpectedAlert(e["rule"], e.get("severity"), e.get("min_severity"), e.get("from"))
            )
        scenario = cls(
            id=sid,
            name=raw["name"],
            expected_result=str(raw.get("expected_result", "")),
            description=" ".join(str(raw.get("description", "")).split()),
            threat=str(raw.get("threat", "-")),
            start=parse_utc(raw["start"]),
            duration=parse_duration(str(raw["duration"])),
            activity=bool(raw.get("activity", False)),
            steps=steps,
            expected=expected,
            allow=set(exp.get("allow") or []),
            incident=exp.get("incident"),
            events_status=exp.get("events_status"),
            path=path,
            out_of_range=exp.get("out_of_range"),
        )
        for e in expected:
            if e.from_step:
                scenario.step(e.from_step)  # validates the reference
        return scenario


def load_scenarios(directory: Path | None = None, only: list[str] | None = None) -> list[Scenario]:
    directory = directory or SCENARIO_DIR
    scenarios = [Scenario.load(p) for p in sorted(directory.glob("TC-*.yaml"))]
    if only:
        wanted = {o.upper() for o in only}
        scenarios = [s for s in scenarios if s.id.upper() in wanted]
    if not scenarios:
        raise ValueError(f"no scenarios found in {directory}")
    return scenarios
