"""Building blocks shared by all detection rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from fridgeguard.timeutil import parse_utc

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
TELEMETRY = "telemetry"
SECURITY = "security"


@dataclass(frozen=True)
class Record:
    """One stored event as the rules see it."""

    kind: str  # "telemetry" or "security"
    record_id: str  # TEL-000001 / EVT-000001
    ts: datetime
    device_id: str
    data: dict[str, Any]

    @classmethod
    def from_row(cls, kind: str, row: dict[str, Any]) -> Record:
        record_id = row["reading_id"] if kind == TELEMETRY else row["event_id"]
        return cls(kind, record_id, parse_utc(row["ts_device"]), row["device_id"], row)

    @property
    def is_security(self) -> bool:
        return self.kind == SECURITY

    @property
    def payload(self) -> dict[str, Any]:
        """The original event payload (fields not promoted to columns)."""
        return json.loads(self.data["raw_json"]).get("payload", {})

    def __getitem__(self, key: str) -> Any:
        return self.data.get(key)

    def change_text(self) -> str:
        """'setpoint_c 4.0 °C -> 10.0 °C' for configuration events."""
        unit = self.data.get("unit") or ""
        old, new = self.data.get("previous_value"), self.data.get("new_value")
        return f"{self.data.get('parameter')} {old}{unit} -> {new}{unit}"


@dataclass
class RuleHit:
    """A rule match. The detector turns hits into (grouped) alerts."""

    subject: str  # what the alert is about; hits with the same subject are grouped
    device_id: str | None
    title: str
    description: str
    evidence: list[tuple[Record, str]] = field(default_factory=list)  # (record, note)
    event_status: str | None = "suspicious"  # verdict for security events in evidence
    ts: datetime | None = None  # when the condition was met (default: latest evidence)

    @property
    def when(self) -> datetime:
        if self.ts is not None:
            return self.ts
        return max(rec.ts for rec, _ in self.evidence)


@dataclass(frozen=True)
class DetectionContext:
    tz: ZoneInfo


class Rule:
    """Base class. Subclasses set ``type_name`` and ``defaults`` and override
    :meth:`evaluate` (called for every record, in time order) and/or :meth:`advance`
    (called whenever detection time moves forward, for absence-of-data rules)."""

    type_name: ClassVar[str] = ""
    defaults: ClassVar[dict[str, Any]] = {}
    required: ClassVar[tuple[str, ...]] = ()

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        params: dict[str, Any] | None,
        context: DetectionContext,
        *,
        implements: list[str] | None = None,
        attack: list[str] | None = None,
    ):
        if severity not in SEVERITIES:
            raise ValueError(f"{rule_id}: severity must be one of {SEVERITIES}")
        params = dict(params or {})
        unknown = set(params) - set(self.defaults) - set(self.required)
        if unknown:
            raise ValueError(f"{rule_id}: unknown parameters {sorted(unknown)}")
        missing = [p for p in self.required if p not in params]
        if missing:
            raise ValueError(f"{rule_id}: missing parameters {missing}")
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.params = {**self.defaults, **params}
        self.context = context
        self.implements = list(implements or [])
        self.attack = list(attack or [])
        self.setup()

    def setup(self) -> None:
        """Validate parameters and create per-rule state."""

    def evaluate(self, record: Record) -> list[RuleHit]:
        return []

    def advance(self, now: datetime) -> list[RuleHit]:
        return []


RULE_TYPES: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    if not cls.type_name:
        raise ValueError(f"{cls.__name__} has no type_name")
    if cls.type_name in RULE_TYPES:
        raise ValueError(f"duplicate rule type {cls.type_name}")
    RULE_TYPES[cls.type_name] = cls
    return cls


def minutes(seconds: float) -> str:
    return f"{seconds / 60:.0f} min"


def short_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M UTC")
