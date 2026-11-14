"""Common event model shared by every component (docs/architecture.md, section 5)."""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# Event types produced by the simulators.
TELEMETRY_TEMPERATURE = "telemetry.temperature"
AUTH_LOGIN_SUCCESS = "auth.login_success"
AUTH_LOGIN_FAILURE = "auth.login_failure"
AUTH_LOGOUT = "auth.logout"
CONFIG_CHANGE = "config.change"

EVENT_TYPES = {
    TELEMETRY_TEMPERATURE,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGIN_FAILURE,
    AUTH_LOGOUT,
    CONFIG_CHANGE,
}

BASELINE = "baseline"


def iso_utc(ts: datetime) -> str:
    """Format a timezone-aware datetime as ISO 8601 UTC with milliseconds (NFR-1)."""
    if ts.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return ts.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_event_id(rng: random.Random) -> str:
    """UUID v4 drawn from the simulation RNG so seeded runs are reproducible."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    device_id: str
    ts_device: str
    actor: str | None = None
    source_ip: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    scenario: str = BASELINE
    ts_ingest: str | None = None  # set by the detection pipeline on arrival
    hash: str = ""

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {self.event_type}")
        if not self.hash:
            object.__setattr__(self, "hash", self.compute_hash())

    def compute_hash(self) -> str:
        """SHA-256 over the canonical JSON of the content fields (NFR-5)."""
        content = {k: v for k, v in asdict(self).items() if k not in ("hash", "ts_ingest")}
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def make_event(
    rng: random.Random,
    event_type: str,
    device_id: str,
    ts: datetime,
    *,
    actor: str | None = None,
    source_ip: str | None = None,
    payload: dict[str, Any] | None = None,
    scenario: str = BASELINE,
) -> Event:
    return Event(
        event_id=new_event_id(rng),
        event_type=event_type,
        device_id=device_id,
        ts_device=iso_utc(ts),
        actor=actor,
        source_ip=source_ip,
        payload=payload or {},
        scenario=scenario,
    )
