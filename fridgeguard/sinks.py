"""Event sinks: where generated events go.

Events go to the console, a JSON Lines log and the SQLite event database
(``SQLiteSink``). The detection pipeline can also consume them through ``QueueSink``.
"""

from __future__ import annotations

import json
import queue
import time
from pathlib import Path
from typing import Protocol, TextIO

from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    CONFIG_CHANGE,
    TELEMETRY_TEMPERATURE,
    Event,
)
from fridgeguard.timeutil import parse_utc


class EventSink(Protocol):
    def emit(self, event: Event) -> None: ...

    def close(self) -> None: ...


class ListSink:
    """Keeps events in memory (tests, notebooks)."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def emit(self, event: Event) -> None:
        self.events.append(event)

    def close(self) -> None:
        pass


class QueueSink:
    """Hands events to another component through a thread-safe queue."""

    def __init__(self, q: queue.Queue | None = None) -> None:
        self.queue: queue.Queue = q or queue.Queue()

    def emit(self, event: Event) -> None:
        self.queue.put(event)

    def close(self) -> None:
        pass


class JsonlSink:
    """Append-only JSON Lines event log, one event per line."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self.count = 0

    def emit(self, event: Event) -> None:
        self._fh.write(event.to_json() + "\n")
        self._fh.flush()
        self.count += 1

    def close(self) -> None:
        self._fh.close()


class ConsoleSink:
    """Human-readable live view of the simulation."""

    def __init__(self, stream: TextIO, show: str = "all") -> None:
        if show not in ("all", "activity", "none"):
            raise ValueError("show must be all, activity or none")
        self.stream = stream
        self.show = show

    def emit(self, event: Event) -> None:
        if self.show == "none":
            return
        if self.show == "activity" and event.event_type == TELEMETRY_TEMPERATURE:
            return
        self.stream.write(format_event(event) + "\n")
        self.stream.flush()

    def close(self) -> None:
        pass


def format_event(e: Event) -> str:
    ts = e.ts_device.replace("T", " ")[:19] + "Z"
    p = e.payload
    flag = "" if e.scenario == "baseline" else f"  <{e.scenario}>"
    if e.event_type == TELEMETRY_TEMPERATURE:
        expected = f"{p['expected_min_c']:.1f}..{p['expected_max_c']:.1f}"
        detail = (
            f"TEMP    {p['temperature_c']:6.1f} °C  range {expected}"
            f"  setpoint {p['setpoint_c']:.1f}  {p['status']}"
        )
    elif e.event_type == AUTH_LOGIN_SUCCESS:
        detail = f"LOGIN   ok      {e.actor} ({p['role']}) from {e.source_ip}{_window(p)}"
    elif e.event_type == AUTH_LOGIN_FAILURE:
        detail = f"LOGIN   FAILED  {e.actor} from {e.source_ip} reason={p['reason']}"
    elif e.event_type == AUTH_LOGOUT:
        detail = f"LOGOUT          {e.actor} after {p['session_s']} s"
    elif e.event_type == CONFIG_CHANGE:
        detail = (
            f"CONFIG  {p['result'].upper():7} {p['parameter']} {p['old_value']} -> {p['new_value']}"
            f" by {e.actor} ({p['role']}){_window(p)}"
        )
    else:
        detail = json.dumps(p)
    return f"{ts}  {e.device_id}  {detail}{flag}"


# Roles that can change device settings; for them working outside the maintenance
# window is worth pointing out. (The fact is recorded in every event regardless.)
PRIVILEGED_ROLES = {"technician", "admin"}


def _window(p: dict) -> str:
    if p.get("role") in PRIVILEGED_ROLES and not p.get("within_maintenance_window"):
        return "  [outside maintenance window]"
    return ""


class SQLiteSink:
    """Writes events into the centralized event database (Step 7).

    The ingest time is the event's own (simulated) timestamp, so accelerated or
    historical simulations do not look like huge device-clock delays. Commits are
    batched: at most ``commit_every_s`` seconds or ``commit_every_n`` events apart, so
    the dashboard sees live data without one transaction per reading.
    """

    def __init__(
        self, store, commit_every_n: int = 1000, commit_every_s: float = 1.0, on_stored=None
    ) -> None:
        self.store = store
        self.on_stored = on_stored  # called with each IngestResult that was stored
        self.commit_every_n = commit_every_n
        self.commit_every_s = commit_every_s
        self._clock = time.monotonic
        self._pending = 0
        self._last_commit = self._clock()
        self.stored = 0
        self.rejected = 0

    def emit(self, event: Event) -> None:
        result = self.store.ingest(event, parse_utc(event.ts_device))
        if result.error:
            self.rejected += 1
        elif not result.duplicate:
            self.stored += 1
            if self.on_stored:
                self.on_stored(result)
        self._pending += 1
        now = self._clock()
        if self._pending >= self.commit_every_n or now - self._last_commit >= self.commit_every_s:
            self.store.commit()
            self._pending = 0
            self._last_commit = now

    def close(self) -> None:
        self.store.commit()
