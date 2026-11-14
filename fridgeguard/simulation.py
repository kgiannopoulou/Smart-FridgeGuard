"""Simulation runner: fleet + user activity on one simulated clock.

Every ``interval_s`` the runner:

1. executes the user activity planned since the previous tick (with its own
   timestamps, so logins and config changes fall between readings),
2. advances the fridge physics and emits one temperature reading per device,
3. moves the clock forward and, in real-time mode, sleeps.

The run can be bounded (``duration``) or continuous until interrupted.
"""

from __future__ import annotations

import random
import time as _time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from fridgeguard.config import load_yaml
from fridgeguard.generator.activity import ActivitySimulator
from fridgeguard.generator.auth import AuthService, UserDirectory
from fridgeguard.models import Event
from fridgeguard.simulator.faults import FaultInjector
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.sinks import EventSink
from fridgeguard.timeutil import parse_utc


@dataclass
class SimulationSettings:
    seed: int = 42
    start: datetime = parse_utc("2026-11-16T04:00:00Z")
    interval_s: float = 60.0
    activity: bool = True
    anomalies_per_day: float = 2.0
    faults_per_day: float = 0.0
    password_hash_iterations: int = 100_000

    @classmethod
    def from_config(cls, config_dir: Path | None = None, **overrides) -> SimulationSettings:
        cfg = load_yaml("simulation.yaml", config_dir)
        activity = cfg.get("activity", {})
        values = {
            "seed": cfg.get("seed", 42),
            "start": parse_utc(cfg["start"]) if "start" in cfg else cls.start,
            "interval_s": float(cfg.get("interval_s", 60)),
            "activity": activity.get("enabled", True),
            "anomalies_per_day": float(activity.get("anomalies_per_day", 2.0)),
            "faults_per_day": float(cfg.get("faults", {}).get("per_day", 0.0)),
            "password_hash_iterations": int(cfg.get("password_hash_iterations", 100_000)),
        }
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)


class Simulation:
    def __init__(
        self,
        settings: SimulationSettings,
        sinks: Iterable[EventSink],
        config_dir: Path | None = None,
    ):
        if settings.interval_s <= 0:
            raise ValueError("interval_s must be positive")
        self.settings = settings
        self.sinks = list(sinks)
        self.rng = random.Random(settings.seed)
        self.now = settings.start
        self.events_emitted = 0
        self.fleet = Fleet.from_config(self.rng, config_dir)
        directory, passwords, users_cfg = UserDirectory.from_config(
            self.rng, settings.password_hash_iterations, config_dir
        )
        self.auth = AuthService.from_config(directory, users_cfg, self.fleet, self.rng, self.emit)
        self.activity = (
            ActivitySimulator(self.auth, passwords, self.rng, settings.anomalies_per_day)
            if settings.activity
            else None
        )
        # separate random stream: enabling faults does not change the user activity
        self.faults = FaultInjector(
            self.fleet, random.Random(settings.seed + 1_000_003), settings.faults_per_day
        )

    def emit(self, event: Event) -> None:
        self.events_emitted += 1
        for sink in self.sinks:
            sink.emit(event)

    def step(self) -> None:
        if self.activity:
            self.activity.tick(self.now)
        self.faults.tick(self.now)
        for event in self.fleet.tick(self.now, self.settings.interval_s):
            self.emit(event)
        self.now += timedelta(seconds=self.settings.interval_s)

    def run(
        self,
        duration: timedelta | None = None,
        *,
        realtime: bool = False,
        speed: float = 1.0,
        should_stop: Callable[[], bool] = lambda: False,
    ) -> int:
        """Run for ``duration`` of simulated time, or forever if ``None``.

        Returns the number of ticks executed.
        """
        end: datetime | None = self.now + duration if duration is not None else None
        ticks = 0
        try:
            while (end is None or self.now < end) and not should_stop():
                started = _time.monotonic()
                self.step()
                ticks += 1
                if realtime:
                    wait = self.settings.interval_s / speed - (_time.monotonic() - started)
                    if wait > 0:
                        _time.sleep(wait)
        finally:
            for sink in self.sinks:
                sink.close()
        return ticks


def parse_duration(text: str) -> timedelta:
    """Parse ``90s``, ``30m``, ``12h`` or ``3d``."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    text = text.strip().lower()
    if not text or text[-1] not in units:
        raise ValueError(f"invalid duration {text!r}; use e.g. 30m, 12h, 3d")
    value = float(text[:-1])
    if value <= 0:
        raise ValueError("duration must be positive")
    return timedelta(seconds=value * units[text[-1]])
