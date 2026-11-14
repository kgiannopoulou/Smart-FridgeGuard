"""Device fault injection (added in Step 8 to exercise DET-003 and DET-005).

Faults are planned per simulated day, like user activity, and applied to the fridge
physics. Each one labels the affected device's readings with its scenario name so
detection results can be compared with what really happened.

* ``compressor_failure``: the compressor stops for 2-4 h; the cabinet warms towards room
  temperature and leaves its expected range.
* ``device_offline``: the device sends no readings for 10-45 min (network or power loss).

The injector uses its own random-number stream, so turning faults on or off does not
change the user activity that a given seed produces.
"""

from __future__ import annotations

import heapq
import itertools
import random
from collections.abc import Callable
from datetime import date, datetime, time, timedelta

from fridgeguard.models import BASELINE
from fridgeguard.simulator.fleet import Fleet

COMPRESSOR_FAILURE = "compressor_failure"
DEVICE_OFFLINE = "device_offline"
FAULT_SCENARIOS = [COMPRESSOR_FAILURE, DEVICE_OFFLINE]


class FaultInjector:
    def __init__(self, fleet: Fleet, rng: random.Random, faults_per_day: float):
        if faults_per_day < 0:
            raise ValueError("faults_per_day must be >= 0")
        self.fleet = fleet
        self.rng = rng
        self.faults_per_day = faults_per_day
        self._queue: list[tuple[datetime, int, Callable[[], None]]] = []
        self._seq = itertools.count()
        self._planned_until: date | None = None
        self._busy_until: dict[str, datetime] = {}

    def tick(self, now: datetime) -> None:
        if self.faults_per_day == 0:
            return
        self._ensure_planned(now)
        while self._queue and self._queue[0][0] <= now:
            _, _, action = heapq.heappop(self._queue)
            action()

    def _ensure_planned(self, now: datetime) -> None:
        today = now.astimezone(self.fleet.tz).date()
        if self._planned_until is None:
            self._planned_until = today - timedelta(days=1)
        while self._planned_until < today + timedelta(days=1):
            self._planned_until += timedelta(days=1)
            self._plan_day(self._planned_until, now)

    def _plan_day(self, day: date, not_before: datetime) -> None:
        count = int(self.faults_per_day)
        if self.rng.random() < self.faults_per_day - count:
            count += 1
        midnight = datetime.combine(day, time(0, 0), self.fleet.tz)
        for _ in range(count):
            start = midnight + timedelta(seconds=self.rng.uniform(0, 86400))
            device_id = self.rng.choice(self.fleet.device_ids)
            kind = self.rng.choice(FAULT_SCENARIOS)
            if kind == COMPRESSOR_FAILURE:
                duration = timedelta(hours=self.rng.uniform(2, 4))
            else:
                duration = timedelta(minutes=self.rng.uniform(10, 45))
            if start < not_before or start < self._busy_until.get(device_id, start):
                continue  # in the past, or the device already has a fault then
            self._busy_until[device_id] = start + duration
            self._push(start, self._start(kind, device_id))
            self._push(start + duration, self._stop(kind, device_id))

    def _push(self, at: datetime, action: Callable[[], None]) -> None:
        heapq.heappush(self._queue, (at, next(self._seq), action))

    def _start(self, kind: str, device_id: str) -> Callable[[], None]:
        def action() -> None:
            fridge = self.fleet[device_id]
            if kind == COMPRESSOR_FAILURE:
                fridge.set_compressor_fault(True)
            else:
                fridge.set_offline(True)
            self.fleet.scenario_labels[device_id] = kind

        return action

    def _stop(self, kind: str, device_id: str) -> Callable[[], None]:
        def action() -> None:
            fridge = self.fleet[device_id]
            if kind == COMPRESSOR_FAILURE:
                fridge.set_compressor_fault(False)
            else:
                fridge.set_offline(False)
            self.fleet.scenario_labels[device_id] = BASELINE

        return action
