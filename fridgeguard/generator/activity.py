"""User activity simulator (Phase 1, Step 6).

Plans each simulated day in advance (local site time) and executes the planned steps
as the simulation clock passes them.

Normal behaviour (scenario label ``baseline``):

* ``store_manager`` checks a fridge in the morning and the evening, sometimes
  mistyping the password once.
* ``maintenance_tech`` works inside the maintenance window on weekdays: logs in,
  nudges a setpoint or changes the defrost interval, logs out.
* ``system_admin`` occasionally updates firmware or a defrost setting, also inside
  the maintenance window (change-managed work).

Suspicious behaviour (injected ``anomalies_per_day`` times on average, each with its
own ground-truth label so detection accuracy can be measured later):

* ``unknown_login_attempts``: an outsider tries several usernames and passwords.
* ``off_hours_access``: the technician account logs in at night and changes a setpoint.
* ``unauthorized_change_attempt``: the store manager tries to change a setpoint
  (denied by role-based access control).
"""

from __future__ import annotations

import heapq
import itertools
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from fridgeguard.generator.auth import AuthService, Session
from fridgeguard.models import BASELINE
from fridgeguard.timeutil import parse_hhmm

COMMON_PASSWORDS = ["123456", "password", "admin", "admin123", "fridge2026", "letmein", "qwerty"]
GUESSED_USERNAMES = ["unknown_user", "admin", "root", "system_admin", "technician"]

SCENARIO_UNKNOWN_LOGIN = "unknown_login_attempts"
SCENARIO_OFF_HOURS = "off_hours_access"
SCENARIO_UNAUTHORIZED_CHANGE = "unauthorized_change_attempt"
ANOMALY_SCENARIOS = [SCENARIO_UNKNOWN_LOGIN, SCENARIO_OFF_HOURS, SCENARIO_UNAUTHORIZED_CHANGE]


@dataclass(order=True)
class PlannedStep:
    at: datetime
    seq: int
    action: Callable[[datetime], None] = field(compare=False)


@dataclass
class Visit:
    """State shared by the steps of one user session."""

    username: str
    device_id: str
    source_ip: str
    scenario: str
    session: Session | None = None


class ActivitySimulator:
    def __init__(
        self,
        auth: AuthService,
        passwords: dict[str, str],
        rng: random.Random,
        anomalies_per_day: float = 2.0,
    ):
        self.auth = auth
        self.fleet = auth.fleet
        self.directory = auth.directory
        self.passwords = passwords  # what each simulated person remembers
        self.rng = rng
        self.anomalies_per_day = anomalies_per_day
        self.tz = auth.tz
        self._queue: list[PlannedStep] = []
        self._seq = itertools.count()
        self._planned_until: date | None = None

    # ---- public ----------------------------------------------------------------------
    def tick(self, now: datetime) -> None:
        """Plan new days as needed and run every step due up to ``now``."""
        self._ensure_planned(now)
        while self._queue and self._queue[0].at <= now:
            step = heapq.heappop(self._queue)
            step.action(step.at)

    @property
    def pending(self) -> int:
        return len(self._queue)

    # ---- planning --------------------------------------------------------------------
    def _ensure_planned(self, now: datetime) -> None:
        today = now.astimezone(self.tz).date()
        if self._planned_until is None:
            self._plan_day(today, not_before=now)
            self._planned_until = today
        while self._planned_until < today + timedelta(days=1):
            self._planned_until += timedelta(days=1)
            self._plan_day(self._planned_until, not_before=now)

    def _at(self, day: date, start: str, end: str) -> datetime:
        """Random local time between ``start`` and ``end`` (HH:MM) on ``day``."""
        a = datetime.combine(day, parse_hhmm(start), self.tz)
        b = datetime.combine(day, parse_hhmm(end), self.tz)
        return self._between(a, b)

    def _between(self, a: datetime, b: datetime) -> datetime:
        return a + timedelta(seconds=self.rng.uniform(0, max(0.0, (b - a).total_seconds())))

    def _schedule(self, at: datetime, action: Callable[[datetime], None], not_before: datetime):
        if at >= not_before:
            heapq.heappush(self._queue, PlannedStep(at, next(self._seq), action))

    def _plan_day(self, day: date, not_before: datetime) -> None:
        plans: list[tuple[datetime, list[tuple[float, Callable]]]] = []
        weekday = day.weekday()

        # store manager: morning and evening check
        for start, end in (("07:00", "08:30"), ("20:00", "21:30")):
            plans.append((self._at(day, start, end), self._manager_check()))

        # technician (every maintenance day) and admin (some days): planned work inside
        # the maintenance window; start 10 min after it opens, leave an hour to finish
        mw = self.auth.maintenance_window
        if weekday in mw.days:
            opens = datetime.combine(day, mw.start, self.tz) + timedelta(minutes=10)
            closes = datetime.combine(day, mw.end, self.tz) - timedelta(minutes=60)
            plans.append((self._between(opens, closes), self._technician_maintenance()))
            if self.rng.random() < 0.4:
                plans.append((self._between(opens, closes), self._admin_task()))

        # anomalies
        count = int(self.anomalies_per_day)
        if self.rng.random() < self.anomalies_per_day - count:
            count += 1
        for _ in range(count):
            kind = self.rng.choice(ANOMALY_SCENARIOS)
            if kind == SCENARIO_UNKNOWN_LOGIN:
                plans.append((self._at(day, "00:00", "23:59"), self._unknown_login_attempts()))
            elif kind == SCENARIO_OFF_HOURS:
                plans.append((self._at(day, "00:30", "04:30"), self._off_hours_access()))
            else:
                plans.append((self._at(day, "09:00", "19:00"), self._unauthorized_change()))

        for start, steps in plans:
            for offset_s, action in steps:
                self._schedule(start + timedelta(seconds=offset_s), action, not_before)

    # ---- building blocks -------------------------------------------------------------
    def _visit(self, username: str, scenario: str, device_id: str | None = None) -> Visit:
        user = self.directory.get(username)
        ips = user.known_ips if user and user.known_ips else ("10.10.1.99",)
        return Visit(
            username=username,
            device_id=device_id or self.rng.choice(self.fleet.device_ids),
            source_ip=self.rng.choice(ips),
            scenario=scenario,
        )

    def _login(self, v: Visit, password: str | None = None) -> Callable[[datetime], None]:
        def action(ts: datetime) -> None:
            pw = password if password is not None else self.passwords.get(v.username, "")
            v.session = self.auth.login(
                ts, v.username, pw, v.device_id, v.source_ip, scenario=v.scenario
            )

        return action

    def _logout(self, v: Visit) -> Callable[[datetime], None]:
        def action(ts: datetime) -> None:
            if v.session:
                self.auth.logout(ts, v.session, scenario=v.scenario)
                v.session = None

        return action

    def _change(self, v: Visit, parameter: str, value_fn: Callable) -> Callable[[datetime], None]:
        def action(ts: datetime) -> None:
            if v.session:
                fridge = self.fleet[v.device_id]
                self.auth.change_config(
                    ts, v.session, parameter, value_fn(fridge), scenario=v.scenario
                )

        return action

    def _nudged_setpoint(self, fridge, max_step: float = 0.5) -> float:
        """A small, safe setpoint adjustment that stays inside the expected range."""
        spec = fridge.spec
        low, high = spec.safe_min_c + 1.0, spec.safe_max_c - 1.0
        target = fridge.setpoint_c + self.rng.choice([-max_step, max_step])
        if not low <= target <= high:
            target = spec.setpoint_c
        return round(target, 1)

    def _other_defrost_interval(self, fridge) -> int:
        """A defrost interval different from the current one (no no-op changes)."""
        return self.rng.choice([h for h in (6, 8, 12) if h != fridge.defrost_interval_h])

    # ---- routines --------------------------------------------------------------------
    def _manager_check(self) -> list[tuple[float, Callable]]:
        v = self._visit("store_manager", BASELINE)
        steps: list[tuple[float, Callable]] = []
        offset = 0.0
        if self.rng.random() < 0.15:  # typo, then the right password
            steps.append((offset, self._login(v, password=self.passwords[v.username] + "1")))
            offset += self.rng.uniform(5, 20)
        steps.append((offset, self._login(v)))
        steps.append((offset + self.rng.uniform(300, 900), self._logout(v)))
        return steps

    def _technician_maintenance(self) -> list[tuple[float, Callable]]:
        v = self._visit("maintenance_tech", BASELINE)
        steps: list[tuple[float, Callable]] = [(0, self._login(v))]
        offset = self.rng.uniform(60, 180)
        steps.append((offset, self._change(v, "setpoint_c", self._nudged_setpoint)))
        if self.rng.random() < 0.3:
            offset += self.rng.uniform(60, 240)
            steps.append(
                (
                    offset,
                    self._change(v, "defrost_interval_h", self._other_defrost_interval),
                )
            )
        steps.append((offset + self.rng.uniform(600, 1500), self._logout(v)))
        return steps

    def _admin_task(self) -> list[tuple[float, Callable]]:
        v = self._visit("system_admin", BASELINE)
        steps: list[tuple[float, Callable]] = [(0, self._login(v))]
        if self.rng.random() < 0.5:

            def next_firmware(fridge) -> str:
                major, minor, patch = (int(p) for p in fridge.firmware_version.split("."))
                return f"{major}.{minor}.{patch + 1}"

            steps.append(
                (self.rng.uniform(60, 300), self._change(v, "firmware_version", next_firmware))
            )
        else:
            steps.append(
                (
                    self.rng.uniform(60, 300),
                    self._change(v, "defrost_interval_h", self._other_defrost_interval),
                )
            )
        steps.append((self.rng.uniform(600, 1200), self._logout(v)))
        return steps

    def _unknown_login_attempts(self) -> list[tuple[float, Callable]]:
        actor = self.directory.get("unknown_user")
        ip = self.rng.choice(actor.known_ips if actor else ("203.0.113.50",))
        device_id = self.rng.choice(self.fleet.device_ids)
        steps, offset = [], 0.0
        for _ in range(self.rng.randint(3, 8)):
            v = Visit(self.rng.choice(GUESSED_USERNAMES), device_id, ip, SCENARIO_UNKNOWN_LOGIN)
            steps.append((offset, self._login(v, password=self.rng.choice(COMMON_PASSWORDS))))
            offset += self.rng.uniform(5, 30)
        return steps

    def _off_hours_access(self) -> list[tuple[float, Callable]]:
        v = self._visit("maintenance_tech", SCENARIO_OFF_HOURS)

        def raised_setpoint(fridge) -> float:
            return round(fridge.setpoint_c + self.rng.choice([1.0, 1.5, 2.0]), 1)

        return [
            (0, self._login(v)),
            (self.rng.uniform(60, 180), self._change(v, "setpoint_c", raised_setpoint)),
            (self.rng.uniform(300, 600), self._logout(v)),
        ]

    def _unauthorized_change(self) -> list[tuple[float, Callable]]:
        v = self._visit("store_manager", SCENARIO_UNAUTHORIZED_CHANGE)
        return [
            (0, self._login(v)),
            (self.rng.uniform(30, 120), self._change(v, "setpoint_c", lambda f: f.setpoint_c + 2)),
            (self.rng.uniform(180, 400), self._logout(v)),
        ]
