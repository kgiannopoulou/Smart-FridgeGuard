"""Run a controlled scenario through the complete system and measure the result
(Phase 4, Step 14).

One run = one scenario with one random seed:

1. the real simulator (thermal model, door openings, sensor noise, users with PBKDF2
   passwords and RBAC) produces readings every 60 s; a :class:`Driver` executes the
   scenario's scripted actions at their times through the same interfaces the normal
   activity uses (``AuthService.login/change_config/logout``, fridge fault controls);
2. every event goes through the production pipeline: ``SQLiteSink`` -> ``EventStore``
   (validation, hashing) -> live ``Detector`` (rules + prioritizer) -> ``Notifier``;
   at the end ``Correlator`` groups incidents;
3. the stored alerts are compared with the scenario's expectations: true positives,
   missed detections, false positives, time to detect, incident pattern, event status;
4. reliability checks: re-running detection over the stored events must create no new
   alert and no new notification, and every expected HIGH+ alert must have a
   notification decision.
"""

from __future__ import annotations

import heapq
import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fridgeguard.detection import Correlator, Detector
from fridgeguard.evaluation.scenario import ExpectedAlert, Scenario
from fridgeguard.notifications import Channel, Notifier
from fridgeguard.notifications import Settings as NotifySettings
from fridgeguard.simulation import Simulation, SimulationSettings, parse_duration
from fridgeguard.sinks import SQLiteSink
from fridgeguard.storage import EventStore
from fridgeguard.storage.store import SEVERITY_LEVELS


class CollectingChannel(Channel):
    """In-memory notification channel (HIGH and above) used to check delivery."""

    name = "collect"

    def __init__(self) -> None:
        super().__init__("HIGH")
        self.messages = []

    def send(self, message) -> str:
        self.messages.append(message)
        return "collected"


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Driver:
    """Executes a scenario's scripted steps on the simulator at their times."""

    def __init__(self, sim: Simulation, scenario: Scenario):
        self.sim, self.scenario = sim, scenario
        self.sessions: dict[str, Any] = {}
        self.step_times: dict[str, datetime] = {}
        self._queue: list[tuple[datetime, int, Callable[[datetime], None]]] = []
        self._seq = itertools.count()
        for step in scenario.steps:
            at = scenario.start + step.at
            self.step_times[step.id] = at
            if step.action == "fail_logins":
                gap = timedelta(seconds=float(step.params.get("interval_s", 20)))
                for i, user in enumerate(step.params["users"]):
                    self._push(at + i * gap, self._failed_login(step.params, user))
            else:
                self._push(at, self._action(step))

    def _push(self, at: datetime, action: Callable[[datetime], None]) -> None:
        heapq.heappush(self._queue, (at, next(self._seq), action))

    def run_due(self, now: datetime) -> None:
        while self._queue and self._queue[0][0] <= now:
            at, _, action = heapq.heappop(self._queue)
            action(at)

    # ---- actions ----------------------------------------------------------------------
    def _failed_login(self, p: dict[str, Any], user: str) -> Callable[[datetime], None]:
        def run(at: datetime) -> None:
            self.sim.auth.login(
                at, user, "not-the-password", p["device"], p["ip"], scenario=self.scenario.id
            )

        return run

    def _action(self, step) -> Callable[[datetime], None]:
        p, sid, auth = step.params, self.scenario.id, self.sim.auth

        def run(at: datetime) -> None:
            if step.action == "login":
                password = self.sim.passwords[p["user"]]
                session = auth.login(at, p["user"], password, p["device"], p["ip"], scenario=sid)
                if session is None:
                    raise RuntimeError(f"{sid}: scripted login {step.id} failed")
                self.sessions[step.id] = session
            elif step.action == "change":
                auth.change_config(
                    at,
                    self.sessions[p["session"]],
                    p["parameter"],
                    p["value"],
                    scenario=sid,
                    enforce_rbac=bool(p.get("enforce_rbac", True)),
                )
            elif step.action == "logout":
                auth.logout(at, self.sessions[p["session"]], scenario=sid)
            elif step.action == "door_open":
                self.sim.fleet[p["device"]].open_door(parse_duration(str(p["for"])).total_seconds())
            else:  # compressor_fault / offline: physical faults on one fridge
                fridge = self.sim.fleet[p["device"]]
                setter = (
                    fridge.set_compressor_fault
                    if step.action == "compressor_fault"
                    else fridge.set_offline
                )
                setter(True)
                self.sim.fleet.scenario_labels[p["device"]] = sid

                def stop(_: datetime) -> None:
                    setter(False)
                    self.sim.fleet.scenario_labels[p["device"]] = "baseline"

                self._push(at + parse_duration(str(p["for"])), stop)

        return run


@dataclass
class Match:
    expected: ExpectedAlert
    alert: dict[str, Any] | None  # best candidate (None: rule never fired)
    ttd_s: float | None
    notify_s: float | None = None  # first HIGH+ notification sent, from the same step

    @property
    def detected(self) -> bool:
        return self.alert is not None and self.expected.matches_severity(self.alert["severity"])


@dataclass
class RunResult:
    scenario: Scenario
    seed: int
    events: int
    wall_s: float
    alerts: list[dict[str, Any]]
    matches: list[Match]
    false_positives: list[dict[str, Any]]
    incidents: list[str]
    incident_ok: bool | None
    status_ok: bool | None
    statuses: dict[str, int]
    notified_ok: bool
    notifications_sent: int
    notifications_suppressed: int
    idempotent_ok: bool
    rejected: int = 0
    out_of_range_readings: int | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> tuple:
        """What the run produced, for the determinism check (same seed, same result)."""
        return (
            tuple((a["rule_id"], a["severity"], a["first_seen"]) for a in self.alerts),
            tuple(self.incidents),
            self.notifications_sent,
        )

    @property
    def per_event_ms(self) -> float:
        return 1000 * self.wall_s / max(self.events, 1)

    @property
    def detected(self) -> list[Match]:
        return [m for m in self.matches if m.detected]

    @property
    def missed(self) -> list[Match]:
        return [m for m in self.matches if not m.detected]

    @property
    def passed(self) -> bool:
        return (
            not self.missed
            and not self.false_positives
            and self.incident_ok is not False
            and self.status_ok is not False
            and self.notified_ok
            and self.idempotent_ok
            and (
                self.scenario.out_of_range is None
                or (self.out_of_range_readings or 0) >= self.scenario.out_of_range["min_readings"]
            )
        )


def run_scenario(
    scenario: Scenario,
    seed: int = 42,
    *,
    db_path: Path | str = ":memory:",
    hash_iterations: int | None = None,
) -> RunResult:
    settings = SimulationSettings.from_config(
        seed=seed,
        start=scenario.start,
        activity=scenario.activity,
        anomalies_per_day=0.0,  # controlled: only the scripted actions are abnormal
        faults_per_day=0.0,
        password_hash_iterations=hash_iterations,
    )
    store = EventStore(db_path)
    collector = CollectingChannel()
    notifier = Notifier(store, [collector], NotifySettings.from_config())
    detector = Detector.from_config(store, on_alert=notifier.on_alert)
    sink = SQLiteSink(store)

    def detect_stored(result) -> None:
        kind = "telemetry" if result.table == "telemetry" else "security"
        detector.process_row(kind, store.record_row(kind, result.ref))

    sink.on_stored = detect_stored
    sim = Simulation(settings, [sink])
    store.register_devices(sim.fleet)
    driver = Driver(sim, scenario)

    end = scenario.start + scenario.duration
    started = time.perf_counter()
    while sim.now < end:
        driver.run_due(sim.now)
        sim.step()
    sink.close()
    detector.finish(end)
    Correlator.from_config(store).run()
    notifier.check_escalations(None, end)
    wall_s = time.perf_counter() - started

    try:
        return _evaluate(store, scenario, seed, sim, driver, notifier, wall_s)
    finally:
        store.close()


def _evaluate(store, scenario, seed, sim, driver, notifier, wall_s) -> RunResult:
    alerts = store.alerts()
    matches = []
    for e in scenario.expected:
        candidates = [a for a in alerts if a["rule_id"] == e.rule]
        good = [a for a in candidates if e.matches_severity(a["severity"])]
        best = (good or candidates or [None])[0]
        ttd = None
        if best is not None and e.from_step:
            ttd = (_ts(best["first_seen"]) - driver.step_times[e.from_step]).total_seconds()
        matches.append(Match(e, best, ttd))
    expected_rules = {e.rule for e in scenario.expected} | scenario.allow
    false_positives = [
        a for a in alerts if a["severity"] != "INFO" and a["rule_id"] not in expected_rules
    ]

    incidents = sorted({i["pattern_id"] for i in store.incidents()})
    incident_ok = None if scenario.incident is None else scenario.incident in incidents

    rows = store.conn.execute(
        """SELECT COALESCE(s.status, 'normal') FROM security_events e
           LEFT JOIN v_event_status s ON s.event_ref = e.id WHERE e.scenario = ?""",
        (scenario.id,),
    ).fetchall()
    statuses: dict[str, int] = {}
    for (status,) in rows:
        statuses[status] = statuses.get(status, 0) + 1
    status_ok = None
    if scenario.events_status:
        status_ok = bool(rows) and set(statuses) == {scenario.events_status}

    out_of_range = None
    if scenario.out_of_range:
        out_of_range = store.conn.execute(
            """SELECT COUNT(*) FROM telemetry WHERE device_id = ?
               AND (temperature_c > expected_max_c OR temperature_c < expected_min_c)""",
            (scenario.out_of_range["device"],),
        ).fetchone()[0]

    # notification delivery: every expected HIGH+ alert got a decision, none failed
    log = store.notifications(channel="collect")
    decided = {n["alert_id"] for n in log}
    high = [
        m.alert["alert_id"]
        for m in matches
        if m.alert and SEVERITY_LEVELS.index(m.alert["severity"]) >= SEVERITY_LEVELS.index("HIGH")
    ]
    for m in matches:
        if m.alert and m.expected.from_step:
            sent = [
                n["ts"]
                for n in log
                if n["alert_id"] == m.alert["alert_id"] and n["status"] == "sent"
            ]
            if sent:
                start = driver.step_times[m.expected.from_step]
                m.notify_s = (_ts(min(sent)) - start).total_seconds()
    problems = []
    notified_ok = all(a in decided for a in high) and not any(n["status"] == "failed" for n in log)
    if not notified_ok:
        problems.append("an expected HIGH+ alert has no notification decision")

    # reliability: detection and notification are idempotent over the stored events
    before = (len(alerts), len(log))
    again = Detector.from_config(store, on_alert=notifier.on_alert).run()
    notifier.process_stored()
    after = (len(store.alerts()), len(store.notifications(channel="collect")))
    idempotent_ok = not again.new_alerts and before == after
    if not idempotent_ok:
        problems.append(f"re-run changed alerts/notifications: {before} -> {after}")

    return RunResult(
        scenario=scenario,
        seed=seed,
        events=sim.events_emitted,
        wall_s=wall_s,
        alerts=alerts,
        matches=matches,
        false_positives=false_positives,
        incidents=incidents,
        incident_ok=incident_ok,
        status_ok=status_ok,
        statuses=statuses,
        notified_ok=notified_ok,
        notifications_sent=sum(n["status"] == "sent" for n in log),
        notifications_suppressed=sum(n["status"] == "suppressed" for n in log),
        idempotent_ok=idempotent_ok,
        rejected=store.stats()["rejected"],
        out_of_range_readings=out_of_range,
        problems=problems,
    )
