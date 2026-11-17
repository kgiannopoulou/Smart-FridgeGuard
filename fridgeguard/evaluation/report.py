"""Aggregate system-test runs into metrics and ``test_results.md`` (Phase 4, Step 14)."""

from __future__ import annotations

import platform
import statistics
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fridgeguard.config import PROJECT_ROOT
from fridgeguard.evaluation.runner import RunResult, run_scenario
from fridgeguard.evaluation.scenario import Scenario

# Why each rule needs the time it needs (configured in config/detection.yaml).
TTD_EXPLAINED = {
    "DET-001": "raised on the change event (HIGH); CRITICAL once the fridge leaves its range (the DET-003 time in TC-02)",
    "DET-002": "at the 5th failed attempt; the clock starts at the 1st (attempts 20 s apart)",
    "DET-003": "temperature must first leave the range (physics), then stay out 15 min",
    "DET-004": "on the login event itself",
    "DET-005": "3 missed 60-s readings; the clock starts when the device goes silent",
    "DET-007": "on the change event itself (audit record)",
}


@dataclass
class Evaluation:
    seeds: list[int]
    runs: list[RunResult]
    determinism: dict[str, bool] = field(default_factory=dict)  # scenario -> repeat equal
    started: datetime = field(default_factory=lambda: datetime.now(UTC))
    wall_s: float = 0.0

    def for_case(self, scenario_id: str) -> list[RunResult]:
        return [r for r in self.runs if r.scenario.id == scenario_id]

    @property
    def scenarios(self) -> list[Scenario]:
        seen: dict[str, Scenario] = {}
        for r in self.runs:
            seen.setdefault(r.scenario.id, r.scenario)
        return list(seen.values())

    # ---- metrics ------------------------------------------------------------------------
    @property
    def expected(self) -> int:
        return sum(len(r.matches) for r in self.runs)

    @property
    def true_positives(self) -> int:
        return sum(len(r.detected) for r in self.runs)

    @property
    def missed(self) -> int:
        return sum(len(r.missed) for r in self.runs)

    @property
    def false_positives(self) -> int:
        return sum(len(r.false_positives) for r in self.runs)

    @property
    def detection_rate(self) -> float:
        return self.true_positives / self.expected if self.expected else 1.0

    @property
    def precision(self) -> float:
        raised = self.true_positives + self.false_positives
        return self.true_positives / raised if raised else 1.0

    @property
    def case_accuracy(self) -> float:
        return sum(r.passed for r in self.runs) / len(self.runs)

    def ttd(self, rule: str) -> list[float]:
        return [
            m.ttd_s
            for r in self.runs
            for m in r.detected
            if m.expected.rule == rule and m.ttd_s is not None
        ]

    def notify_times(self) -> list[float]:
        return [m.notify_s for r in self.runs for m in r.detected if m.notify_s is not None]


def evaluate(
    scenarios: list[Scenario],
    seeds: list[int],
    *,
    hash_iterations: int | None = None,
    progress: Callable[[RunResult], None] | None = None,
) -> Evaluation:
    import time

    started = time.perf_counter()
    result = Evaluation(seeds, [])
    for scenario in scenarios:
        for seed in seeds:
            run = run_scenario(scenario, seed, hash_iterations=hash_iterations)
            result.runs.append(run)
            if progress:
                progress(run)
        # determinism: the first seed again must give exactly the same result
        repeat = run_scenario(scenario, seeds[0], hash_iterations=hash_iterations)
        result.determinism[scenario.id] = (
            repeat.fingerprint == result.for_case(scenario.id)[0].fingerprint
        )
    result.wall_s = time.perf_counter() - started
    return result


# ---- Markdown -------------------------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{100 * x:.1f} %"


def _dur(seconds: float) -> str:
    if seconds < 120:
        return f"{seconds:.0f} s"
    if seconds < 7200:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:g} h"


def _span(values: list[float]) -> str:
    if not values:
        return "-"
    lo, med, hi = min(values), statistics.median(values), max(values)
    if lo == hi:
        return _dur(lo)
    return f"{_dur(med)} (min {_dur(lo)}, max {_dur(hi)})"


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return out.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def to_markdown(ev: Evaluation) -> str:
    n = len(ev.seeds)
    runs = len(ev.runs)
    passed = sum(r.passed for r in ev.runs)
    events = sum(r.events for r in ev.runs)
    proc_s = sum(r.wall_s for r in ev.runs)
    normal = ev.for_case("TC-01")
    normal_days = sum(r.scenario.duration.total_seconds() for r in normal) / 86400
    normal_fp = sum(len(r.false_positives) for r in normal)
    seeds_text = f"{ev.seeds[0]}-{ev.seeds[-1]}" if len(ev.seeds) > 1 else str(ev.seeds[0])
    L: list[str] = [
        "# Smart-FridgeGuard — System Test Results",
        "",
        "**Phase:** 4 – Testing, professional documentation and presentation  ",
        "**Step:** 14 – Test the complete system  ",
        f"**Generated:** {ev.started:%Y-%m-%d %H:%M} UTC by `python -m fridgeguard evaluate "
        f"--seeds {n}` (commit `{_git_commit()}`, Python {platform.python_version()}, "
        f"{platform.system()})  ",
        "**Related:** [test plan scenarios](scenarios/) · [automated tests](tests/test_system.py)"
        " · [requirements.md](requirements.md) · [threat-model.md](threat-model.md)",
        "",
        "---",
        "",
        "## 1. Summary",
        "",
        f"Every test case ran **{n} times with different random seeds** ({seeds_text}): the "
        "seed changes sensor noise, door openings, user passwords, session IDs and (in TC-01) "
        "the whole day of normal activity. "
        f"**{passed} of {runs} runs passed** "
        "(all expected alerts with the expected severity, no false positive, expected "
        "incident and event status, notifications delivered, re-runs idempotent).",
        "",
        "| Metric | Result |",
        "|--------|--------|",
        f"| Detection accuracy (runs whose outcome matched the expectation exactly) | **{_pct(ev.case_accuracy)}** ({passed} / {runs}) |",
        f"| Detection rate (expected alerts raised with the expected severity) | **{_pct(ev.detection_rate)}** ({ev.true_positives} / {ev.expected}) |",
        f"| Missed detections | **{ev.missed}** |",
        f"| False positives (alerts above INFO that no test expected) | **{ev.false_positives}** — {normal_fp} in {normal_days:.0f} simulated days of normal operation |",
        f"| Precision | **{_pct(ev.precision)}** |",
        f"| Time to detect | see section 4 (from immediate to {_dur(max((t for r in ev.runs for m in r.detected if (t := m.ttd_s) is not None), default=0))}) |",
        f"| Alert generation reliability | {sum(r.idempotent_ok for r in ev.runs)} / {runs} runs idempotent on re-run, {sum(ev.determinism.values())} / {len(ev.determinism)} cases deterministic per seed, {sum(r.notified_ok for r in ev.runs)} / {runs} runs with every HIGH+ alert notified |",
        f"| Pipeline processing | {events:,} events in {proc_s:.1f} s: {1000 * proc_s / max(events, 1):.2f} ms per event (simulate + validate + store + detect + notify) |",
        "",
        "## 2. Test plan",
        "",
        "Each case is a YAML file in [`scenarios/`](scenarios/). The real simulator runs "
        "(thermal model, door openings, sensor noise, users with PBKDF2 passwords and RBAC); "
        "the scripted actions go through the same interfaces as normal activity "
        "(`AuthService.login / change_config / logout`, the fridges' fault controls). Every "
        "event passes through the production pipeline: `EventStore` (validation, SHA-256) → "
        "live `Detector` (rules + prioritizer) → `Notifier`, then `Correlator`. Only the "
        "scripted actions are abnormal: background anomalies and random faults are off.",
        "",
        "| ID | Test | Expected result | What the system must produce | Passed |",
        "|----|------|-----------------|------------------------------|--------|",
    ]
    for sc in ev.scenarios:
        rr = ev.for_case(sc.id)
        L.append(
            f"| {sc.id} | {sc.name} | {sc.expected_result} | {sc.expectation_text} | "
            f"{sum(r.passed for r in rr)} / {len(rr)} |"
        )
    L += [
        "",
        "Anything else above INFO counts as a **false positive**; an expected alert that is "
        "missing or has another severity counts as a **missed detection**.",
        "",
        "## 3. Results per test case",
        "",
    ]
    for sc in ev.scenarios:
        rr = ev.for_case(sc.id)
        L += [f"### {sc.id} {sc.name}", "", sc.description, ""]
        if sc.steps:
            steps = ", ".join(
                f"`{s.id}` +{_dur(s.at.total_seconds())} {s.action}" for s in sc.steps
            )
            L += [f"Script ({_dur(sc.duration.total_seconds())} simulated): {steps}.", ""]
        else:
            L += [f"Script: {_dur(sc.duration.total_seconds())} of normal operation.", ""]
        L += [
            "| Expected | Raised as | Detected | Time to detect | Time to notify |",
            "|---|---|---|---|---|",
        ]
        for i, e in enumerate(sc.expected):
            ms = [r.matches[i] for r in rr]
            severities = sorted({m.alert["severity"] for m in ms if m.alert})
            L.append(
                f"| {e.rule} {e.wanted} | {', '.join(severities) or 'not raised'} | "
                f"{sum(m.detected for m in ms)} / {len(ms)} | "
                f"{_span([m.ttd_s for m in ms if m.detected and m.ttd_s is not None])} | "
                f"{_span([m.notify_s for m in ms if m.notify_s is not None])} |"
            )
        if not sc.expected:
            L.append("| no alert above INFO | - | - | - | - |")
        fps = [a for r in rr for a in r.false_positives]
        info = sum(a["severity"] == "INFO" for r in rr for a in r.alerts)
        extra = [f"false positives: **{len(fps)}**"]
        if fps:
            extra.append("(" + "; ".join(f"{a['rule_id']} {a['title']}" for a in fps[:5]) + ")")
        if info:
            extra.append(f"INFO maintenance records: {info} (authorized activity, not alerts)")
        if sc.incident:
            ok = sum(bool(r.incident_ok) for r in rr)
            extra.append(f"incident {sc.incident}: {ok} / {len(rr)}")
        else:
            seen = sorted({p for r in rr for p in r.incidents})
            if seen:
                extra.append(f"incidents formed: {', '.join(seen)}")
        if sc.out_of_range:
            counts = [r.out_of_range_readings or 0 for r in rr]
            extra.append(
                f"out-of-range readings on {sc.out_of_range['device']} (the near-miss really "
                f"happened, and stayed under the alert threshold): {min(counts)}-{max(counts)} "
                f"per run, required >= {sc.out_of_range['min_readings']}"
            )
        if sc.events_status:
            ok = sum(bool(r.status_ok) for r in rr)
            extra.append(f"scripted events all `{sc.events_status}`: {ok} / {len(rr)}")
        sent = sum(r.notifications_sent for r in rr)
        held = sum(r.notifications_suppressed for r in rr)
        extra.append(f"notifications (HIGH+): {sent} sent, {held} held back")
        extra.append(
            "deterministic per seed: " + ("yes" if ev.determinism.get(sc.id) else "**no**")
        )
        L += ["", "- " + "\n- ".join(extra), ""]
        problems = [f"seed {r.seed}: {p}" for r in rr for p in r.problems]
        if problems:
            L += ["Problems:", "", *[f"- {p}" for p in problems[:10]], ""]

    L += [
        "## 4. Time to detect",
        "",
        "Measured in simulated time from the scripted action (the step named in the "
        "scenario's `from`) to the alert's `first_seen`, over all runs. The delay is set by "
        "the rules' thresholds, not by processing: the pipeline needs "
        f"{1000 * proc_s / max(events, 1):.2f} ms per event.",
        "",
        "| Rule | Time to detect (median, min, max) | Why |",
        "|------|-----------------------------------|-----|",
    ]
    for rule in sorted({m.expected.rule for r in ev.runs for m in r.matches}):
        L.append(f"| {rule} | {_span(ev.ttd(rule))} | {TTD_EXPLAINED.get(rule, '')} |")
    nt = ev.notify_times()
    L += [
        "",
        f"Time from the action to the first notification of a HIGH+ alert: {_span(nt)}. A "
        "temperature alert can be created as LOW (small deviation) and is notified when it "
        "is re-graded to HIGH while the fridge keeps warming.",
        "",
        "## 5. Alert generation reliability",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| Same seed run twice gives identical alerts, severities, times, incidents and notification count | {sum(ev.determinism.values())} / {len(ev.determinism)} cases |",
        f"| Re-running detection over the stored events creates no new alert and no new notification | {sum(r.idempotent_ok for r in ev.runs)} / {runs} runs |",
        f"| Every expected HIGH+ alert has a notification decision, none failed | {sum(r.notified_ok for r in ev.runs)} / {runs} runs |",
        f"| Expected alerts raised in every one of the {n} seeds (no flaky detection) | {sum(all(m.detected for r in ev.for_case(sc.id) for m in [r.matches[i]]) for sc in ev.scenarios for i in range(len(sc.expected)))} / {sum(len(sc.expected) for sc in ev.scenarios)} expected alerts |",
        f"| Events rejected by validation (all scripted and simulated events must be valid) | {sum(r.rejected for r in ev.runs)} |",
        "",
        "## 6. Defects found by these tests and fixed",
        "",
        "| # | Found in | Defect | Fix |",
        "|---|----------|--------|-----|",
        "| 1 | TC-04 (1 of 20 seeds) and TC-08 (3 of 20 seeds) before the fix | A temperature alert created as LOW (deviation still small) was below the HIGH notification threshold. The prioritizer re-graded it to HIGH only at the end of detection, and the notifier only re-checked alerts it had already notified, so the HIGH alert was never notified live. | The detector re-grades open temperature alerts every 5 min of activity time (`reprioritize_every_s` in `config/detection.yaml`) and reports a change through `on_alert`; the notifier also notifies an alert that crosses a channel's threshold for the first time. Regression tests: [`tests/test_system.py`](tests/test_system.py). |",
        '| 2 | TC-09, TC-10 (every run) | `notify run` and the `detect` command crashed on a database without any alert: the latest alert time defaulted to `"0"`, which is not a timestamp. | Escalation check skipped when there are no alerts. Regression test: `test_notify_run_and_detect_work_on_a_database_without_alerts`. |',
        "",
        "## 7. Limitations",
        "",
        "- **Verification, not field accuracy.** The cases test the behaviour the rules were "
        "designed for, plus two boundary cases just under the thresholds (TC-09, TC-10). 100 % "
        "here means the system does what its requirements say; it is not a measured accuracy "
        "against real attacks, which would need real data and attacks the rules were not "
        "written for.",
        "- **Simulated data.** All events come from the simulator; real controllers may "
        "produce noisier data (clock drift, duplicate or late events).",
        "- **Times are simulated time.** Time to detect shows the rule thresholds' delay; "
        "it does not include network or broker latency of a real deployment.",
        "- **Stolen credentials.** In TC-08 the change is made with a valid account, so "
        "DET-001 (unauthorized change) does not fire; the attack is rated CRITICAL at the "
        "incident level (COR-001), and the individual alerts stay HIGH / MEDIUM.",
        "- **TC-02 needs a compromised controller.** With working RBAC the store manager's "
        "change is refused (that case is DET-001 MEDIUM, covered by unit tests). TC-02 "
        "models threat T-4: the controller applies the change despite `authorized: false`.",
        "- **Channels.** Notifications are checked with an in-memory channel; SMTP and "
        "Telegram are covered by unit tests with a local socket server and a mocked API.",
        "",
        "## 8. Reproduce",
        "",
        "```powershell",
        f"python -m fridgeguard evaluate --seeds {n}          # all cases, writes test_results.md",
        "python -m fridgeguard evaluate --case TC-03 --seeds 5 --out -   # one case, print only",
        "pytest tests/test_system.py                          # the same cases as automated tests",
        "```",
        "",
        f"Total evaluation time: {ev.wall_s:.0f} s ({runs} runs + {len(ev.determinism)} "
        "determinism repeats).",
        "",
    ]
    return "\n".join(L)


def default_output() -> str:
    return str(PROJECT_ROOT / "test_results.md")
