"""Step 14: system tests of the complete pipeline (scenarios/TC-*.yaml).

Every test case of the test plan runs through the real simulator and the production
pipeline (store -> detection + prioritization -> notifications -> correlation) with
fixed seeds, so the results are repeatable. ``python -m fridgeguard evaluate`` runs the
same cases with more seeds and writes docs/test-results.md.
"""

import pytest

from fridgeguard.evaluation.report import evaluate, to_markdown
from fridgeguard.evaluation.runner import run_scenario
from fridgeguard.evaluation.scenario import Scenario, load_scenarios

SEEDS = [1, 2, 3]
FAST_HASH = 1000  # PBKDF2 iterations do not affect detection; keep the tests quick
SCENARIOS = {s.id: s for s in load_scenarios()}


@pytest.fixture(scope="module")
def evaluation():
    return evaluate(list(SCENARIOS.values()), SEEDS, hash_iterations=FAST_HASH)


def describe(run) -> str:
    return "; ".join(
        [
            f"missed {m.expected.rule} (raised as {m.alert and m.alert['severity']})"
            for m in run.missed
        ]
        + [f"false positive {a['rule_id']} {a['title']}" for a in run.false_positives]
        + (
            [f"incident {run.scenario.incident} not formed ({run.incidents})"]
            if run.incident_ok is False
            else []
        )
        + ([f"event statuses {run.statuses}"] if run.status_ok is False else [])
        + run.problems
    )


# ---- the test plan ------------------------------------------------------------------------
def test_the_test_plan_covers_every_required_case():
    names = {s.name for s in SCENARIOS.values()}
    for required in (
        "Normal operation",
        "Unauthorized setpoint change",
        "Five failed logins",
        "Temperature rises gradually",
        "Device stops sending readings",
        "Authorized technician changes settings",
        "Suspicious login followed by configuration change",
    ):
        assert required in names


@pytest.mark.parametrize("case", sorted(SCENARIOS))
def test_case_passes_for_every_seed(evaluation, case):
    for run in evaluation.for_case(case):
        assert run.passed, f"{case} seed {run.seed}: {describe(run)}"


@pytest.mark.parametrize(
    ("case", "rule", "severity"),
    [
        ("TC-02", "DET-001", "CRITICAL"),  # unauthorized setpoint change -> critical alert
        ("TC-03", "DET-002", "HIGH"),  # five failed logins -> brute-force alert
        ("TC-04", "DET-003", "HIGH"),  # temperature rises gradually -> temperature alert
        ("TC-05", "DET-005", "HIGH"),  # device stops sending -> offline alert
        ("TC-06", "DET-007", "INFO"),  # authorized technician -> activity recorded only
        ("TC-07", "DET-004", "MEDIUM"),  # suspicious login (+ COR-002 incident)
    ],
)
def test_expected_alert_and_severity(evaluation, case, rule, severity):
    for run in evaluation.for_case(case):
        raised = {(a["rule_id"], a["severity"]) for a in run.alerts}
        assert (rule, severity) in raised, f"{case} seed {run.seed}: {raised}"


def test_normal_operation_raises_no_security_alert(evaluation):
    for run in evaluation.for_case("TC-01"):
        assert [a for a in run.alerts if a["severity"] != "INFO"] == []
        assert all(a["rule_id"] == "DET-007" for a in run.alerts)  # maintenance records


def test_correlated_incidents(evaluation):
    assert all("COR-002" in r.incidents for r in evaluation.for_case("TC-07"))
    assert all("COR-001" in r.incidents for r in evaluation.for_case("TC-08"))


def test_authorized_activity_is_recorded_as_normal(evaluation):
    for run in evaluation.for_case("TC-06"):
        assert run.statuses == {"normal": 3}  # login, change, logout


def test_boundary_cases_happen_but_stay_below_the_thresholds(evaluation):
    for run in evaluation.for_case("TC-09"):
        assert [a["rule_id"] for a in run.alerts] == []  # four failures are not brute force
        assert sum(run.statuses.values()) == 4
    for run in evaluation.for_case("TC-10"):
        assert run.out_of_range_readings >= 5 and run.alerts == []


# ---- measured metrics -----------------------------------------------------------------------
def test_detection_accuracy_false_positives_and_missed(evaluation):
    assert evaluation.case_accuracy == 1.0
    assert evaluation.detection_rate == 1.0
    assert evaluation.missed == 0
    assert evaluation.false_positives == 0
    assert evaluation.precision == 1.0


def test_time_to_detect_matches_the_rule_thresholds(evaluation):
    assert set(evaluation.ttd("DET-001")) == {0.0}  # on the change event
    assert set(evaluation.ttd("DET-004")) == {0.0}  # on the login event
    assert set(evaluation.ttd("DET-002")) == {80.0}  # 5th attempt, 20 s apart
    assert set(evaluation.ttd("DET-005")) == {120.0}  # 3 missed 60-s readings
    ttd3 = evaluation.ttd("DET-003")
    assert ttd3 and all(15 * 60 <= t <= 60 * 60 for t in ttd3)  # >= the 15-min rule


def test_alert_generation_reliability(evaluation):
    assert all(evaluation.determinism.values())  # same seed, same result
    assert all(r.idempotent_ok for r in evaluation.runs)  # re-runs add nothing
    assert all(r.notified_ok for r in evaluation.runs)  # HIGH+ alerts notified
    assert sum(r.rejected for r in evaluation.runs) == 0


def test_results_report_has_every_section(evaluation):
    md = to_markdown(evaluation)
    for heading in (
        "## 1. Summary",
        "## 2. Test plan",
        "## 3. Results per test case",
        "## 4. Time to detect",
        "## 5. Alert generation reliability",
        "## 6. Defects found by these tests and fixed",
        "## 7. Limitations",
    ):
        assert heading in md
    assert f"**{len(evaluation.runs)} of {len(evaluation.runs)} runs passed**" in md
    for scenario in SCENARIOS.values():
        assert f"| {scenario.id} | {scenario.name} | {scenario.expected_result} |" in md


# ---- regressions for the defects these tests found -------------------------------------------
@pytest.mark.parametrize(("case", "seed"), [("TC-04", 12), ("TC-08", 10), ("TC-08", 15)])
def test_alert_regraded_to_high_is_notified_live(case, seed):
    """Defect 1: an alert created as LOW and re-graded to HIGH was never notified."""
    run = run_scenario(SCENARIOS[case], seed, hash_iterations=FAST_HASH)
    assert run.passed, describe(run)
    temperature = next(m for m in run.matches if m.expected.rule == "DET-003")
    assert temperature.notify_s is not None


# ---- scenario validation ----------------------------------------------------------------------
def test_bad_scenarios_are_rejected(tmp_path):
    bad = tmp_path / "TC-99.yaml"
    bad.write_text(
        "id: TC-99\nname: x\nstart: '2026-11-17T00:00:00Z'\nduration: 1h\n"
        "steps: [{id: a, at: 1m, action: teleport}]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown action"):
        Scenario.load(bad)
    bad.write_text(
        "id: TC-99\nname: x\nstart: '2026-11-17T00:00:00Z'\nduration: 1h\nsteps: []\n"
        "expect: {alerts: [{rule: DET-002, from: nowhere}]}\n",
        encoding="utf-8",
    )
    with pytest.raises(KeyError, match="unknown step"):
        Scenario.load(bad)
