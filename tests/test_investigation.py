"""Step 12: L1 alert investigation workflow and incident reports (hand-made events)."""

import random
import sqlite3
from datetime import UTC, datetime

import pytest

from fridgeguard.__main__ import main
from fridgeguard.detection import Detector
from fridgeguard.investigation import Settings, build_case, record, render, start
from fridgeguard.investigation.report import _latin1, build_report, to_markdown
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage import EventStore
from tests.test_dashboard import build_story_db
from tests.test_detection import MON_0630, Feed

TEMPLATE_SECTIONS = [
    "1. Initial alert",
    "2. Investigation performed",
    "3. Evidence collected",
    "4. Event timeline",
    "5. Findings",
    "6. Potential impact",
    "7. Recommended response",
    "8. Escalation decision",
    "9. Final status",
]
FIXED_NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def settings():
    return Settings.from_config()


@pytest.fixture
def story(tmp_path):
    """Brute force -> takeover -> setpoint 4 -> 12 °C -> excursion (see test_dashboard)."""
    s = EventStore(build_story_db(tmp_path / "story.db"))
    yield s
    s.close()


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "inv.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


def alert_of(store, rule_id, device=None):
    found = [a for a in store.alerts(rule_id=rule_id) if device is None or a["device_id"] == device]
    assert found, f"no {rule_id} alert"
    return found[0]["alert_id"]


def complete(store, inv_id, final="true_positive"):
    record(store, inv_id, "authorization", "anna", "Owner did not log in", "unauthorized")
    record(store, inv_id, "impact", "anna", "Setpoint raised to 12 °C", "critical")
    record(store, inv_id, "escalation", "anna", "Handed to L2 at 09:10", "l2_soc")
    return record(store, inv_id, "documentation", "anna", "Account takeover", final)


# ---- evidence and suggestions ---------------------------------------------------------------
def test_takeover_case_gathers_device_user_and_ip(story, settings):
    case = build_case(story, alert_of(story, "DET-003"), settings)
    assert case.investigation is None and case.final_status == "open"
    assert case.device["device_id"] == "FRIDGE-001"
    assert case.device["excursions"] and case.device["max_deviation_c"] == pytest.approx(4.0)
    # the temperature alert has no user evidence: the change before it is judged instead
    assert [u["user"] for u in case.users] == ["maintenance_tech"]
    ip = case.source_ips[0]
    assert ip["source_ip"] == "203.0.113.50" and not ip["on_allow_list"]
    assert ip["failed_logins"] == 5 and "root" in ip["usernames"]
    assert case.incident and case.incident["pattern_id"] == "COR-001"
    assert any("SETPOINT_CHANGE" in e["detail"] for e in case.related_events)
    assert case.timeline == sorted(case.timeline, key=lambda t: t["ts"])


def test_takeover_suggestions(story, settings):
    case = build_case(story, alert_of(story, "DET-003"), settings)
    assert case.authorization.decision == "unauthorized"
    assert any("not on the device allow-list" in r for r in case.authorization.reasons)
    assert case.impact.decision == "critical"
    assert case.escalation.decision == "l2_soc"
    assert set(case.escalation.teams) == {"l2_soc", "store_management", "it_network"}


def test_heartbeat_alert_is_not_an_access_question(story, settings):
    case = build_case(story, alert_of(story, "DET-005", "FRIDGE-002"), settings)
    assert case.authorization.decision == "not_applicable"
    assert case.impact.decision == "medium"
    assert case.escalation.decision == "maintenance_engineering"
    assert case.device["longest_gap_min"] >= 3


def test_planned_maintenance_is_authorized_with_no_impact(store, settings):
    Feed(store).change(MON_0630)  # technician, own IP, inside the window
    Detector.from_config(store).run()
    case = build_case(store, alert_of(store, "DET-007"), settings)
    assert (case.authorization.decision, case.impact.decision, case.escalation.decision) == (
        "authorized",
        "none",
        "not_required",
    )


def test_refused_change_is_unauthorized_with_low_impact(store, settings):
    Feed(store).change(
        MON_0630, user="store_manager", role="manager", authorized=False, result="denied"
    )
    Detector.from_config(store).run()
    case = build_case(store, alert_of(store, "DET-001"), settings)
    assert case.authorization.decision == "unauthorized"
    assert case.impact.decision == "low"
    assert case.escalation.decision == "not_required"


# ---- workflow -----------------------------------------------------------------------------
def test_start_assigns_the_alert_and_is_idempotent(story):
    alert_id = alert_of(story, "DET-003")
    inv_id, created = start(story, alert_id, "anna")
    assert created and inv_id == "INV-000001"
    alert = story.alert(alert_id)
    assert alert["status"] == "under_investigation" and alert["assigned_to"] == "anna"
    assert start(story, alert_id, "ben") == (inv_id, False)


def test_documentation_needs_the_decisions_first(story):
    inv_id, _ = start(story, alert_of(story, "DET-003"), "anna")
    with pytest.raises(ValueError, match="authorization, impact, escalation"):
        record(story, inv_id, "documentation", "anna", "done", "true_positive")


def test_step_validation(story):
    inv_id, _ = start(story, alert_of(story, "DET-003"), "anna")
    with pytest.raises(ValueError, match="note is required"):
        record(story, inv_id, "review_alert", "anna", "  ")
    with pytest.raises(ValueError, match="must be one of"):
        record(story, inv_id, "impact", "anna", "x", "catastrophic")
    with pytest.raises(ValueError, match="notes only"):
        record(story, inv_id, "review_alert", "anna", "x", "authorized")
    with pytest.raises(KeyError):
        record(story, "INV-999999", "review_alert", "anna", "x")


@pytest.mark.parametrize(
    ("final", "alert_status", "moved"),
    [
        ("true_positive", "resolved", ["confirmed", "resolved"]),
        ("escalated", "confirmed", ["confirmed"]),
        ("false_positive", "false_positive", ["false_positive"]),
        ("benign", "resolved", ["resolved"]),
        ("undetermined", "under_investigation", []),
    ],
)
def test_final_status_moves_the_alert(story, final, alert_status, moved):
    alert_id = alert_of(story, "DET-003")
    inv_id, _ = start(story, alert_id, "anna")
    assert complete(story, inv_id, final) == moved
    assert story.alert(alert_id)["status"] == alert_status
    assert story.investigation(inv_id)["final_status"] == final


def test_answers_are_append_only_and_latest_wins(story, settings):
    alert_id = alert_of(story, "DET-003")
    inv_id, _ = start(story, alert_id, "anna")
    record(story, inv_id, "impact", "anna", "first look", "medium")
    record(story, inv_id, "impact", "anna", "stock was out of range", "high")
    case = build_case(story, alert_id, settings)
    assert case.decision("impact") == ("high", True)
    assert len(case.entries) == 2 and case.steps_done == ["impact"]
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        story.conn.execute("UPDATE investigation_entries SET decision = 'none'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        story.conn.execute("DELETE FROM investigation_entries")


def test_move_alert_to_finds_the_workflow_path(story):
    alert_id = alert_of(story, "DET-002")
    assert story.move_alert_to(alert_id, "confirmed", "anna", "checked") == [
        "under_investigation",
        "confirmed",
    ]
    assert story.move_alert_to(alert_id, "confirmed", "anna", "again") == []


# ---- reports ------------------------------------------------------------------------------
def test_markdown_report_follows_the_template(story, settings):
    alert_id = alert_of(story, "DET-003")
    inv_id, _ = start(story, alert_id, "anna")
    complete(story, inv_id, "escalated")
    md = render(build_case(story, alert_id, settings), "md", FIXED_NOW).decode("utf-8")
    assert md.startswith("# INCIDENT REPORT")
    for field in ("Incident ID:", "Detection time:", "Affected device:", "Alert severity:"):
        assert f"**{field}**" in md
    positions = [md.index(f"## {s}") for s in TEMPLATE_SECTIONS]
    assert positions == sorted(positions)
    assert "INV-000001 (correlated incident INC-" in md
    assert "| Final status | escalated |" in md
    assert "Owner did not log in" in md and "setpoint_c 4.0 -> 12.0" in md
    assert "block the source IP" in md  # COR-001 response


def test_unrecorded_decisions_are_marked_as_suggestions(story, settings):
    case = build_case(story, alert_of(story, "DET-003"), settings)
    md = to_markdown(build_report(case, FIXED_NOW))
    assert "unauthorized (suggested, not confirmed)" in md
    assert "The investigation has not been opened yet." in md


def test_pdf_report(story, settings):
    alert_id = alert_of(story, "DET-003")
    inv_id, _ = start(story, alert_id, "anna")
    complete(story, inv_id)
    pdf = render(build_case(story, alert_id, settings), "pdf", FIXED_NOW)
    assert pdf.startswith(b"%PDF-") and len(pdf) > 3000


def test_pdf_text_is_latin1_safe():
    assert _latin1("4.0 → 12.0 °C … ✅") == "4.0 -> 12.0 °C ... ?"


# ---- storage upgrade and CLI ------------------------------------------------------------------
def test_version4_database_is_upgraded(tmp_path):
    db = build_story_db(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    conn.executescript(
        """DROP VIEW v_investigations; DROP TABLE investigation_entries;
           DROP TABLE investigations; UPDATE schema_info SET value = '4' WHERE key = 'version';"""
    )
    conn.commit()
    conn.close()
    s = EventStore(db, read_only=True)
    try:
        assert s.investigations() == []
    finally:
        s.close()


def test_cli_start_record_report(tmp_path, capsys):
    db = build_story_db(tmp_path / "cli.db")
    s = EventStore(db, read_only=True)
    alert_id = alert_of(s, "DET-003")
    s.close()
    base = ["investigate", "--db", str(db)]
    assert main([*base, "start", alert_id, "--analyst", "anna"]) == 0
    out = capsys.readouterr().out
    assert "INV-000001  opened" in out and "suggested: unauthorized" in out
    assert (
        main(
            [
                *base,
                "record",
                "INV-000001",
                "documentation",
                "--decision",
                "benign",
                "--note",
                "x",
                "--analyst",
                "anna",
            ]
        )
        == 2
    )
    assert "record these decisions" in capsys.readouterr().err
    for step, decision in (
        ("authorization", "unauthorized"),
        ("impact", "high"),
        ("escalation", "l2_soc"),
        ("documentation", "escalated"),
    ):
        assert (
            main(
                [
                    *base,
                    "record",
                    "INV-000001",
                    step,
                    "--decision",
                    decision,
                    "--note",
                    "checked",
                    "--analyst",
                    "anna",
                ]
            )
            == 0
        )
    assert "alert moved to: confirmed" in capsys.readouterr().out
    assert main([*base, "list"]) == 0
    assert "escalated" in capsys.readouterr().out
    for fmt in ("md", "pdf"):
        assert (
            main(
                [*base, "report", "INV-000001", "--format", fmt, "--out", str(tmp_path / "reports")]
            )
            == 0
        )
        assert (tmp_path / "reports" / f"INV-000001.{fmt}").stat().st_size > 1000
    assert main([*base, "show", "INV-424242"]) == 2


def test_unrelated_excursion_does_not_raise_brute_force_impact(store, settings):
    from datetime import timedelta

    from tests.test_correlation import Story
    from tests.test_detection import TUE_0300

    s = Story(store)
    s.readings(TUE_0300 - timedelta(minutes=10), [4.0] * 10)
    s.guesses(TUE_0300)  # no login succeeds
    s.warming(TUE_0300 + timedelta(minutes=10))  # compressor fault, no change made
    store.commit()
    Detector.from_config(store).run()
    case = build_case(store, alert_of(store, "DET-002"), settings)
    assert case.authorization.decision == "unauthorized"
    assert case.impact.decision == "low"
    assert any(r.startswith("context:") for r in case.impact.reasons)
    assert case.escalation.decision == "it_network"
    fault = build_case(store, alert_of(store, "DET-003"), settings)
    assert fault.authorization.decision == "not_applicable"
    assert fault.escalation.teams[0] == "maintenance_engineering"


def test_report_reverifies_evidence_hashes(story, settings):
    alert_id = alert_of(story, "DET-003")
    case = build_case(story, alert_id, settings)
    integ = case.integrity
    assert integ["records"] == integ["verified"] > 0 and not integ["problems"]
    assert len(integ["sha256"]) == 64
    md = render(case, "md", FIXED_NOW).decode("utf-8")
    assert integ["sha256"] in md
    # same evidence, same hash: a printed report can be checked against the database later
    assert build_case(story, alert_id, settings).integrity["sha256"] == integ["sha256"]
    # a tampered record (bypassing the append-only trigger) is reported
    target = case.evidence[0]["record_id"]
    story.conn.execute("DROP TRIGGER telemetry_no_update")
    story.conn.execute(
        "UPDATE telemetry SET raw_json = replace(raw_json, '\"temperature_c\": ', "
        "'\"temperature_c\": 1') WHERE reading_id = ?",
        (target,),
    )
    tampered = build_case(story, alert_id, settings).integrity
    assert tampered["problems"] == [f"{target}: hash mismatch"]
