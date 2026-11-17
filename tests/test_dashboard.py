"""Step 11: SOC dashboard data layer and pages (hand-made events, Streamlit AppTest)."""

import random
from datetime import timedelta
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from fridgeguard.dashboard import data
from fridgeguard.detection import Correlator, Detector
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage import EventStore
from tests.test_correlation import ATTACKER, Story
from tests.test_detection import MON_0630, TUE_0300

APP = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")
PAGES = ["overview", "temperature", "security", "alerts", "investigation", "incidents"]


def build_story_db(path: Path) -> Path:
    """Planned maintenance on Monday, then a takeover story on Tuesday night."""
    store = EventStore(path)
    store.register_devices(Fleet.from_config(random.Random(0)))
    s = Story(store)
    s.readings(MON_0630 - timedelta(minutes=5), [4.0] * 5)
    s.session_login(MON_0630, "S-M", ip="10.10.1.30", window=True)  # planned, 06:30 local
    s.readings(TUE_0300 - timedelta(minutes=10), [4.0] * 10)
    s.readings(TUE_0300 - timedelta(minutes=10), [-18.0] * 10, device="FRIDGE-002")
    s.guesses(TUE_0300)
    s.session_login(TUE_0300 + timedelta(minutes=3), "S-77")
    s.session_change(TUE_0300 + timedelta(minutes=5), "S-77")
    s.logout(TUE_0300 + timedelta(minutes=7), "S-77")
    s.warming(TUE_0300 + timedelta(minutes=6))
    store.commit()
    Detector.from_config(store).run()
    Correlator.from_config(store).run()
    store.close()
    return path


@pytest.fixture(scope="module")
def story_db(tmp_path_factory):
    return build_story_db(tmp_path_factory.mktemp("dash") / "story.db")


@pytest.fixture
def store(story_db):
    s = EventStore(story_db, read_only=True)
    yield s
    s.close()


@pytest.fixture(scope="module")
def site():
    return data.Site.from_config()


# ---- data layer ---------------------------------------------------------------------------
def test_temperature_comparison_and_excursions(store):
    tel = data.telemetry(store)
    comparison = data.device_comparison(tel, data.devices(store)).set_index("device_id")
    assert comparison.loc["FRIDGE-001", "max_c"] == 12.0
    assert comparison.loc["FRIDGE-001", "excursions"] == 1
    assert comparison.loc["FRIDGE-002", "in_range_pct"] == 100.0
    exc = data.excursions(tel)
    assert list(exc["device_id"]) == ["FRIDGE-001"]
    assert exc.iloc[0]["max_deviation_c"] == pytest.approx(4.0)
    assert len(data.abnormal_readings(tel)) == exc.iloc[0]["readings"]


def test_security_views(store, site):
    sec = data.security_events(store, site)
    ips = data.suspicious_ips(sec)
    assert list(ips["source_ip"]) == [ATTACKER]
    row = ips.iloc[0]
    assert row["failed"] == 5 and row["successful"] == 1 and row["changes"] == 1
    assert not row["on_allow_list"]
    assert "maintenance_tech" in row["usernames_tried"]

    unusual = data.unusual_access(sec)
    # the Tuesday 03:00 login and change are unusual; Monday 06:30 maintenance is not
    assert set(unusual["session_id"]) == {"S-77"}
    assert all("privileged, outside maintenance window" in w for w in unusual["why"])

    per_hour = data.auth_per_hour(sec)
    assert per_hour.groupby("outcome")["count"].sum().to_dict() == {"Failed": 5, "Successful": 2}
    grid = data.access_heatmap(sec)
    assert grid.shape == (7, 24) and grid.loc["Tue", 3] == 2  # login + change at 03:0x


def test_alert_frame_has_associated_users(store):
    alerts = data.alerts(store).set_index("rule_id")
    assert alerts.loc["DET-002", "user"].startswith("tried: ")
    assert alerts.loc["DET-004", "user"] == "maintenance_tech"
    assert alerts.loc["DET-002", "incident_id"].startswith("INC-")


def test_incident_detail_and_report(store):
    incidents = data.incidents(store)
    assert list(incidents["pattern_id"]) == ["COR-001"]
    inc = data.incident_detail(store, incidents.iloc[0]["incident_id"])
    members = inc["members"]
    assert {"Alert", "Security event", "Telemetry"} <= set(members["type"])
    change = members[members["what"].str.contains("SETPOINT_CHANGE")].iloc[0]
    assert "4.0 -> 12.0" in change["what"] and change["source_ip"] == ATTACKER
    context = data.incident_context(store, inc)
    assert not context.empty and set(context["device_id"]) == {"FRIDGE-001"}

    report = data.incident_report(inc)
    assert report.startswith(f"# Incident report {inc['incident_id']}")
    for section in (
        "## Event timeline",
        "## Related alerts",
        "## Analyst findings",
        "## Recommended response",
    ):
        assert section in report
    assert "block the source IP" in report


# ---- pages --------------------------------------------------------------------------------
def run_page(page: str) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60).run()
    if page != "overview":
        at.switch_page(f"views/{page}.py").run()
    return at


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_with_data(story_db, monkeypatch, page):
    monkeypatch.setenv("FRIDGEGUARD_DB", str(story_db))
    at = run_page(page)
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value


@pytest.mark.parametrize("page", PAGES)
def test_every_page_explains_a_missing_database(tmp_path, monkeypatch, page):
    monkeypatch.setenv("FRIDGEGUARD_DB", str(tmp_path / "missing.db"))
    at = run_page(page)
    assert not at.exception
    assert "No event database" in at.warning[0].value


def test_review_is_saved_from_the_investigation_page(tmp_path, monkeypatch):
    db = build_story_db(tmp_path / "review.db")
    monkeypatch.setenv("FRIDGEGUARD_DB", str(db))
    at = run_page("incidents")
    at.sidebar.text_input(key="analyst").input("anna").run()
    form_area = [t for t in at.text_area if t.label == "Findings"][0]
    form_area.input("Owner confirmed they did not log in; source IP unknown.")
    verdict = [s for s in at.selectbox if s.label == "Verdict"][0]
    verdict.select("true_positive")
    [b for b in at.button if b.label == "Save review"][0].click().run()
    assert not at.exception

    s = EventStore(db, read_only=True)
    try:
        inc = s.incidents()[0]
        assert inc["verdict"] == "true_positive" and inc["reviewed_by"] == "anna"
    finally:
        s.close()


def test_investigation_is_started_and_recorded_from_the_page(tmp_path, monkeypatch):
    db = build_story_db(tmp_path / "investigate.db")
    monkeypatch.setenv("FRIDGEGUARD_DB", str(db))
    at = run_page("investigation")
    at.sidebar.text_input(key="analyst").input("anna").run()
    [b for b in at.button if b.label == "Start investigation"][0].click().run()
    assert not at.exception, [e.value for e in at.exception]
    notes = [t for t in at.text_area if t.label == "Notes"]
    notes[4].input("Owner confirmed by phone that they did not log in.")  # authorization
    [b for b in at.button if "Determine whether" in b.label][0].click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert [d.label for d in at.get("download_button")] == ["Markdown", "PDF"]

    s = EventStore(db, read_only=True)
    try:
        inv = s.investigations()[0]
        assert inv["opened_by"] == "anna" and inv["alert_status"] == "under_investigation"
        entry = s.investigation_entries(inv["investigation_id"])[0]
        assert (entry["step"], entry["analyst"]) == ("authorization", "anna")
        assert entry["decision"] in ("unauthorized", "not_applicable", "unknown", "authorized")
    finally:
        s.close()


def test_device_status_online_and_offline(store):
    from datetime import timedelta as td

    assert data.heartbeat_timeout() == td(minutes=3)  # DET-005: 3 x 60 s
    bounds = data.data_bounds(store)
    status = data.device_status(store, bounds[1], td(minutes=3)).set_index("device_id")
    # the story only has readings for FRIDGE-001/002 up to the warming; FRIDGE-003 never reports
    assert not status.loc["FRIDGE-003", "online"]
    assert status["last_seen"].notna().sum() == 2
    early = data.device_status(store, status["last_seen"].dropna().min(), td(minutes=3))
    assert early.set_index("device_id").loc["FRIDGE-002", "online"]
