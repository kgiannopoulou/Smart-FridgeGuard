"""Step 10: alert prioritization (INFO..CRITICAL) and alert management (triage workflow)."""

import random
import shutil
import sqlite3
from datetime import timedelta

import pytest
import yaml

from fridgeguard.__main__ import main
from fridgeguard.config import CONFIG_DIR
from fridgeguard.detection import Detector, Prioritizer, PrioritySettings
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage import EventStore
from tests.test_detection import MON_0630, TUE_0300, Feed, by_rule, detect, simulate


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "prio.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


@pytest.fixture
def feed(store):
    return Feed(store)


def one(alerts, rule_id):
    found = by_rule(alerts, rule_id)
    assert len(found) == 1, found
    return found[0]


def warm_up(feed, start, peak, device="FRIDGE-001", minutes=20):
    """Readings leaving the range and climbing to ``peak`` over ``minutes``."""
    low, high = {"FRIDGE-001": (2.0, 8.0), "FRIDGE-003": (2.0, 8.0)}[device]
    temps = [round(high + 0.2 + (peak - high - 0.2) * i / (minutes - 1), 2) for i in range(minutes)]
    feed.readings(start, temps, device)


# ---- severity classification ------------------------------------------------------------
def test_critical_unauthorized_change_followed_by_temperature_manipulation(store, feed):
    feed.change(TUE_0300, user="store_manager", role="manager", authorized=False, new=12.0)
    warm_up(feed, TUE_0300 + timedelta(minutes=20), peak=11.0)
    alerts = detect(store)[1]
    change, temp = one(alerts, "DET-001"), one(alerts, "DET-003")
    assert change["severity"] == temp["severity"] == "CRITICAL"
    assert change["base_severity"] == temp["base_severity"] == "HIGH"
    assert f"followed by temperature excursion {temp['alert_id']}" in change["severity_reason"]
    assert f"preceded by unauthorized change {change['alert_id']}" in temp["severity_reason"]


@pytest.mark.parametrize(
    "change_offset, device",
    [
        (timedelta(minutes=60), "FRIDGE-001"),  # change after the excursion started
        (timedelta(hours=-3), "FRIDGE-001"),  # change more than 2 h before
        (timedelta(minutes=-20), "FRIDGE-002"),  # change on another device
    ],
)
def test_no_critical_without_the_sequence(store, feed, change_offset, device):
    start = TUE_0300 + timedelta(hours=4)
    feed.change(
        start + change_offset,
        user="store_manager",
        role="manager",
        authorized=False,
        device=device,
    )
    warm_up(feed, start, peak=11.0)
    alerts = detect(store)[1]
    assert {a["severity"] for a in alerts} <= {"HIGH"}


def test_refused_change_is_medium(store, feed):
    feed.change(TUE_0300, user="store_manager", role="manager", authorized=False, result="denied")
    alert = one(detect(store)[1], "DET-001")
    assert alert["severity"] == "MEDIUM" and "refused" in alert["severity_reason"]


def test_refused_change_does_not_start_the_critical_sequence(store, feed):
    feed.change(TUE_0300, user="store_manager", role="manager", authorized=False, result="denied")
    warm_up(feed, TUE_0300 + timedelta(minutes=10), peak=11.0)
    alerts = detect(store)[1]
    assert one(alerts, "DET-001")["severity"] == "MEDIUM"
    assert one(alerts, "DET-003")["severity"] == "HIGH"


def test_repeated_failed_logins_are_high(store, feed):
    for i in range(5):
        feed.failure(TUE_0300 + timedelta(seconds=10 * i))
    assert one(detect(store)[1], "DET-002")["severity"] == "HIGH"


def test_serious_temperature_deviation_is_high_and_minor_is_low(store, feed):
    warm_up(feed, TUE_0300, peak=11.0)  # 3 °C beyond 8 °C
    warm_up(feed, TUE_0300, peak=8.6, device="FRIDGE-003")  # 0.6 °C beyond, critical device
    # FRIDGE-001 back in range, then a second, small excursion (0.4 °C beyond)
    feed.readings(TUE_0300 + timedelta(minutes=20), [5.0] * 10 + [8.4] * 20)
    alerts = sorted(by_rule(detect(store)[1], "DET-003"), key=lambda a: a["first_seen"])
    serious = next(a for a in alerts if a["device_id"] == "FRIDGE-001")
    minor = alerts[-1]
    vaccine = next(a for a in alerts if a["device_id"] == "FRIDGE-003")
    assert serious["severity"] == "HIGH" and "serious deviation" in serious["severity_reason"]
    assert minor["severity"] == "LOW" and "minor deviation" in minor["severity_reason"]
    # critical device: minor LOW raised one level
    assert vaccine["severity"] == "MEDIUM" and "critical device" in vaccine["severity_reason"]


def test_severity_rises_as_the_temperature_keeps_rising(store, feed):
    feed.readings(TUE_0300, [8.5] * 20)
    detector = Detector.from_config(store)
    detector.run()
    alert = one(store.alerts(), "DET-003")
    assert alert["severity"] == "LOW"
    feed.readings(TUE_0300 + timedelta(minutes=20), [9.0, 10.0, 11.5])
    Prioritizer.from_config(store).run()
    alert = store.alert(alert["alert_id"])
    assert alert["severity"] == "HIGH"
    last = store.alert_history(alert["alert_id"])[-1]
    assert (last["actor"], last["field"], last["old_value"], last["new_value"]) == (
        "prioritizer",
        "severity",
        "LOW",
        "HIGH",
    )


def test_missing_heartbeat_on_critical_device_stays_below_critical(store, feed):
    feed.readings(TUE_0300, [5.0] * 5, device="FRIDGE-003")
    feed.readings(TUE_0300 + timedelta(minutes=30), [5.0], device="FRIDGE-001")
    alert = one(detect(store)[1], "DET-005")
    assert alert["device_id"] == "FRIDGE-003" and alert["severity"] == "HIGH"


def test_off_hours_access_is_medium(store, feed):
    feed.login(TUE_0300)
    assert one(detect(store)[1], "DET-004")["severity"] == "MEDIUM"


def test_normal_maintenance_is_informational(store, feed):
    feed.login(MON_0630)
    feed.change(MON_0630 + timedelta(minutes=2), new=4.5)
    feed.change(MON_0630 + timedelta(minutes=5), new=4.0)
    alert = one(detect(store)[1], "DET-007")
    assert alert["severity"] == "INFO" and alert["evidence_count"] == 2  # one session
    assert {e["status"] for e in store.security_events()} == {"normal"}


def test_raise_one_respects_the_ceiling():
    from fridgeguard.detection.prioritizer import raise_one

    assert raise_one("LOW") == "MEDIUM"
    assert raise_one("HIGH", "HIGH") == "HIGH"
    assert raise_one("HIGH") == "CRITICAL"
    assert raise_one("INFO") == "INFO"


def test_invalid_prioritization_config(tmp_path):
    cfg = tmp_path / "config"
    shutil.copytree(CONFIG_DIR, cfg)
    path = cfg / "prioritization.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["refused_change"]["severity"] = "URGENT"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="refused_severity"):
        PrioritySettings.from_config(cfg)


# ---- alert management -------------------------------------------------------------------
@pytest.fixture
def det004(store, feed):
    feed.login(TUE_0300)
    return one(detect(store)[1], "DET-004")


def test_new_alerts_start_as_new(det004):
    assert det004["status"] == "new" and det004["assigned_to"] is None


def test_workflow_investigate_confirm_resolve(store, det004):
    aid = det004["alert_id"]
    a = store.set_alert_status(aid, "under_investigation", "anna")
    assert a["status"] == "under_investigation" and a["assigned_to"] == "anna"
    with pytest.raises(ValueError, match="note is required"):
        store.set_alert_status(aid, "confirmed", "anna")
    store.set_alert_status(aid, "confirmed", "anna", "owner did not log in at 03:00")
    history = store.status_history("EVT-000001")
    assert history[-1]["status"] == "malicious" and history[-1]["set_by"] == "analyst:anna"
    a = store.set_alert_status(aid, "resolved", "anna", "password reset, account reviewed")
    assert a["status"] == "resolved"
    fields = [(h["field"], h["new_value"]) for h in store.alert_history(aid)]
    assert fields[-4:] == [
        ("status", "under_investigation"),
        ("assigned_to", "anna"),
        ("status", "confirmed"),
        ("status", "resolved"),
    ]


def test_false_positive_returns_events_to_normal_and_can_be_reopened(store, det004):
    aid = det004["alert_id"]
    store.set_alert_status(aid, "false_positive", "anna", "emergency call-out, confirmed by phone")
    assert store.security_events()[0]["status"] == "normal"
    with pytest.raises(ValueError, match="note is required"):
        store.set_alert_status(aid, "under_investigation", "anna")
    a = store.set_alert_status(aid, "under_investigation", "anna", "second login seen")
    assert a["status"] == "under_investigation"


@pytest.mark.parametrize(
    "path",
    [["confirmed"], ["resolved", "confirmed"], ["under_investigation", "new"]],
)
def test_invalid_transitions_are_rejected(store, det004, path):
    aid = det004["alert_id"]
    for status in path[:-1]:
        store.set_alert_status(aid, status, "anna", "step")
    with pytest.raises(ValueError, match="can move to"):
        store.set_alert_status(aid, path[-1], "anna", "not allowed")


def test_analyst_severity_override_is_kept(store, det004):
    aid = det004["alert_id"]
    with pytest.raises(ValueError, match="note is required"):
        store.set_alert_severity(aid, "HIGH", "anna", "")
    store.set_alert_severity(aid, "HIGH", "anna", "account used for vaccine fridge")
    Prioritizer.from_config(store).run()
    a = store.alert(aid)
    assert a["severity"] == "HIGH" and a["severity_locked"] == 1
    assert a["severity_reason"] == "account used for vaccine fridge"


def test_history_is_append_only(store, det004):
    store.set_alert_status(det004["alert_id"], "under_investigation", "anna")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store.conn.execute("UPDATE alert_history SET actor = 'mallory'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store.conn.execute("DELETE FROM alert_history")


def test_unknown_alert(store):
    with pytest.raises(KeyError):
        store.set_alert_status("ALR-999999", "resolved", "anna", "x")


def test_queue_order_and_filters(store, feed):
    feed.login(TUE_0300)  # DET-004 MEDIUM
    for i in range(5):  # DET-002 HIGH, later
        feed.failure(TUE_0300 + timedelta(minutes=30, seconds=10 * i))
    feed.change(MON_0630)  # DET-007 INFO, earliest
    detect(store)
    queue = store.alert_queue()
    assert [a["rule_id"] for a in queue] == ["DET-002", "DET-004"]
    assert [a["rule_id"] for a in store.alert_queue("INFO")] == ["DET-002", "DET-004", "DET-007"]
    store.set_alert_status(queue[0]["alert_id"], "resolved", "anna", "IP blocked")
    assert [a["rule_id"] for a in store.alert_queue()] == ["DET-004"]


# ---- upgrading an existing database ------------------------------------------------------
STEP8_ALERTS = """
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT GENERATED ALWAYS AS ('ALR-' || printf('%06d', id)) STORED,
    alert_key TEXT NOT NULL UNIQUE, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    device_id TEXT, subject TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
    attack_ids TEXT NOT NULL, implements TEXT NOT NULL, first_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive'))
);
INSERT INTO alerts (alert_key, rule_id, rule_name, severity, subject, title, description,
                    attack_ids, implements, first_seen, created_at, status)
VALUES ('k1', 'DET-001', 'x', 'CRITICAL', 's', 't', 'd', '[]', '[]', '2026-11-17T01:00:00Z',
        '2026-11-17T01:00:00Z', 'acknowledged'),
       ('k2', 'DET-004', 'x', 'MEDIUM', 's', 't', 'd', '[]', '[]', '2026-11-17T02:00:00Z',
        '2026-11-17T02:00:00Z', 'open');
CREATE TABLE alert_evidence (
    alert_ref INTEGER NOT NULL REFERENCES alerts(id), record_id TEXT NOT NULL,
    kind TEXT NOT NULL, ts TEXT NOT NULL, note TEXT NOT NULL,
    PRIMARY KEY (alert_ref, record_id)
);
INSERT INTO alert_evidence VALUES (2, 'EVT-000009', 'security', '2026-11-17T02:00:00Z', 'n');
"""


def test_step8_database_is_upgraded(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(STEP8_ALERTS)
    conn.close()
    s = EventStore(path)
    rows = {a["alert_id"]: a for a in s.alerts()}
    assert rows["ALR-000001"]["status"] == "under_investigation"
    assert rows["ALR-000002"]["status"] == "new"
    assert rows["ALR-000001"]["base_severity"] == "CRITICAL"
    assert rows["ALR-000002"]["evidence_count"] == 1
    s.set_alert_status("ALR-000002", "under_investigation", "anna")  # new columns work
    s.close()
    EventStore(path).close()  # opening again is a no-op


# ---- end to end --------------------------------------------------------------------------
def test_live_and_batch_give_the_same_severities(tmp_path):
    live = simulate(tmp_path / "live.db", days=3)
    batch = simulate(tmp_path / "batch.db", days=3, live=False)
    Detector.from_config(batch).run()

    def key(a):
        return (a["rule_id"], a["first_seen"], a["severity"])

    assert sorted(map(key, live.alerts())) == sorted(map(key, batch.alerts()))
    assert {a["severity"] for a in live.alerts()} >= {"INFO", "MEDIUM", "HIGH"}
    live.close()
    batch.close()


def test_cli_alert_management(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    args = ["simulate", "--duration", "2d", "--show", "none", "--out", "-", "--db", db]
    assert main(args) == 0
    capsys.readouterr()
    assert main(["alerts", "--db", db, "queue"]) == 0
    out = capsys.readouterr().out
    assert "open alerts in the queue" in out and "INFO" not in out
    first = out.splitlines()[2].split()[0]
    assert (
        main(["alerts", "--db", db, "status", first, "under_investigation", "--analyst", "anna"])
        == 0
    )
    assert "now under_investigation (assigned to anna)" in capsys.readouterr().out
    assert main(["alerts", "--db", db, "status", first, "confirmed", "--analyst", "anna"]) == 2
    assert "note is required" in capsys.readouterr().err
    note = ["--note", "verified with the store manager", "--analyst", "anna"]
    assert main(["alerts", "--db", db, "status", first, "false_positive", *note]) == 0
    assert main(["alerts", "--db", db, "severity", first, "LOW", *note]) == 0
    capsys.readouterr()
    assert main(["alerts", "--db", db, "show", first]) == 0
    out = capsys.readouterr().out
    assert "(set by analyst)" in out and "status false_positive" not in out
    assert "status under_investigation -> false_positive" in out
    assert main(["alerts", "--db", db, "stats"]) == 0
    assert "false_positive 1" in capsys.readouterr().out
    assert main(["alerts", "--db", db, "prioritize"]) == 0
    assert "classified" in capsys.readouterr().out
    assert main(["alerts", "--db", db, "list", "--min-severity", "HIGH"]) == 0
    assert main(["alerts", "--db", db, "status", "ALR-999999", "resolved", "--note", "x"]) == 2
