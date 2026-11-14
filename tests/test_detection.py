"""Step 8: detection engine and rules DET-001 .. DET-006."""

import random
import shutil
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from fridgeguard.__main__ import main
from fridgeguard.config import CONFIG_DIR
from fridgeguard.detection import Detector, load_rules
from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    CONFIG_CHANGE,
    TELEMETRY_TEMPERATURE,
    make_event,
)
from fridgeguard.simulation import Simulation, SimulationSettings
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.sinks import SQLiteSink
from fridgeguard.storage import EventStore

# Monday 16 Nov 2026 06:30 Athens = 04:30 UTC (inside the maintenance window)
MON_0630 = datetime(2026, 11, 16, 4, 30, tzinfo=UTC)
# Tuesday 17 Nov 2026 03:00 Athens = 01:00 UTC (outside)
TUE_0300 = datetime(2026, 11, 17, 1, 0, tzinfo=UTC)


RANGES = {"FRIDGE-001": (2.0, 8.0), "FRIDGE-002": (-22.0, -15.0), "FRIDGE-003": (2.0, 8.0)}


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "det.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


class Feed:
    """Builds events and stores them (each test then runs the detector)."""

    def __init__(self, store):
        self.store = store
        self.rng = random.Random(5)

    def _put(self, event):
        result = self.store.ingest(event)
        assert result.error is None, result.error
        return event

    def change(
        self,
        ts,
        parameter="setpoint_c",
        old=4.0,
        new=10.0,
        *,
        user="maintenance_tech",
        role="technician",
        authorized=True,
        result="applied",
        device="FRIDGE-001",
        window=True,
    ):
        payload = {
            "parameter": parameter,
            "old_value": old,
            "new_value": new,
            "change_source": "local_panel",
            "result": result,
            "role": role,
            "permission": "change_setpoint",
            "within_maintenance_window": window,
            "session_id": "S-1",
        }
        if authorized is not ...:
            payload["authorized"] = authorized
        return self._put(
            make_event(
                self.rng,
                CONFIG_CHANGE,
                device,
                ts,
                actor=user,
                source_ip="10.10.1.30",
                payload=payload,
            )
        )

    def login(
        self, ts, user="maintenance_tech", role="technician", device="FRIDGE-001", ip="10.10.1.30"
    ):
        return self._put(
            make_event(
                self.rng,
                AUTH_LOGIN_SUCCESS,
                device,
                ts,
                actor=user,
                source_ip=ip,
                payload={"method": "password", "role": role, "within_maintenance_window": True},
            )
        )

    def failure(self, ts, ip="203.0.113.50", user="admin", device="FRIDGE-001"):
        return self._put(
            make_event(
                self.rng,
                AUTH_LOGIN_FAILURE,
                device,
                ts,
                actor=user,
                source_ip=ip,
                payload={"method": "password", "reason": "unknown_user", "role": None},
            )
        )

    def reading(self, ts, temp, device="FRIDGE-001", low=2.0, high=8.0):
        status = "ok" if low <= temp <= high else "out_of_range"
        return self._put(
            make_event(
                self.rng,
                TELEMETRY_TEMPERATURE,
                device,
                ts,
                payload={
                    "temperature_c": temp,
                    "setpoint_c": 4.0,
                    "expected_min_c": low,
                    "expected_max_c": high,
                    "status": status,
                    "door_open": False,
                    "compressor_on": True,
                },
            )
        )

    def readings(self, start, temps, device="FRIDGE-001", every_s=60):
        low, high = RANGES[device]
        for i, t in enumerate(temps):
            self.reading(start + timedelta(seconds=i * every_s), t, device, low, high)


@pytest.fixture
def feed(store):
    return Feed(store)


def detect(store, config_dir=None):
    summary = Detector.from_config(store, config_dir).run()
    return summary, store.alerts()


def by_rule(alerts, rule_id):
    return [a for a in alerts if a["rule_id"] == rule_id]


# ---- configuration -----------------------------------------------------------------------
def test_default_rules_and_severities():
    rules, dedup = load_rules()
    assert {r.rule_id: (r.name, r.severity) for r in rules} == {
        "DET-001": ("Unauthorized setpoint change", "CRITICAL"),
        "DET-002": ("Multiple failed logins", "HIGH"),
        "DET-003": ("Temperature outside configured limits", "HIGH"),
        "DET-004": ("Access outside maintenance hours", "MEDIUM"),
        "DET-005": ("Missing device heartbeat", "HIGH"),
        "DET-006": ("Unauthorized user configuration change", "CRITICAL"),
    }
    assert dedup == 900
    det2 = next(r for r in rules if r.rule_id == "DET-002")
    assert (det2.threshold, det2.window.total_seconds(), det2.column) == (5, 300, "source_ip")


@pytest.fixture
def config_copy(tmp_path):
    target = tmp_path / "config"
    shutil.copytree(CONFIG_DIR, target)
    return target


def rewrite_rules(config_dir: Path, change):
    path = config_dir / "detection.yaml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(cfg["rules"])
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda r: r["DET-002"].update(type="magic"), "unknown rule type"),
        (lambda r: r["DET-002"]["params"].update(treshold=3), "unknown parameters"),
        (lambda r: r["DET-001"].pop("params"), "missing parameters"),
        (lambda r: r["DET-003"].update(severity="URGENT"), "severity must be"),
        (lambda r: r["DET-002"]["params"].update(group_by="colour"), "group_by must be"),
        (lambda r: r["DET-004"]["params"]["maintenance_window"].pop("end"), "maintenance_window"),
    ],
)
def test_invalid_configuration_is_rejected(config_copy, change, message):
    rewrite_rules(config_copy, change)
    with pytest.raises(ValueError, match=message):
        load_rules(config_copy)


def test_thresholds_come_from_config(store, feed, config_copy):
    for i in range(3):
        feed.failure(MON_0630 + timedelta(seconds=10 * i))
    assert by_rule(detect(store)[1], "DET-002") == []
    rewrite_rules(config_copy, lambda r: r["DET-002"]["params"].update(threshold=3))
    assert len(by_rule(detect(store, config_copy)[1], "DET-002")) == 1


def test_disabled_rule_does_not_run(config_copy):
    rewrite_rules(config_copy, lambda r: r["DET-005"].update(enabled=False))
    assert "DET-005" not in {r.rule_id for r in load_rules(config_copy)[0]}


def test_new_rule_from_config_only(store, feed, config_copy):
    """A second brute-force rule, grouped by user, without writing code."""
    rewrite_rules(
        config_copy,
        lambda r: r.update(
            {
                "DET-007": {
                    "name": "Password spraying on one account",
                    "type": "failed_logins",
                    "severity": "HIGH",
                    "params": {"threshold": 3, "window_s": 600, "group_by": "user"},
                }
            }
        ),
    )
    for i, ip in enumerate(["198.51.100.1", "198.51.100.2", "198.51.100.3"]):
        feed.failure(MON_0630 + timedelta(seconds=30 * i), ip=ip, user="system_admin")
    alerts = detect(store, config_copy)[1]
    assert by_rule(alerts, "DET-002") == []  # different IPs
    assert len(by_rule(alerts, "DET-007")) == 1


# ---- DET-001 / DET-006 unauthorized changes ----------------------------------------------
def test_det001_unauthorized_setpoint_change(store, feed):
    event = feed.change(MON_0630, user="store_manager", role="manager", authorized=False)
    alerts = by_rule(detect(store)[1], "DET-001")
    assert len(alerts) == 1 and alerts[0]["severity"] == "CRITICAL"
    assert "store_manager changed setpoint_c 4.0 °C -> 10.0 °C" in alerts[0]["title"]
    history = store.status_history("EVT-000001")
    assert history[-1]["status"] == "malicious" and history[-1]["set_by"] == "DET-001"
    assert store.alert_evidence(alerts[0]["alert_id"])[0]["record_id"] == "EVT-000001"
    assert event.device_id == alerts[0]["device_id"]


def test_det001_denied_attempt_is_suspicious_not_malicious(store, feed):
    feed.change(MON_0630, user="store_manager", role="manager", authorized=False, result="denied")
    alerts = by_rule(detect(store)[1], "DET-001")
    assert "tried to change (denied)" in alerts[0]["title"]
    assert store.security_events()[0]["status"] == "suspicious"


def test_det001_authorized_technician_does_not_alert(store, feed):
    feed.change(MON_0630)  # technician with change_setpoint
    summary, alerts = detect(store)
    assert alerts == [] and summary.hits == 0
    assert store.security_events()[0]["status"] == "normal"


def test_det001_missing_authorization_is_flagged(store, feed):
    feed.change(MON_0630, authorized=...)
    alerts = by_rule(detect(store)[1], "DET-001")
    assert len(alerts) == 1 and "missing or invalid" in alerts[0]["description"]


def test_det006_other_configuration_parameters(store, feed):
    feed.change(MON_0630, parameter="firmware_version", old="2.4.1", new="9.9.9", authorized=False)
    feed.change(
        MON_0630 + timedelta(minutes=1),
        parameter="alarm_high_c",
        old=8.0,
        new=20.0,
        authorized=False,
        device="FRIDGE-002",
    )
    alerts = detect(store)[1]
    assert by_rule(alerts, "DET-001") == []
    assert {a["device_id"] for a in by_rule(alerts, "DET-006")} == {"FRIDGE-001", "FRIDGE-002"}
    assert all(a["severity"] == "CRITICAL" for a in alerts)


# ---- DET-002 multiple failed logins ------------------------------------------------------
def test_det002_five_failures_in_five_minutes(store, feed):
    for i in range(5):
        feed.failure(MON_0630 + timedelta(seconds=40 * i))
    alerts = by_rule(detect(store)[1], "DET-002")
    assert len(alerts) == 1
    assert alerts[0]["subject"] == "203.0.113.50" and alerts[0]["evidence_count"] == 5
    assert all(e["status"] == "suspicious" for e in store.security_events())


def test_det002_four_failures_do_not_alert(store, feed):
    for i in range(4):
        feed.failure(MON_0630 + timedelta(seconds=10 * i))
    assert detect(store)[1] == []


def test_det002_slow_failures_do_not_alert(store, feed):
    for i in range(5):
        feed.failure(MON_0630 + timedelta(minutes=2 * i))  # 5 failures over 8 minutes
    assert detect(store)[1] == []


def test_det002_different_sources_are_counted_separately(store, feed):
    for i in range(6):
        feed.failure(MON_0630 + timedelta(seconds=10 * i), ip=f"198.51.100.{i % 2}")
    assert detect(store)[1] == []


def test_det002_one_alert_per_burst(store, feed):
    for i in range(8):
        feed.failure(MON_0630 + timedelta(seconds=10 * i))
    for i in range(5):  # a second burst an hour later
        feed.failure(MON_0630 + timedelta(hours=1, seconds=10 * i))
    alerts = by_rule(detect(store)[1], "DET-002")
    assert [a["evidence_count"] for a in alerts] == [8, 5]


# ---- DET-003 temperature outside configured limits ---------------------------------------
def test_det003_sustained_excursion(store, feed):
    feed.readings(MON_0630, [4.0, 5.0] + [9.0 + i * 0.1 for i in range(20)])
    alerts = by_rule(detect(store)[1], "DET-003")
    assert len(alerts) == 1
    assert "above its 2.0..8.0 °C range for 15 min" in alerts[0]["title"]
    evidence = store.alert_evidence(alerts[0]["alert_id"])
    assert [e["kind"] for e in evidence] == ["telemetry", "telemetry"]
    assert "first reading outside" in evidence[0]["note"]


def test_det003_short_excursion_is_ignored(store, feed):
    feed.readings(MON_0630, [4.0] + [9.5] * 10 + [4.5] * 5)  # e.g. door left open 10 min
    assert detect(store)[1] == []


def test_det003_below_range_and_per_device_limits(store, feed):
    temps = [-23.5] * 20
    for i, t in enumerate(temps):
        feed.reading(MON_0630 + timedelta(minutes=i), t, device="FRIDGE-002", low=-22.0, high=-15.0)
    alerts = by_rule(detect(store)[1], "DET-003")
    assert len(alerts) == 1 and "below" in alerts[0]["title"]


# ---- DET-004 access outside maintenance hours --------------------------------------------
def test_det004_off_hours_session_is_one_alert(store, feed):
    feed.login(TUE_0300)
    feed.change(TUE_0300 + timedelta(minutes=2), window=False)
    alerts = by_rule(detect(store)[1], "DET-004")
    assert len(alerts) == 1 and alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["subject"] == "maintenance_tech" and alerts[0]["evidence_count"] == 2
    assert "logged in on FRIDGE-001 at Tue 03:00 local time" in alerts[0]["title"]


def test_det004_inside_window_is_fine(store, feed):
    feed.login(MON_0630)
    feed.change(MON_0630 + timedelta(minutes=2))
    assert detect(store)[1] == []


def test_det004_ignores_roles_without_restrictions(store, feed):
    feed.login(TUE_0300, user="store_manager", role="manager")
    assert detect(store)[1] == []


def test_det004_weekend_is_outside_the_window(store, feed):
    saturday_0700 = datetime(2026, 11, 21, 5, 0, tzinfo=UTC)
    feed.login(saturday_0700, user="system_admin", role="admin")
    assert len(by_rule(detect(store)[1], "DET-004")) == 1


def test_det004_does_not_trust_the_device_flag(store, feed):
    """The device claims 'inside the window', but the clock says 03:00."""
    feed.change(TUE_0300, window=True)
    assert len(by_rule(detect(store)[1], "DET-004")) == 1


# ---- DET-005 missing heartbeat -----------------------------------------------------------
def test_det005_silent_device(store, feed):
    feed.readings(MON_0630, [4.0] * 5, device="FRIDGE-001")
    feed.readings(MON_0630, [-18.0] * 15, device="FRIDGE-002")  # keeps time moving
    alerts = detect(store)[1]
    assert len(alerts) == 1 and alerts[0]["device_id"] == "FRIDGE-001"
    assert alerts[0]["first_seen"] == "2026-11-16T04:37:00.000Z"  # last reading + 3 min
    assert store.alert_evidence(alerts[0]["alert_id"])[0]["record_id"] == "TEL-000005"


def test_det005_short_gap_is_fine(store, feed):
    for minute in (0, 1, 2, 4, 5, 6):  # one missed reading
        feed.reading(MON_0630 + timedelta(minutes=minute), 4.0)
    assert detect(store)[1] == []


def test_det005_alerts_again_after_recovery(store, feed):
    for minute in [0, 1, 30, 31, 60]:  # two outages, 30 min apart
        feed.reading(MON_0630 + timedelta(minutes=minute), 4.0, device="FRIDGE-001")
    feed.readings(MON_0630, [-18.0] * 61, device="FRIDGE-002")
    alerts = detect(store)[1]
    assert [a["rule_id"] for a in alerts] == ["DET-005", "DET-005"]


def test_det005_flapping_device_is_one_alert(store, feed):
    for minute in [0, 1, 10, 11, 20]:  # outages within the 15-min grouping window
        feed.reading(MON_0630 + timedelta(minutes=minute), 4.0, device="FRIDGE-001")
    feed.readings(MON_0630, [-18.0] * 21, device="FRIDGE-002")
    alerts = detect(store)[1]
    assert len(alerts) == 1 and alerts[0]["evidence_count"] == 2


# ---- engine behaviour --------------------------------------------------------------------
def test_running_twice_creates_no_duplicates(store, feed):
    for i in range(6):
        feed.failure(MON_0630 + timedelta(seconds=10 * i))
    feed.change(
        MON_0630 + timedelta(minutes=5), user="store_manager", role="manager", authorized=False
    )
    first, alerts = detect(store)
    history = len(store.status_history("EVT-000001"))
    second, again = detect(store)
    assert len(first.new_alerts) == 2 and second.new_alerts == []
    assert again == alerts
    assert len(store.status_history("EVT-000001")) == history


def test_hits_far_apart_become_separate_alerts(store, feed):
    feed.change(MON_0630, user="store_manager", role="manager", authorized=False)
    feed.change(
        MON_0630 + timedelta(minutes=5), user="store_manager", role="manager", authorized=False
    )
    feed.change(
        MON_0630 + timedelta(hours=2), user="store_manager", role="manager", authorized=False
    )
    alerts = by_rule(detect(store)[1], "DET-001")
    assert [a["evidence_count"] for a in alerts] == [2, 1]


# ---- end to end against the simulator's ground truth ------------------------------------
def simulate(path, days=7, live=True, **settings):
    sim = Simulation(
        SimulationSettings(
            password_hash_iterations=1000, faults_per_day=0.6, anomalies_per_day=2, **settings
        ),
        [],
    )
    store = EventStore(path)
    store.register_devices(sim.fleet)
    sink = SQLiteSink(store)
    sim.sinks.append(sink)
    detector = None
    if live:
        detector = Detector.from_config(store)

        def on_stored(result):
            kind = "telemetry" if result.table == "telemetry" else "security"
            detector.process_row(kind, store.record_row(kind, result.ref))

        sink.on_stored = on_stored
    sim.run(timedelta(days=days))
    if detector:
        detector.finish(sim.now)
    return store


@pytest.fixture(scope="module")
def week(tmp_path_factory):
    store = simulate(tmp_path_factory.mktemp("week") / "week.db")
    yield store
    store.close()


def test_live_and_batch_detection_agree(week, tmp_path):
    batch = simulate(tmp_path / "batch.db", live=False)
    Detector.from_config(batch).run()

    def key(a):
        return (a["rule_id"], a["subject"], a["first_seen"], a["evidence_count"])

    assert sorted(map(key, batch.alerts())) == sorted(map(key, week.alerts()))
    batch.close()


def test_every_rule_fires_in_a_simulated_week(week):
    assert {a["rule_id"] for a in week.alerts()} >= {
        "DET-001",
        "DET-002",
        "DET-003",
        "DET-004",
        "DET-005",
    }


def test_alerts_point_at_injected_scenarios(week):
    """No false positives: alert evidence belongs to an injected anomaly or fault."""
    scenarios = {}
    for row in week.security_events():
        scenarios[row["event_id"]] = row["scenario"]
    for row in week.telemetry():
        scenarios[row["reading_id"]] = row["scenario"]
    expected = {
        "DET-001": {"unauthorized_change_attempt"},
        "DET-002": {"unknown_login_attempts"},
        "DET-003": {"compressor_failure"},
        "DET-004": {"off_hours_access"},
    }
    for alert in week.alerts():
        if alert["rule_id"] not in expected:
            continue  # DET-005 evidence is the last *normal* reading before the silence
        evidence = week.alert_evidence(alert["alert_id"])
        labels = {scenarios[e["record_id"]] for e in evidence}
        assert labels & expected[alert["rule_id"]], (alert["alert_id"], labels)


def test_injected_anomalies_are_detected(week):
    """Recall: every unauthorized change and off-hours session raised an alert."""
    alerted = {e["record_id"] for a in week.alerts() for e in week.alert_evidence(a["alert_id"])}
    missed = defaultdict(list)
    for row in week.security_events():
        if (
            row["scenario"] == "unauthorized_change_attempt"
            and row["event_type"] == "SETPOINT_CHANGE"
        ):
            if row["event_id"] not in alerted:
                missed["DET-001"].append(row["event_id"])
        if row["scenario"] == "off_hours_access" and row["event_type"] == "LOGIN_SUCCESS":
            if row["event_id"] not in alerted:
                missed["DET-004"].append(row["event_id"])
    assert not missed


# ---- CLI ---------------------------------------------------------------------------------
def test_cli_simulate_detect_and_alerts(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    assert (
        main(
            [
                "simulate",
                "--duration",
                "3d",
                "--show",
                "none",
                "--out",
                "-",
                "--db",
                db,
                "--faults-per-day",
                "1",
            ]
        )
        == 0
    )
    err = capsys.readouterr().err
    assert "# detection:" in err and "new alerts" in err
    assert main(["detect", "--db", db]) == 0
    assert "0 new" in capsys.readouterr().out  # already detected live
    assert main(["alerts", "--db", db, "list"]) == 0
    out = capsys.readouterr().out
    assert "ALR-000001" in out and "Severity" in out
    assert main(["alerts", "--db", db, "show", "ALR-000001"]) == 0
    assert "evidence (" in capsys.readouterr().out
    assert main(["alerts", "rules"]) == 0
    assert "DET-006" in capsys.readouterr().out
    assert main(["alerts", "--db", db, "show", "ALR-999999"]) == 2
