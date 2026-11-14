"""Step 6: users, authentication, authorization roles and activity logging."""

import json
from collections import Counter
from datetime import timedelta

import pytest

from fridgeguard.generator.activity import ANOMALY_SCENARIOS
from fridgeguard.generator.auth import (
    RESULT_APPLIED,
    RESULT_DENIED,
    RESULT_REJECTED,
    PasswordHasher,
)
from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    CONFIG_CHANGE,
    TELEMETRY_TEMPERATURE,
)
from fridgeguard.simulation import Simulation, SimulationSettings, parse_duration
from fridgeguard.sinks import JsonlSink, ListSink
from tests.conftest import IN_WINDOW, OFF_HOURS

DEVICE = "FRIDGE-001"
TECH_IP = "10.10.1.30"


def login(auth, passwords, username, ts=IN_WINDOW, password=None):
    pw = passwords.get(username, "x") if password is None else password
    return auth.login(ts, username, pw, DEVICE, TECH_IP)


# ---- users and passwords -----------------------------------------------------------
def test_fictional_users_and_roles(directory_and_passwords):
    directory, passwords, _ = directory_and_passwords
    assert {u: directory.get(u).role for u in directory.users} == {
        "store_manager": "manager",
        "maintenance_tech": "technician",
        "system_admin": "admin",
        "unknown_user": "none",
    }
    assert directory.account("unknown_user") is None
    assert set(passwords) == {"store_manager", "maintenance_tech", "system_admin"}


def test_only_password_hashes_are_stored(directory_and_passwords):
    directory, passwords, _ = directory_and_passwords
    for username, password in passwords.items():
        user = directory.get(username)
        assert password not in user.password_hash
        assert len(user.password_hash) == 64 and len(user.salt) == 16
    hasher = PasswordHasher(1000)
    salt = b"s" * 16
    assert hasher.verify("pw", salt, hasher.hash("pw", salt))
    assert not hasher.verify("pw2", salt, hasher.hash("pw", salt))


# ---- authentication events ---------------------------------------------------------
def test_successful_login_is_logged(auth, passwords, sink):
    session = login(auth, passwords, "maintenance_tech")
    assert session is not None
    event = sink.events[-1]
    assert event.event_type == AUTH_LOGIN_SUCCESS
    assert event.actor == "maintenance_tech"
    assert event.source_ip == TECH_IP
    assert event.ts_device == "2026-11-16T04:30:00.000Z"
    assert event.payload["role"] == "technician"
    assert event.payload["method"] == "password"
    assert event.payload["within_maintenance_window"] is True


@pytest.mark.parametrize(
    "username, password, reason",
    [
        ("maintenance_tech", "wrong-password", "bad_password"),
        ("unknown_user", "123456", "unknown_user"),
        ("root", "admin", "unknown_user"),
    ],
)
def test_failed_logins_are_logged(auth, passwords, sink, username, password, reason):
    assert login(auth, passwords, username, password=password) is None
    event = sink.events[-1]
    assert event.event_type == AUTH_LOGIN_FAILURE
    assert event.actor == username
    assert event.payload["reason"] == reason


def test_logout_records_session_length(auth, passwords, sink):
    session = login(auth, passwords, "store_manager")
    auth.logout(IN_WINDOW + timedelta(minutes=5), session)
    event = sink.events[-1]
    assert event.event_type == AUTH_LOGOUT
    assert event.payload["session_s"] == 300
    assert event.payload["session_id"] == session.session_id


def test_passwords_never_appear_in_events(auth, passwords, sink):
    for username, password in passwords.items():
        login(auth, passwords, username)
        login(auth, passwords, username, password=password + "typo")
    blob = json.dumps([e.to_dict() for e in sink.events])
    for password in passwords.values():
        assert password not in blob
    assert "password_hash" not in blob and "salt" not in blob


# ---- authorization -----------------------------------------------------------------
def test_technician_changes_setpoint_in_window(auth, passwords, sink, fleet):
    session = login(auth, passwords, "maintenance_tech")
    assert auth.change_config(IN_WINDOW, session, "setpoint_c", 4.5) == RESULT_APPLIED
    assert fleet[DEVICE].setpoint_c == 4.5
    p = sink.events[-1].payload
    assert sink.events[-1].event_type == CONFIG_CHANGE
    assert (p["old_value"], p["new_value"], p["result"]) == (4.0, 4.5, "applied")
    assert p["authorized"] is True and p["within_maintenance_window"] is True


def test_manager_cannot_change_setpoint(auth, passwords, sink, fleet):
    session = login(auth, passwords, "store_manager")
    assert auth.change_config(IN_WINDOW, session, "setpoint_c", 9.0) == RESULT_DENIED
    assert fleet[DEVICE].setpoint_c == 4.0
    p = sink.events[-1].payload
    assert p["authorized"] is False and p["permission"] == "change_setpoint"


def test_technician_cannot_update_firmware_but_admin_can(auth, passwords, fleet):
    tech = login(auth, passwords, "maintenance_tech")
    assert auth.change_config(IN_WINDOW, tech, "firmware_version", "9.9.9") == RESULT_DENIED
    admin = login(auth, passwords, "system_admin")
    assert auth.change_config(IN_WINDOW, admin, "firmware_version", "2.4.2") == RESULT_APPLIED
    assert fleet[DEVICE].firmware_version == "2.4.2"


def test_off_hours_change_is_applied_but_flagged(auth, passwords, sink):
    session = login(auth, passwords, "maintenance_tech", ts=OFF_HOURS)
    assert sink.events[-1].payload["within_maintenance_window"] is False
    assert auth.change_config(OFF_HOURS, session, "setpoint_c", 6.0) == RESULT_APPLIED
    p = sink.events[-1].payload
    assert p["authorized"] is True and p["within_maintenance_window"] is False


def test_physically_invalid_value_is_rejected(auth, passwords, fleet):
    session = login(auth, passwords, "maintenance_tech")
    assert auth.change_config(IN_WINDOW, session, "setpoint_c", 99) == RESULT_REJECTED
    assert auth.change_config(IN_WINDOW, session, "setpoint_c", "warm") == RESULT_REJECTED
    assert fleet[DEVICE].setpoint_c == 4.0


def test_change_requires_active_session(auth, passwords):
    session = login(auth, passwords, "maintenance_tech")
    auth.logout(IN_WINDOW, session)
    with pytest.raises(ValueError, match="not active"):
        auth.change_config(IN_WINDOW, session, "setpoint_c", 5.0)


# ---- activity simulator and runner -------------------------------------------------
def simulate(days=3, **kwargs):
    sink = ListSink()
    settings = SimulationSettings(password_hash_iterations=1000, **kwargs)
    Simulation(settings, [sink]).run(timedelta(days=days))
    return sink.events


def test_activity_over_several_days():
    events = simulate(days=3)
    types = Counter(e.event_type for e in events)
    assert types[TELEMETRY_TEMPERATURE] == 3 * 24 * 60 * 3
    assert types[AUTH_LOGIN_SUCCESS] >= 9
    assert types[AUTH_LOGIN_FAILURE] >= 1
    assert types[AUTH_LOGOUT] >= 9
    assert types[CONFIG_CHANGE] >= 3
    actors = {e.actor for e in events if e.actor}
    assert {"store_manager", "maintenance_tech"} <= actors
    for e in events:
        assert e.ts_device.endswith("Z")
        if e.event_type != TELEMETRY_TEMPERATURE:
            assert e.actor and e.source_ip


def test_events_are_in_time_order():
    events = simulate(days=2)
    times = [e.ts_device for e in events]
    assert times == sorted(times)


def test_baseline_has_no_anomalies():
    events = simulate(days=3, anomalies_per_day=0)
    assert {e.scenario for e in events} == {"baseline"}
    changes = [e for e in events if e.event_type == CONFIG_CHANGE]
    assert changes and all(e.payload["within_maintenance_window"] for e in changes)
    assert all(e.payload["result"] == RESULT_APPLIED for e in changes)


def test_anomalies_are_labelled():
    events = simulate(days=7, anomalies_per_day=3)
    labels = {e.scenario for e in events} - {"baseline"}
    assert labels == set(ANOMALY_SCENARIOS)
    off_hours = [
        e for e in events if e.scenario == "off_hours_access" and e.event_type == CONFIG_CHANGE
    ]
    assert off_hours and not any(e.payload["within_maintenance_window"] for e in off_hours)
    denied = [
        e for e in events if e.event_type == CONFIG_CHANGE and e.payload["result"] == "denied"
    ]
    assert denied and all(e.scenario == "unauthorized_change_attempt" for e in denied)


def test_simulation_is_reproducible():
    a = simulate(days=1, seed=99)
    b = simulate(days=1, seed=99)
    assert [e.hash for e in a] == [e.hash for e in b]


def test_fridges_only_mode():
    events = simulate(days=1, activity=False)
    assert {e.event_type for e in events} == {TELEMETRY_TEMPERATURE}


def test_jsonl_log_is_valid(tmp_path):
    path = tmp_path / "events.jsonl"
    settings = SimulationSettings(password_hash_iterations=1000)
    Simulation(settings, [JsonlSink(path)]).run(timedelta(hours=6))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 6 * 60 * 3
    first = json.loads(lines[0])
    assert {"event_id", "event_type", "device_id", "ts_device", "payload", "hash"} <= set(first)


def test_continuous_run_until_stopped():
    sink = ListSink()
    settings = SimulationSettings(password_hash_iterations=1000, activity=False)
    sim = Simulation(settings, [sink])
    ticks = sim.run(None, realtime=True, speed=1e6, should_stop=lambda: len(sink.events) >= 15)
    assert ticks == 5


@pytest.mark.parametrize(
    "text, seconds", [("90s", 90), ("30m", 1800), ("12h", 43200), ("2d", 172800)]
)
def test_parse_duration(text, seconds):
    assert parse_duration(text).total_seconds() == seconds


@pytest.mark.parametrize("text", ["", "10", "-5m", "3w"])
def test_parse_duration_rejects_bad_input(text):
    with pytest.raises(ValueError):
        parse_duration(text)
