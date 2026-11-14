"""Step 7: centralized event database."""

import json
import random
import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from fridgeguard.__main__ import main
from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    CONFIG_CHANGE,
    TELEMETRY_TEMPERATURE,
    make_event,
)
from fridgeguard.simulation import Simulation, SimulationSettings
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.sinks import JsonlSink, SQLiteSink
from fridgeguard.storage import EventStore, import_jsonl
from tests.conftest import IN_WINDOW, OFF_HOURS


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "events.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


def config_change(rng, ts=IN_WINDOW, **payload):
    base = {
        "parameter": "setpoint_c",
        "old_value": 3.0,
        "new_value": 12.0,
        "change_source": "local_panel",
        "result": "applied",
        "role": "technician",
        "permission": "change_setpoint",
        "authorized": True,
        "within_maintenance_window": True,
        "session_id": "S-1",
    }
    base.update(payload)
    return make_event(
        rng,
        CONFIG_CHANGE,
        "FRIDGE-001",
        ts,
        actor="maintenance_tech",
        source_ip="192.168.1.50",
        payload=base,
    )


def reading(rng, ts=IN_WINDOW, **payload):
    base = {
        "temperature_c": 3.2,
        "setpoint_c": 4.0,
        "expected_min_c": 2.0,
        "expected_max_c": 8.0,
        "status": "ok",
        "door_open": False,
        "compressor_on": True,
    }
    base.update(payload)
    return make_event(rng, TELEMETRY_TEMPERATURE, "FRIDGE-001", ts, payload=base)


# ---- schema ----------------------------------------------------------------------------
def test_schema_tables_and_wal(store):
    names = {r[0] for r in store.conn.execute("SELECT name FROM sqlite_master")}
    for name in (
        "devices",
        "telemetry",
        "security_events",
        "event_status_history",
        "rejected_events",
        "v_security_events",
    ):
        assert name in names
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store.stats()["devices"] == 3


def test_telemetry_table_has_no_user_columns(store):
    columns = {r[1] for r in store.conn.execute("PRAGMA table_info(telemetry)")}
    assert not columns & {"user", "source_ip", "role", "previous_value", "new_value"}


# ---- ingest ------------------------------------------------------------------------------
def test_reading_goes_to_telemetry_only(store, rng):
    result = store.ingest(reading(rng), IN_WINDOW)
    store.commit()
    assert result.table == "telemetry"
    row = store.telemetry()[0]
    assert row["reading_id"] == "TEL-000001"
    assert (row["temperature_c"], row["expected_min_c"], row["device_status"]) == (3.2, 2.0, "ok")
    assert store.security_events() == []


def test_setpoint_change_has_the_central_fields(store, rng):
    store.ingest(config_change(rng), IN_WINDOW + timedelta(milliseconds=40))
    store.commit()
    e = store.security_events()[0]
    assert e["event_id"] == "EVT-000001"
    assert e["timestamp"] == "2026-11-16T04:30:00.000Z"
    assert e["device"] == "FRIDGE-001"
    assert e["event_type"] == "SETPOINT_CHANGE"
    assert e["user"] == "maintenance_tech"
    assert (e["previous_value"], e["new_value"]) == ("3.0 °C", "12.0 °C")
    assert e["source_ip"] == "192.168.1.50"
    assert e["status"] == "normal"
    raw = store.conn.execute("SELECT ts_ingest FROM security_events").fetchone()[0]
    assert raw == "2026-11-16T04:30:00.040Z"


@pytest.mark.parametrize(
    "parameter, old, new, event_type, shown",
    [
        ("setpoint_c", 4.0, 4.5, "SETPOINT_CHANGE", "4.5 °C"),
        ("alarm_high_c", 8.0, 12.0, "ALARM_THRESHOLD_CHANGE", "12.0 °C"),
        ("defrost_interval_h", 8, 6, "CONFIG_CHANGE", "6 h"),
        ("firmware_version", "2.4.1", "2.4.2", "FIRMWARE_UPDATE", "2.4.2"),
    ],
)
def test_configuration_event_types(store, rng, parameter, old, new, event_type, shown):
    store.ingest(config_change(rng, parameter=parameter, old_value=old, new_value=new))
    e = store.security_events()[0]
    assert (e["event_type"], e["new_value"]) == (event_type, shown)


def test_login_events(store, rng):
    ok = make_event(
        rng,
        AUTH_LOGIN_SUCCESS,
        "FRIDGE-002",
        IN_WINDOW,
        actor="store_manager",
        source_ip="10.10.1.20",
        payload={"method": "password", "role": "manager", "within_maintenance_window": True},
    )
    bad = make_event(
        rng,
        AUTH_LOGIN_FAILURE,
        "FRIDGE-002",
        IN_WINDOW,
        actor="store_manager",
        source_ip="10.10.1.20",
        payload={"method": "password", "role": "manager", "reason": "bad_password"},
    )
    store.ingest(ok)
    store.ingest(bad)
    rows = store.security_events()
    assert [r["event_type"] for r in rows] == ["LOGIN_SUCCESS", "LOGIN_FAILURE"]
    assert rows[1]["reason"] == "bad_password" and rows[1]["status"] == "normal"


def test_duplicate_events_are_stored_once(store, rng):
    event = config_change(rng)
    assert not store.ingest(event).duplicate
    assert store.ingest(event).duplicate
    assert len(store.security_events()) == 1


# ---- initial status ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload, ts, status, reason_part",
    [
        ({}, IN_WINDOW, "normal", "no issues"),
        (
            {"authorized": False, "role": "manager", "result": "denied"},
            IN_WINDOW,
            "suspicious",
            "lacks permission",
        ),
        ({"within_maintenance_window": False}, OFF_HOURS, "suspicious", "outside the maintenance"),
        ({"authorized": None}, IN_WINDOW, "suspicious", "missing or invalid"),
        ({"authorized": "yes"}, IN_WINDOW, "suspicious", "missing or invalid"),
    ],
)
def test_initial_status_of_config_changes(store, rng, payload, ts, status, reason_part):
    store.ingest(config_change(rng, ts=ts, **payload))
    e = store.security_events()[0]
    assert e["status"] == status
    assert reason_part in e["status_reason"]
    assert e["status_set_by"] == "ingest"


def test_missing_authorized_field_is_suspicious(store, rng):
    event = config_change(rng)
    payload = {k: v for k, v in event.payload.items() if k != "authorized"}
    store.ingest(replace(event, payload=payload, hash=""))
    assert store.security_events()[0]["status"] == "suspicious"


def test_unknown_account_login_is_suspicious_but_typo_is_not(store, rng):
    for actor, reason in (("root", "unknown_user"), ("store_manager", "bad_password")):
        store.ingest(
            make_event(
                rng,
                AUTH_LOGIN_FAILURE,
                "FRIDGE-001",
                IN_WINDOW,
                actor=actor,
                source_ip="203.0.113.50",
                payload={"method": "password", "reason": reason, "role": None},
            )
        )
    statuses = {r["user"]: r["status"] for r in store.security_events()}
    assert statuses == {"root": "suspicious", "store_manager": "normal"}


def test_status_can_be_raised_and_history_is_kept(store, rng):
    store.ingest(config_change(rng))
    store.set_status("EVT-000001", "malicious", "matched DR-5", "DR-5")
    assert store.security_events()[0]["status"] == "malicious"
    history = store.status_history("EVT-000001")
    assert [h["status"] for h in history] == ["normal", "malicious"]
    assert history[1]["set_by"] == "DR-5"
    assert store.security_events(status="normal") == []
    with pytest.raises(ValueError):
        store.set_status("EVT-000001", "harmless", "x", "analyst")
    with pytest.raises(KeyError):
        store.set_status("EVT-999999", "normal", "x", "analyst")


# ---- validation --------------------------------------------------------------------------
def test_invalid_events_are_rejected_not_dropped(store, rng):
    unknown_device = replace(reading(rng), device_id="FRIDGE-999", hash="")
    tampered = replace(config_change(rng), actor="system_admin")  # hash no longer matches
    telemetry_with_user = replace(reading(rng), actor="mallory", hash="")
    for event in (unknown_device, tampered, telemetry_with_user):
        assert store.ingest(event).error
    errors = [r["error"] for r in store.rejected()]
    assert "unknown device" in errors[0]
    assert "hash does not match" in errors[1]
    assert "must not carry a user" in errors[2]
    assert store.stats()["telemetry"] == store.stats()["security_events"] == 0


def test_garbage_json_lines_are_rejected(store):
    assert store.ingest_json_line("not json").error
    assert store.ingest_json_line('{"event_type": "telemetry.temperature"}').error
    assert len(store.rejected()) == 2


# ---- integrity ---------------------------------------------------------------------------
@pytest.mark.parametrize("table", ["telemetry", "security_events", "event_status_history"])
def test_tables_are_append_only(store, rng, table):
    store.ingest(reading(rng))
    store.ingest(config_change(rng))
    store.commit()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store.conn.execute(f"UPDATE {table} SET id = id + 100")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store.conn.execute(f"DELETE FROM {table}")


def test_verify_integrity_detects_tampering(store, rng):
    store.ingest(config_change(rng))
    store.commit()
    assert store.verify_integrity() == []
    # an attacker with file access drops the trigger and edits the raw record
    store.conn.execute("DROP TRIGGER security_events_no_update")
    store.conn.execute("UPDATE security_events SET raw_json = replace(raw_json, '12.0', '5.0')")
    assert store.verify_integrity() == ["EVT-000001: hash mismatch"]


# ---- end to end --------------------------------------------------------------------------
def simulate_into(store, days=2, **settings):
    sim = Simulation(SimulationSettings(password_hash_iterations=1000, **settings), [])
    store.register_devices(sim.fleet)
    sink = SQLiteSink(store)
    sim.sinks.append(sink)
    sim.run(timedelta(days=days))
    return sim, sink


def test_simulation_fills_the_database(store):
    sim, sink = simulate_into(store, days=2)
    s = store.stats()
    assert sink.rejected == 0 and s["rejected"] == 0
    assert s["telemetry"] == 2 * 24 * 60 * 3
    assert s["telemetry"] + s["security_events"] == sim.events_emitted
    assert {"LOGIN_SUCCESS", "LOGOUT", "SETPOINT_CHANGE"} <= set(s["by_type"])
    assert store.verify_integrity() == []


def test_suspicious_status_matches_injected_anomalies(store):
    simulate_into(store, days=7, anomalies_per_day=3)
    for row in store.security_events():
        if row["scenario"] == "baseline":
            assert row["status"] == "normal", row
    # the off-hours setpoint changes and denied changes are flagged at ingest
    for row in store.security_events(event_type="SETPOINT_CHANGE"):
        if row["scenario"] in ("off_hours_access", "unauthorized_change_attempt"):
            assert row["status"] == "suspicious"


def test_filters(store):
    simulate_into(store, days=2)
    rows = store.security_events(device="FRIDGE-001", event_type="LOGIN_SUCCESS")
    assert rows and all(r["device"] == "FRIDGE-001" for r in rows)
    since = store.security_events(since="2026-11-17T00:00")
    assert since and all(r["timestamp"] >= "2026-11-17" for r in since)
    assert len(store.telemetry(device="FRIDGE-002", limit=5)) == 5
    with pytest.raises(ValueError):
        store.security_events(colour="red")


def test_jsonl_import_matches_direct_storage(tmp_path):
    log = tmp_path / "events.jsonl"
    settings = SimulationSettings(password_hash_iterations=1000)
    Simulation(settings, [JsonlSink(log)]).run(timedelta(days=1))
    direct = EventStore(tmp_path / "direct.db")
    simulate_into(direct, days=1)
    imported = EventStore(tmp_path / "imported.db")
    imported.register_devices(Fleet.from_config(random.Random(0)))
    with log.open(encoding="utf-8") as fh:
        counts = import_jsonl(imported, fh)
    assert counts["rejected"] == 0
    assert direct.stats() == imported.stats()
    # importing the same log again adds nothing
    with log.open(encoding="utf-8") as fh:
        again = import_jsonl(imported, fh)
    assert again["duplicates"] == counts["telemetry"] + counts["security_events"]


def test_read_only_store_cannot_write(tmp_path, store, rng):
    store.ingest(reading(rng))
    store.commit()
    ro = EventStore(store.path, read_only=True)
    assert len(ro.telemetry()) == 1
    with pytest.raises(sqlite3.OperationalError):
        ro.conn.execute(
            "INSERT INTO rejected_events (ts_ingest, error, raw_json) VALUES ('', '', '')"
        )
    ro.close()


# ---- CLI -----------------------------------------------------------------------------------
def test_cli_simulate_and_query(tmp_path, capsys):
    db = tmp_path / "cli.db"
    assert (
        main(["simulate", "--duration", "1d", "--show", "none", "--out", "-", "--db", str(db)]) == 0
    )
    capsys.readouterr()
    assert main(["events", "--db", str(db), "list", "--type", "setpoint_change"]) == 0
    out = capsys.readouterr().out
    assert "Event ID" in out and "SETPOINT_CHANGE" in out and "°C" in out
    assert main(["events", "--db", str(db), "verify"]) == 0
    assert "OK: all" in capsys.readouterr().out
    assert main(["events", "--db", str(db), "history", "EVT-000001"]) == 0
    assert "set by ingest" in capsys.readouterr().out
    assert main(["events", "--db", str(tmp_path / "missing.db"), "stats"]) == 2


def test_raw_json_round_trip(store, rng):
    event = config_change(rng)
    store.ingest(event)
    raw = store.conn.execute("SELECT raw_json FROM security_events").fetchone()[0]
    assert json.loads(raw) == event.to_dict()
