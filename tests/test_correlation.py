"""Step 9: event correlation into incidents, built from hand-made events."""

import json
import random
import sqlite3
from datetime import timedelta

import pytest

from fridgeguard.__main__ import main
from fridgeguard.detection import CorrelationSettings, Correlator, Detector
from fridgeguard.models import AUTH_LOGIN_SUCCESS, AUTH_LOGOUT, make_event
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage import EventStore
from tests.test_detection import MON_0630, TUE_0300, Feed

ATTACKER = "203.0.113.50"


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "cor.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


class Story(Feed):
    """Hand-made events for one investigation story."""

    def session_login(self, ts, session, *, user="maintenance_tech", ip=ATTACKER, window=False):
        return self._put(
            make_event(
                self.rng,
                AUTH_LOGIN_SUCCESS,
                "FRIDGE-001",
                ts,
                actor=user,
                source_ip=ip,
                payload={
                    "method": "password",
                    "role": "technician",
                    "within_maintenance_window": window,
                    "session_id": session,
                },
            )
        )

    def session_change(self, ts, session, *, ip=ATTACKER, new=12.0, window=False, user=None):
        payload = {
            "parameter": "setpoint_c",
            "old_value": 4.0,
            "new_value": new,
            "change_source": "remote_api",
            "result": "applied",
            "role": "technician",
            "permission": "change_setpoint",
            "authorized": True,
            "within_maintenance_window": window,
            "session_id": session,
        }
        return self._put(
            make_event(
                self.rng,
                "config.change",
                "FRIDGE-001",
                ts,
                actor=user or "maintenance_tech",
                source_ip=ip,
                payload=payload,
            )
        )

    def logout(self, ts, session, ip=ATTACKER):
        return self._put(
            make_event(
                self.rng,
                AUTH_LOGOUT,
                "FRIDGE-001",
                ts,
                actor="maintenance_tech",
                source_ip=ip,
                payload={"role": "technician", "session_id": session},
            )
        )

    def guesses(self, ts, names=("admin", "root", "technician", "maintenance_tech", "service")):
        for i, name in enumerate(names):
            self.failure(ts + timedelta(seconds=20 * i), ip=ATTACKER, user=name)

    def warming(self, start, minutes=40, peak=12.0):
        temps = [round(4.0 + (peak - 4.0) * i / (minutes - 1), 2) for i in range(minutes)]
        self.readings(start, temps)


@pytest.fixture
def story(store):
    return Story(store)


def correlate(store):
    Detector.from_config(store).run()
    summary = Correlator.from_config(store).run()
    return summary, store.incidents()


def only(incidents):
    assert len(incidents) == 1, [i["pattern_id"] for i in incidents]
    return incidents[0]


# ---- patterns -----------------------------------------------------------------------------
def test_brute_force_takeover_and_tampering_is_one_critical_incident(store, story):
    story.readings(TUE_0300 - timedelta(minutes=5), [4.0] * 5)
    story.guesses(TUE_0300)
    login = story.session_login(TUE_0300 + timedelta(minutes=3), "S-77")
    change = story.session_change(TUE_0300 + timedelta(minutes=5), "S-77")
    story.logout(TUE_0300 + timedelta(minutes=7), "S-77")
    story.warming(TUE_0300 + timedelta(minutes=6))

    summary, incidents = correlate(store)
    inc = only(incidents)
    assert summary.created == [inc["incident_id"]]
    assert inc["pattern_id"] == "COR-001" and inc["severity"] == "CRITICAL"
    assert inc["status"] == "open" and inc["verdict"] == "unverified"
    assert inc["confidence"] >= 70 and inc["confidence_level"] == "high"

    steps = {s["id"]: s for s in json.loads(inc["steps"])}
    members = store.incident_members(inc["incident_id"])
    ids = {m["record_id"] for m in members}
    kinds = {m["kind"] for m in members}
    assert {"alert", "security", "telemetry"} <= kinds
    assert steps["brute_force"]["record_id"].startswith("ALR-")
    login_id = next(m["record_id"] for m in members if "S-77" in m["note"] or "after" in m["note"])
    assert login_id in ids
    assert steps["login"]["record_id"] and steps["change"]["record_id"]
    assert steps["impact"]["record_id"] is not None  # optional step matched

    factors = " | ".join(r for _, r in json.loads(inc["confidence_factors"]))
    assert "not on allow-list" in factors
    assert "outside the maintenance window" in factors
    assert "5 usernames" in factors
    assert "reacting to the change" in factors
    assert "outside the safe range" in factors
    entities = json.loads(inc["entities"])
    assert entities["source_ips"] == [ATTACKER] and entities["devices"] == ["FRIDGE-001"]
    assert entities["sessions"] == ["S-77"] and entities["users"] == ["maintenance_tech"]
    assert json.loads(inc["response"]) and json.loads(inc["questions"])
    assert login.event_id and change.event_id


def test_brute_force_and_login_without_change_is_high(store, story):
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(minutes=3), "S-5")
    inc = only(correlate(store)[1])
    assert inc["pattern_id"] == "COR-003" and inc["severity"] == "HIGH"


def test_failures_without_a_login_are_not_an_incident(store, story):
    story.guesses(TUE_0300)
    summary, incidents = correlate(store)
    assert incidents == [] and summary.alerts == 1


def test_login_from_the_same_ip_long_after_the_failures_is_not_linked(store, story):
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(hours=3), "S-6")
    patterns = {i["pattern_id"] for i in correlate(store)[1]}
    assert "COR-003" not in patterns and "COR-001" not in patterns


def test_planned_change_followed_by_excursion_has_low_confidence(store, story):
    story.readings(MON_0630 - timedelta(minutes=5), [4.0] * 5)
    story.change(MON_0630, new=10.0)  # permitted technician, inside the window
    story.warming(MON_0630 + timedelta(minutes=1), peak=11.0)
    inc = only(correlate(store)[1])
    assert inc["pattern_id"] == "COR-004" and inc["severity"] == "HIGH"
    factors = " | ".join(r for _, r in json.loads(inc["confidence_factors"]))
    assert "inside the maintenance window" in factors
    assert "allow-list" in factors
    assert inc["confidence_level"] == "low"


def test_suspicious_login_and_change_in_session(store, story):
    story.session_login(TUE_0300, "S-8", ip="10.10.1.30")  # privileged, outside the window
    story.session_change(TUE_0300 + timedelta(minutes=2), "S-8", ip="10.10.1.30", new=6.0)
    inc = only(correlate(store)[1])
    assert inc["pattern_id"] == "COR-002"


def test_single_alert_is_not_an_incident(store, story):
    story.session_login(TUE_0300, "S-9", ip="10.10.1.30")
    summary, incidents = correlate(store)
    assert summary.alerts >= 1 and incidents == []


# ---- re-running, growth and review ----------------------------------------------------------
def test_rerun_is_idempotent_and_an_incident_grows(store, story):
    story.readings(TUE_0300 - timedelta(minutes=5), [4.0] * 5)
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(minutes=3), "S-10")
    first = only(correlate(store)[1])
    assert first["pattern_id"] == "COR-003"

    again, incidents = correlate(store)
    assert again.created == [] and again.updated == [first["incident_id"]]
    assert only(incidents)["incident_id"] == first["incident_id"]

    story.session_change(TUE_0300 + timedelta(minutes=5), "S-10")
    story.warming(TUE_0300 + timedelta(minutes=6))
    grown = only(correlate(store)[1])
    assert grown["incident_id"] == first["incident_id"]
    assert grown["pattern_id"] == "COR-001" and grown["severity"] == "CRITICAL"
    assert grown["record_count"] > first["record_count"]


def test_new_activity_joining_two_incidents_merges_them(store, story):
    # two takeover stories from the same attacker 100 min apart (source IP links span 1 h)
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(minutes=3), "S-11")
    later = TUE_0300 + timedelta(minutes=100)
    story.guesses(later)
    story.session_login(later + timedelta(minutes=3), "S-12")
    first, second = correlate(store)[1]
    # a burst in between connects them: the newer incident is merged into the older one
    story.guesses(TUE_0300 + timedelta(minutes=50))
    summary, incidents = correlate(store)
    assert [i["incident_id"] for i in incidents] == [first["incident_id"]]
    assert summary.merged == [(second["incident_id"], first["incident_id"])]
    merged = store.incident(second["incident_id"])
    assert merged["merged_into"] == first["incident_id"]
    assert len(store.incidents(include_merged=True)) == 2


def test_analyst_review_is_append_only(store, story):
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(minutes=3), "S-13")
    inc = only(correlate(store)[1])
    store.add_incident_review(inc["incident_id"], "anna", "investigating", "unverified", "started")
    store.add_incident_review(
        inc["incident_id"], "anna", "closed", "true_positive", "owner did not log in"
    )
    after = store.incident(inc["incident_id"])
    assert (after["status"], after["verdict"], after["reviewed_by"]) == (
        "closed",
        "true_positive",
        "anna",
    )
    assert [r["status"] for r in store.incident_reviews(inc["incident_id"])] == [
        "investigating",
        "closed",
    ]
    with pytest.raises(ValueError):
        store.add_incident_review(inc["incident_id"], "anna", "closed", "guilty", "x")
    with pytest.raises(KeyError):
        store.add_incident_review("INC-19990101-001", "anna", "open", "unverified", "x")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("DELETE FROM incident_reviews")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE incident_members SET note = 'x'")


# ---- configuration ------------------------------------------------------------------------
def test_shipped_config_loads():
    s = CorrelationSettings.from_config()
    assert [p.id for p in s.patterns] == ["COR-001", "COR-002", "COR-003", "COR-004"]
    assert all(p.response for p in s.patterns)


def test_bad_pattern_reference_is_rejected(tmp_path):
    import shutil

    import yaml

    from fridgeguard.config import CONFIG_DIR

    for f in CONFIG_DIR.glob("*.yaml"):
        shutil.copy(f, tmp_path / f.name)
    cfg = yaml.safe_load((tmp_path / "correlation.yaml").read_text(encoding="utf-8"))
    cfg["patterns"]["COR-003"]["steps"][1]["same"] = {"source_ip": "nowhere"}
    (tmp_path / "correlation.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown step"):
        CorrelationSettings.from_config(tmp_path)


# ---- CLI ---------------------------------------------------------------------------------
def test_cli_correlate_list_show_review(tmp_path, capsys, monkeypatch):
    db = tmp_path / "cli.db"
    s = EventStore(db)
    s.register_devices(Fleet.from_config(random.Random(0)))
    story = Story(s)
    story.guesses(TUE_0300)
    story.session_login(TUE_0300 + timedelta(minutes=3), "S-20")
    s.commit()
    s.close()

    assert main(["detect", "--db", str(db)]) == 0
    assert "incidents:" in capsys.readouterr().out
    assert main(["correlate", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "0 new" in out and "1 updated" in out
    assert main(["incidents", "--db", str(db), "list"]) == 0
    out = capsys.readouterr().out
    inc_id = next(w for w in out.split() if w.startswith("INC-"))
    assert "COR-003" in out
    assert main(["incidents", "--db", str(db), "show", inc_id]) == 0
    out = capsys.readouterr().out
    assert "Brute force followed by a successful login" in out and "timeline" in out
    assert (
        main(
            [
                "incidents",
                "--db",
                str(db),
                "review",
                inc_id,
                "closed",
                "--verdict",
                "false_positive",
                "--note",
                "technician mistyped the password, confirmed by phone",
                "--analyst",
                "anna",
            ]
        )
        == 0
    )
    assert "closed" in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["x"])
    assert main(["incidents", "--db", str(db), "review", inc_id, "closed", "--note", ""]) == 2
