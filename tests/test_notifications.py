"""Step 13: notifications (console, email, Telegram) and their deduplication."""

import io
import json
import random
import socketserver
import threading
import urllib.error
from dataclasses import replace
from datetime import timedelta
from email import message_from_bytes

import pytest

from fridgeguard.__main__ import main
from fridgeguard.config import load_dotenv
from fridgeguard.detection import Correlator, Detector
from fridgeguard.notifications import (
    Channel,
    ConsoleChannel,
    EmailChannel,
    NotificationError,
    Notifier,
    Settings,
    TelegramChannel,
    build_channels,
)
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.storage import EventStore
from tests.test_correlation import Story
from tests.test_detection import TUE_0300


class Recorder(Channel):
    """Test channel: remembers what it was asked to send, can be told to fail."""

    def __init__(self, name="rec", min_severity="LOW", fail=False):
        super().__init__(min_severity)
        self.name = name
        self.sent = []
        self.fail = fail

    def send(self, message):
        if self.fail:
            raise NotificationError("server down")
        self.sent.append(message)
        return "recorded"


@pytest.fixture(scope="module")
def settings():
    return Settings.from_config()


@pytest.fixture
def store(tmp_path):
    s = EventStore(tmp_path / "ntf.db")
    s.register_devices(Fleet.from_config(random.Random(0)))
    yield s
    s.close()


def brute_force(store, start=TUE_0300):
    """Seven failed logins from one IP: DET-002 fires on the 5th, 6th and 7th attempt."""
    s = Story(store)
    s.guesses(
        start,
        names=("admin", "root", "technician", "maintenance_tech", "service", "guest", "operator"),
    )
    store.commit()


def det002(store):
    return [a for a in store.alerts() if a["rule_id"] == "DET-002"]


# ---- deduplication ------------------------------------------------------------------------
def test_ongoing_brute_force_sends_one_notification(store, settings):
    rec = Recorder()
    notifier = Notifier(store, [rec], settings)
    brute_force(store)
    Detector.from_config(store, on_alert=notifier.on_alert).run()
    assert len(det002(store)) == 1
    assert [m.kind for m in rec.sent] == ["new"]
    log = store.notifications()
    assert [r["status"] for r in log] == ["sent", "suppressed", "suppressed"]
    assert log[1]["reason"].startswith(f"duplicate of {log[0]['notification_id']}")
    assert log[0]["dedup_key"] == "DET-002:203.0.113.50"


def test_cooldown_reminder_counts_held_back_then_quiet_gap_is_new(store, settings):
    brute_force(store)
    Detector.from_config(store).run()
    alert = det002(store)[0]["alert_id"]
    rec = Recorder()
    notifier = Notifier(store, [rec], settings)  # cooldown 1 h
    t0 = TUE_0300 + timedelta(minutes=2)
    for minutes in (0, 10, 20):
        notifier.handle(alert, t0 + timedelta(minutes=minutes))
    assert len(rec.sent) == 1
    notifier.handle(alert, t0 + timedelta(minutes=61))  # still active, cooldown over
    assert rec.sent[-1].kind == "ongoing" and rec.sent[-1].held_back == 2
    notifier.handle(alert, t0 + timedelta(hours=5))  # after a quiet gap
    assert rec.sent[-1].kind == "new" and rec.sent[-1].held_back == 0


def test_escalation_is_sent_during_the_cooldown(store, settings):
    brute_force(store)
    Detector.from_config(store).run()
    alert = det002(store)[0]["alert_id"]
    rec = Recorder()
    notifier = Notifier(store, [rec], settings)
    notifier.handle(alert, TUE_0300 + timedelta(minutes=2))
    store.set_alert_severity(alert, "CRITICAL", "anna", "same IP hit another store")
    sent = notifier.check_escalations(None, TUE_0300 + timedelta(minutes=5))
    assert [d.kind for d in sent] == ["escalated"] and sent[0].status == "sent"
    assert rec.sent[-1].headline.startswith("ESCALATED HIGH -> CRITICAL")
    assert notifier.check_escalations(None, TUE_0300 + timedelta(minutes=6)) == []


def test_rate_limit_but_critical_always_goes_through(store, settings):
    s = Story(store)  # one Story: its RNG gives each event a unique source ID
    for i in range(3):  # three separate bursts from different IPs -> three keys
        for j in range(5):
            s.failure(TUE_0300 + timedelta(minutes=10 * i, seconds=10 * j), ip=f"198.51.100.{i}")
    store.commit()
    Detector.from_config(store).run()
    rec = Recorder()
    notifier = Notifier(store, [rec], replace(settings, max_per_hour=2))
    ids = [a["alert_id"] for a in det002(store)]
    for i, alert in enumerate(ids):
        notifier.handle(alert, TUE_0300 + timedelta(minutes=10 * i + 1))
    assert len(rec.sent) == 2
    assert store.notifications(status="suppressed")[0]["reason"].startswith("rate limit")
    store.set_alert_severity(ids[2], "CRITICAL", "anna", "escalate")
    notifier.handle(ids[2], TUE_0300 + timedelta(minutes=30))
    assert rec.sent[-1].severity == "CRITICAL"


def test_severity_threshold_per_channel(store, settings):
    brute_force(store)
    Detector.from_config(store).run()
    alert = det002(store)[0]["alert_id"]  # HIGH
    low, critical = Recorder("low", "LOW"), Recorder("crit", "CRITICAL")
    Notifier(store, [low, critical], settings).handle(alert, TUE_0300 + timedelta(minutes=2))
    assert len(low.sent) == 1 and critical.sent == []
    assert store.notifications(channel="crit") == []  # below threshold: not even logged


def test_reruns_never_notify_twice(store, settings):
    rec = Recorder()
    brute_force(store)
    Detector.from_config(store, on_alert=Notifier(store, [rec], settings).on_alert).run()
    rows = len(store.notifications())
    again = Notifier(store, [rec], settings)
    Detector.from_config(store, on_alert=again.on_alert).run()  # same events again
    again.process_stored()
    assert len(store.notifications()) == rows and len(rec.sent) == 1


def test_failed_delivery_is_logged_and_retried(store, settings):
    brute_force(store)
    broken = Recorder(fail=True)
    Detector.from_config(store, on_alert=Notifier(store, [broken], settings).on_alert).run()
    assert {r["status"] for r in store.notifications()} == {"failed"}
    assert store.alerts()  # detection was not interrupted
    fixed = Recorder()
    summary = Notifier(store, [fixed], settings).process_stored()
    assert summary.count("sent") == 1 and fixed.sent[0].alert_id == det002(store)[0]["alert_id"]


def test_correlated_alerts_share_the_incident_key(store, settings):
    s = Story(store)
    s.readings(TUE_0300 - timedelta(minutes=10), [4.0] * 10)
    s.guesses(TUE_0300)
    s.session_login(TUE_0300 + timedelta(minutes=3), "S-77")
    s.session_change(TUE_0300 + timedelta(minutes=5), "S-77")
    s.warming(TUE_0300 + timedelta(minutes=6))
    store.commit()
    Detector.from_config(store).run()
    Correlator.from_config(store).run()
    rec = Recorder()
    Notifier(store, [rec], settings).process_stored()
    keys = {r["dedup_key"] for r in store.notifications()}
    assert len(keys) == 1 and keys.pop().startswith("incident:INC-")
    assert len(rec.sent) == 1  # one incident, one notification (the rest held back)
    assert rec.sent[0].incident_id


def test_notifications_are_append_only(store, settings):
    brute_force(store)
    Detector.from_config(store, on_alert=Notifier(store, [Recorder()], settings).on_alert).run()
    with pytest.raises(Exception, match="append-only"):
        store.conn.execute("DELETE FROM notifications")


# ---- channels -----------------------------------------------------------------------------
def message(store, settings):
    brute_force(store)
    Detector.from_config(store).run()
    rec = Recorder()
    Notifier(store, [rec], settings).handle(det002(store)[0]["alert_id"], TUE_0300)
    return rec.sent[0]


def test_console_line(store, settings):
    out = io.StringIO()
    ConsoleChannel("LOW", stream=out).send(message(store, settings))
    line = out.getvalue()
    assert line.startswith("🔔 NOTIFY 2026-11-17 01:00:00Z 🟠 HIGH") and "ALR-000001" in line


def test_email_file_mode_writes_eml(store, settings, tmp_path):
    msg = message(store, settings)
    channel = EmailChannel("fg@store.example", ["soc@store.example"], outbox_dir=tmp_path)
    note = channel.send(msg)
    path = next(tmp_path.glob("*.eml"))
    assert path.name == "20261117T010000-ALR-000001-new.eml" and "written" in note
    mail = message_from_bytes(path.read_bytes())
    assert mail["Subject"].startswith("[FridgeGuard] HIGH ALR-000001")
    assert mail["X-FridgeGuard-Alert"] == "ALR-000001"
    body = mail.get_payload(decode=True).decode()
    assert "investigation?alert=ALR-000001" in body and "203.0.113.50" in body


class FakeSMTP(socketserver.StreamRequestHandler):
    """Minimal SMTP server on a real socket: enough for smtplib.send_message."""

    received: list[bytes] = []

    def reply(self, line):
        self.wfile.write(line.encode() + b"\r\n")

    def handle(self):
        self.reply("220 fake ESMTP")
        while line := self.rfile.readline():
            cmd = line.decode().strip().upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.reply("250 fake")
            elif cmd == "DATA":
                self.reply("354 end with .")
                data = b""
                while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                    data += chunk
                FakeSMTP.received.append(data)
                self.reply("250 queued")
            elif cmd == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("250 OK")


def test_email_smtp_mode_delivers_over_a_socket(store, settings):
    FakeSMTP.received = []
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeSMTP) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        channel = EmailChannel(
            "fg@store.example",
            ["soc@store.example"],
            mode="smtp",
            smtp_host="127.0.0.1",
            smtp_port=port,
        )
        note = channel.send(message(store, settings))
        server.shutdown()
    assert note == f"sent via 127.0.0.1:{port} to 1 recipient(s)"
    assert b"Subject: [FridgeGuard] HIGH ALR-000001" in FakeSMTP.received[0]


def test_email_smtp_failure_hides_the_password(store, settings):
    channel = EmailChannel(
        "fg@x",
        ["soc@x"],
        mode="smtp",
        smtp_host="127.0.0.1",
        smtp_port=1,
        username="u",
        password="s3cret-pass",
        timeout_s=2,
    )
    with pytest.raises(NotificationError) as err:
        channel.send(message(store, settings))
    assert "127.0.0.1:1" in str(err.value) and "s3cret-pass" not in str(err.value)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_telegram_sends_html_message(store, settings, monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        return FakeResponse(json.dumps({"ok": True, "result": {"message_id": 42}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    channel = TelegramChannel("123:ABC-token", "-1001", api_url="https://tg.example")
    assert channel.send(message(store, settings)) == "telegram message 42"
    request = calls[0]
    assert request.full_url == "https://tg.example/bot123:ABC-token/sendMessage"
    body = json.loads(request.data)
    assert body["chat_id"] == "-1001" and body["parse_mode"] == "HTML"
    assert body["text"].startswith("<b>HIGH · 5 failed logins")
    assert "investigation?alert=ALR-000001" in body["text"]


def test_telegram_error_never_contains_the_token(store, settings, monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError(f"cannot reach {request.full_url}")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    channel = TelegramChannel("123:SECRET", "-1001")
    with pytest.raises(NotificationError) as err:
        channel.send(message(store, settings))
    assert "SECRET" not in str(err.value) and "***" in str(err.value)


def test_build_channels_from_config_and_environment(settings, tmp_path):
    env = {
        "FRIDGEGUARD_SMTP_TO": "a@x, b@x",
        "FRIDGEGUARD_EMAIL_MODE": "smtp",
        "FRIDGEGUARD_SMTP_PORT": "2525",
    }
    channels, warnings = build_channels(settings.channel_specs, env)
    by_name = {c.name: c for c in channels}
    assert set(by_name) == {"console", "email"}  # telegram is opt-in
    email = by_name["email"]
    assert (email.recipients, email.mode, email.smtp_port) == (["a@x", "b@x"], "smtp", 2525)
    specs = {**settings.channel_specs, "telegram": {"enabled": True}}
    channels, warnings = build_channels(specs, {})
    assert "telegram" not in {c.name for c in channels}
    assert warnings == ["telegram disabled: telegram needs a bot token and a chat ID"]


def test_dotenv_does_not_override_the_environment(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nA=1\nB='two # kept'\nexport C=3   # note\nD=      # empty\n",
        encoding="utf-8",
    )
    env = {"A": "set"}
    assert load_dotenv(env_file, env) == ["B", "C", "D"]
    assert env == {"A": "set", "B": "two # kept", "C": "3", "D": ""}


# ---- CLI ----------------------------------------------------------------------------------
def test_cli_detect_notify_list_and_channels(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("FRIDGEGUARD_SMTP_PASSWORD", "hunter2-secret")
    monkeypatch.setenv("FRIDGEGUARD_SMTP_TO", "soc@x")
    db = tmp_path / "cli.db"
    s = EventStore(db)
    s.register_devices(Fleet.from_config(random.Random(0)))
    brute_force(s)
    s.close()
    monkeypatch.setenv("FRIDGEGUARD_EMAIL_OUTBOX", str(tmp_path / "outbox"))
    assert main(["detect", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "🔔 NOTIFY" in out and "notify:     console 1 sent / 2 suppressed" in out
    assert len(list((tmp_path / "outbox").glob("*.eml"))) == 1
    assert main(["notify", "--db", str(db), "run"]) == 0
    assert "nothing to notify" in capsys.readouterr().out
    assert main(["notify", "--db", str(db), "list", "--status", "suppressed"]) == 0
    assert "(4 notifications)" in capsys.readouterr().out  # 2 console + 2 email
    assert main(["notify", "--db", str(db), "channels"]) == 0
    out = capsys.readouterr().out
    assert "password (set)" in out and "hunter2" not in out
    assert main(["notify", "--db", str(db), "test", "console"]) == 0
    assert "console test sent" in capsys.readouterr().out
    assert main(["detect", "--db", str(db), "--no-notify"]) == 0
    assert "🔔" not in capsys.readouterr().out


def test_sustained_attack_does_not_flood(store, settings):
    """300 failed logins over 2.5 hours from one IP: hundreds of rule hits, a handful
    of notifications (first one, then one reminder per cooldown hour)."""
    s = Story(store)
    for i in range(300):
        s.failure(TUE_0300 + timedelta(seconds=30 * i), ip="203.0.113.99", user=f"user{i % 7}")
    store.commit()
    rec = Recorder()
    notifier = Notifier(store, [rec], settings)
    summary = Detector.from_config(store, on_alert=notifier.on_alert).run()
    assert summary.hits >= 290
    assert [m.kind for m in rec.sent] == ["new", "ongoing", "ongoing"]
    assert [m.held_back for m in rec.sent] == [0, 119, 119]
    assert notifier.summary.count("suppressed") == summary.hits - 3
