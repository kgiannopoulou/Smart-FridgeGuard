"""Deduplicating notifier (Phase 3, Step 13).

The detector calls :meth:`Notifier.on_alert` for every rule hit: a new alert, or one more
hit on an alert that is still active. Per channel the notifier decides:

=========== ============================================================== ==========
decision    when                                                           status
=========== ============================================================== ==========
new         first notification for the deduplication key                   sent
duplicate   same key within the cooldown, same or lower severity           suppressed
escalated   same key, higher severity than the last notification sent      sent
ongoing     same key after the cooldown: one reminder with the held-back   sent
            count
rate limit  more than ``max_per_hour`` sent on the channel (not CRITICAL)  suppressed
=========== ============================================================== ==========

The key is the correlated incident when the alert belongs to one, otherwise rule +
subject. Every decision is appended to the ``notifications`` table, which is also the
state: re-running detection over the same events, or ``notify run`` over stored alerts,
never sends the same notification twice. A failed delivery is logged and retried by the
next ``notify run``; it never stops detection.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fridgeguard.config import PROJECT_ROOT, load_yaml
from fridgeguard.models import iso_utc
from fridgeguard.notifications.channels import (
    Channel,
    ConsoleChannel,
    EmailChannel,
    Message,
    NotificationError,
    TelegramChannel,
)
from fridgeguard.storage import EventStore
from fridgeguard.storage.store import SEVERITY_LEVELS

OPEN_STATUSES = ("new", "under_investigation")


def _rank(severity: str) -> int:
    return SEVERITY_LEVELS.index(severity)


def _ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Settings:
    enabled: bool
    cooldown: timedelta
    max_per_hour: int
    dashboard_url: str
    tz: ZoneInfo
    devices: dict[str, str]
    channel_specs: dict[str, dict[str, Any]]

    @classmethod
    def from_config(cls, config_dir: Path | None = None) -> Settings:
        cfg = load_yaml("notifications.yaml", config_dir)
        site = load_yaml("devices.yaml", config_dir)
        cooldown = float((cfg.get("dedup") or {}).get("cooldown_s", 3600))
        per_hour = int((cfg.get("rate_limit") or {}).get("max_per_hour", 20))
        if cooldown < 0 or per_hour < 1:
            raise ValueError("cooldown_s must be >= 0 and max_per_hour >= 1")
        unknown = set(cfg.get("channels") or {}) - {"console", "email", "telegram"}
        if unknown:
            raise ValueError(f"unknown notification channel(s): {sorted(unknown)}")
        return cls(
            enabled=bool(cfg.get("enabled", True)),
            cooldown=timedelta(seconds=cooldown),
            max_per_hour=per_hour,
            dashboard_url=str(cfg.get("dashboard_url", "http://localhost:8501")).rstrip("/"),
            tz=ZoneInfo(site["site"]["timezone"]),
            devices={d["device_id"]: d["name"] for d in site["devices"]},
            channel_specs=dict(cfg.get("channels") or {}),
        )


def build_channels(
    specs: Mapping[str, Mapping[str, Any]],
    env: Mapping[str, str] | None = None,
    only: list[str] | None = None,
) -> tuple[list[Channel], list[str]]:
    """Create the enabled channels. Returns (channels, warnings); a channel that cannot be
    configured (e.g. Telegram without a token) is skipped with a warning."""
    env = os.environ if env is None else env
    channels: list[Channel] = []
    warnings: list[str] = []
    for name, spec in specs.items():
        spec = dict(spec or {})
        if only is not None:
            if name not in only:
                continue
        elif not spec.get("enabled", False):
            continue
        severity = str(spec.get("min_severity", "HIGH")).upper()
        try:
            if name == "console":
                channels.append(ConsoleChannel(severity))
            elif name == "email":
                to = env.get("FRIDGEGUARD_SMTP_TO")
                outbox = Path(
                    env.get("FRIDGEGUARD_EMAIL_OUTBOX") or spec.get("outbox_dir", "reports/outbox")
                )
                channels.append(
                    EmailChannel(
                        env.get("FRIDGEGUARD_SMTP_FROM")
                        or spec.get("sender", "fridgeguard@localhost"),
                        [t.strip() for t in to.split(",") if t.strip()]
                        if to
                        else list(spec.get("recipients") or []),
                        min_severity=severity,
                        mode=env.get("FRIDGEGUARD_EMAIL_MODE") or spec.get("mode", "file"),
                        outbox_dir=outbox if outbox.is_absolute() else PROJECT_ROOT / outbox,
                        smtp_host=env.get("FRIDGEGUARD_SMTP_HOST")
                        or spec.get("smtp_host", "localhost"),
                        smtp_port=int(
                            env.get("FRIDGEGUARD_SMTP_PORT") or spec.get("smtp_port", 25)
                        ),
                        starttls=bool(spec.get("starttls", False)),
                        username=env.get("FRIDGEGUARD_SMTP_USER") or None,
                        password=env.get("FRIDGEGUARD_SMTP_PASSWORD") or None,
                        timeout_s=float(spec.get("timeout_s", 10)),
                    )
                )
            elif name == "telegram":
                channels.append(
                    TelegramChannel(
                        env.get("FRIDGEGUARD_TELEGRAM_TOKEN", ""),
                        env.get("FRIDGEGUARD_TELEGRAM_CHAT_ID", ""),
                        min_severity=severity,
                        api_url=spec.get("api_url", "https://api.telegram.org"),
                        timeout_s=float(spec.get("timeout_s", 10)),
                    )
                )
        except ValueError as exc:
            warnings.append(f"{name} disabled: {exc}")
    return channels, warnings


@dataclass
class Decision:
    channel: str
    alert_id: str
    kind: str
    status: str
    reason: str
    notification_id: str


@dataclass
class NotifySummary:
    decisions: list[Decision] = field(default_factory=list)

    def count(self, status: str, channel: str | None = None) -> int:
        return sum(
            d.status == status and (channel is None or d.channel == channel) for d in self.decisions
        )

    def text(self) -> str:
        channels = sorted({d.channel for d in self.decisions})
        if not channels:
            return "nothing to notify"
        parts = [
            f"{c} {self.count('sent', c)} sent / {self.count('suppressed', c)} suppressed"
            + (f" / {self.count('failed', c)} failed" if self.count("failed", c) else "")
            for c in channels
        ]
        return "; ".join(parts)


class Notifier:
    def __init__(self, store: EventStore, channels: list[Channel], settings: Settings):
        self.store = store
        self.channels = channels
        self.s = settings
        self.summary = NotifySummary()

    @classmethod
    def from_config(
        cls,
        store: EventStore,
        config_dir: Path | None = None,
        *,
        env: Mapping[str, str] | None = None,
        channels: list[Channel] | None = None,
    ) -> tuple[Notifier, list[str]]:
        settings = Settings.from_config(config_dir)
        warnings: list[str] = []
        if channels is None:
            channels, warnings = build_channels(settings.channel_specs, env)
        return cls(store, channels if settings.enabled else [], settings), warnings

    # ---- entry points ----------------------------------------------------------------------
    def on_alert(self, alert) -> None:
        """Detector hook (``Detector(on_alert=...)``): one rule hit on ``alert``."""
        self.handle(alert.alert_id, alert.ts)
        if alert.device_id:
            self.check_escalations(alert.device_id, alert.ts)

    def handle(self, alert_id: str, ts: str | datetime) -> list[Decision]:
        """Activity on an alert at ``ts``. Activity already handled is ignored."""
        row = self.store.alert(alert_id)
        if row is None:
            raise KeyError(f"unknown alert {alert_id}")
        when = iso_utc(_ts(ts))
        out = []
        for channel in self.channels:
            if not channel.accepts(row["severity"]):
                continue
            done = self.store.last_notified_ts(channel.name, alert_id)
            if done is not None and when <= done:
                continue
            out.append(self._decide(channel, row, when))
        return out

    def check_escalations(self, device_id: str | None, ts: str | datetime) -> list[Decision]:
        """Re-prioritization can raise an *earlier* alert (e.g. an unauthorized change
        becomes CRITICAL when the fridge warms up). Notify such escalations at once."""
        when = iso_utc(_ts(ts))
        alerts = self.store.alerts(device=device_id) if device_id else self.store.alerts()
        out = []
        for row in alerts:
            if row["status"] not in OPEN_STATUSES:
                continue
            for channel in self.channels:
                notified = self.store.max_notified_severity(channel.name, row["alert_id"])
                if notified < 0 or _rank(row["severity"]) <= notified:
                    continue
                if not channel.accepts(row["severity"]):
                    continue
                done = self.store.last_notified_ts(channel.name, row["alert_id"]) or when
                out.append(self._decide(channel, row, max(when, done)))
        return out

    def process_stored(self) -> NotifySummary:
        """Notify stored alerts that a channel has not handled yet (oldest first), e.g.
        after importing events or after a failed delivery. Then send escalations."""
        for row in sorted(self.store.alerts(), key=lambda r: (r["first_seen"], r["ref"])):
            if row["status"] not in OPEN_STATUSES:
                continue
            for channel in self.channels:
                if not channel.accepts(row["severity"]):
                    continue
                if self.store.last_notified_ts(channel.name, row["alert_id"]) is None:
                    self._decide(channel, row, row["first_seen"])
        self.check_escalations(
            None, max((r["last_seen"] for r in self.store.alerts()), default="0")
        )
        return self.summary

    def send_test(self, channel: Channel) -> Decision:
        """Send a test message through one channel (logged as kind 'test')."""
        now = datetime.now(self.s.tz)
        message = Message(
            "test",
            "INFO",
            "ALR-TEST",
            "TEST",
            "Notification test",
            "Notification test from Smart-FridgeGuard",
            "If you can read this, the channel works. No action needed.",
            "-",
            now,
            self.s.tz,
            f"{self.s.dashboard_url}/",
        )
        return self._deliver(
            channel,
            message,
            {
                "ts": iso_utc(now),
                "alert_id": "ALR-TEST",
                "incident_id": None,
                "dedup_key": "test",
                "kind": "test",
                "severity": "INFO",
            },
        )

    # ---- decision ------------------------------------------------------------------------
    def _key(self, row: dict[str, Any]) -> tuple[str, str | None]:
        incidents = sorted(self.store.incidents_containing([row["alert_id"]]))
        if incidents:
            return f"incident:{incidents[0]}", incidents[0]
        return f"{row['rule_id']}:{row['subject']}", None

    def _decide(self, channel: Channel, row: dict[str, Any], when: str) -> Decision:
        key, incident_id = self._key(row)
        severity = row["severity"]
        base = {
            "ts": when,
            "alert_id": row["alert_id"],
            "incident_id": incident_id,
            "dedup_key": key,
            "severity": severity,
        }
        last = self.store.last_sent_notification(channel.name, key)
        held: list[dict[str, Any]] = []
        previous = None
        if last is None:
            kind = "new"
        elif _rank(severity) > _rank(last["severity"]):
            kind, previous = "escalated", last["severity"]
        elif _ts(when) - _ts(last["ts"]) < self.s.cooldown:
            until = iso_utc(_ts(last["ts"]) + self.s.cooldown)
            return self._record(
                channel,
                {
                    **base,
                    "kind": "ongoing",
                    "status": "suppressed",
                    "reason": f"duplicate of {last['notification_id']} (cooldown until {until})",
                    "subject": row["title"],
                },
            )
        else:
            held = self.store.held_back_since(channel.name, key, last["id"])
            # "ongoing" only while activity is continuous (the last decision for the key is
            # within one cooldown); after a quiet gap it is a new occurrence of the same key
            latest = held[-1]["ts"] if held else last["ts"]
            kind = "ongoing" if _ts(when) - _ts(latest) < self.s.cooldown else "new"

        if severity != "CRITICAL":
            hour_ago = iso_utc(_ts(when) - timedelta(hours=1))
            if self.store.sent_since(channel.name, hour_ago) >= self.s.max_per_hour:
                return self._record(
                    channel,
                    {
                        **base,
                        "kind": kind,
                        "status": "suppressed",
                        "reason": f"rate limit: {self.s.max_per_hour} per hour on {channel.name}",
                        "subject": row["title"],
                    },
                )

        message = Message(
            kind=kind,
            severity=severity,
            alert_id=row["alert_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            title=row["title"],
            description=row["description"],
            device=(
                f"{row['device_id']} {self.s.devices.get(row['device_id'], '')}".strip()
                if row["device_id"]
                else "-"
            ),
            ts=_ts(when),
            tz=self.s.tz,
            link=f"{self.s.dashboard_url}/investigation?alert={row['alert_id']}",
            incident_id=incident_id,
            previous_severity=previous,
            held_back=len(held),
            held_back_alerts=sorted({h["alert_id"] for h in held}),
            since=held[0]["ts"].replace("T", " ")[:16] + " UTC" if held else None,
        )
        return self._deliver(channel, message, {**base, "kind": kind, "held_back": len(held)})

    def _deliver(self, channel: Channel, message: Message, base: dict[str, Any]) -> Decision:
        try:
            note = channel.send(message)
            status = "sent"
        except NotificationError as exc:
            note, status = str(exc), "failed"
        except Exception as exc:  # a broken channel must never stop detection
            note, status = f"{type(exc).__name__}: {exc}", "failed"
        return self._record(
            channel, {**base, "status": status, "reason": note, "subject": message.subject}
        )

    def _record(self, channel: Channel, row: dict[str, Any]) -> Decision:
        nid = self.store.add_notification({"channel": channel.name, **row})
        decision = Decision(
            channel.name, row["alert_id"], row["kind"], row["status"], row["reason"], nid
        )
        self.summary.decisions.append(decision)
        return decision
