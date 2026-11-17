"""Notification channels (Phase 3, Step 13): console, email and Telegram.

A channel only delivers a :class:`Message`. Whether a message is sent at all
(severity threshold, deduplication, rate limit) is decided by the
:class:`~fridgeguard.notifications.notifier.Notifier`.

Secrets come from the environment (or ``.env``), never from YAML or logs: the SMTP
password and the Telegram bot token are not part of any error message.
"""

from __future__ import annotations

import html
import json
import smtplib
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path
from typing import Any, TextIO
from zoneinfo import ZoneInfo

from fridgeguard.storage.store import SEVERITY_LEVELS


class NotificationError(Exception):
    """A channel could not deliver a message."""


@dataclass
class Message:
    kind: str  # new | escalated | ongoing | test
    severity: str
    alert_id: str
    rule_id: str
    rule_name: str
    title: str
    description: str
    device: str
    ts: datetime
    tz: ZoneInfo
    link: str
    incident_id: str | None = None
    previous_severity: str | None = None
    held_back: int = 0
    held_back_alerts: list[str] = field(default_factory=list)
    since: str | None = None

    @property
    def headline(self) -> str:
        prefix = {
            "new": "",
            "escalated": f"ESCALATED {self.previous_severity} -> {self.severity}: ",
            "ongoing": "STILL ONGOING: ",
            "test": "TEST: ",
        }[self.kind]
        return f"{prefix}{self.title}"

    @property
    def subject(self) -> str:
        return f"[FridgeGuard] {self.severity} {self.alert_id} {self.headline}"

    def when(self) -> str:
        return (
            f"{self.ts:%Y-%m-%d %H:%M:%S} UTC "
            f"({self.ts.astimezone(self.tz):%a %H:%M} {self.tz.key})"
        )

    def facts(self) -> list[tuple[str, str]]:
        rows = [
            ("Severity", self.severity),
            ("Alert", f"{self.alert_id} - {self.rule_id} {self.rule_name}"),
            ("Fridge", self.device),
            ("Time", self.when()),
        ]
        if self.incident_id:
            rows.append(("Incident", self.incident_id))
        if self.held_back:
            alerts = ", ".join(self.held_back_alerts)
            rows.append(
                (
                    "Held back",
                    f"{self.held_back} similar notification(s) since {self.since}"
                    + (f" ({alerts})" if alerts else ""),
                )
            )
        return rows

    def text(self) -> str:
        width = max(len(k) for k, _ in self.facts())
        lines = [self.headline, "", self.description, ""]
        lines += [f"{k + ':':<{width + 1}} {v}" for k, v in self.facts()]
        lines += [
            "",
            f"Investigate: {self.link}",
            f"CLI:         python -m fridgeguard investigate start {self.alert_id}",
            "",
            "Smart-FridgeGuard (simulated data). Further identical alerts are held back "
            "for the cooldown period; escalations are sent at once.",
        ]
        return "\n".join(lines)


class Channel:
    name = "channel"

    def __init__(self, min_severity: str = "HIGH"):
        if min_severity not in SEVERITY_LEVELS:
            raise ValueError(f"{self.name}: min_severity must be one of {SEVERITY_LEVELS}")
        self.min_severity = min_severity

    def accepts(self, severity: str) -> bool:
        return SEVERITY_LEVELS.index(severity) >= SEVERITY_LEVELS.index(self.min_severity)

    def send(self, message: Message) -> str:  # pragma: no cover - interface
        """Deliver the message. Returns a short delivery note; raises NotificationError."""
        raise NotImplementedError


# ---- console --------------------------------------------------------------------------------
class ConsoleChannel(Channel):
    name = "console"
    ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    def __init__(self, min_severity: str = "MEDIUM", stream: TextIO | None = None):
        super().__init__(min_severity)
        self.stream = stream

    def send(self, message: Message) -> str:
        out = self.stream or sys.stdout
        icon = self.ICONS.get(message.severity, "")
        line = (
            f"🔔 NOTIFY {message.ts:%Y-%m-%d %H:%M:%SZ} {icon} {message.severity:<8} "
            f"{message.alert_id} {message.headline}"
        )
        if message.held_back:
            line += f"  [+{message.held_back} held back since {message.since}]"
        print(line, file=out, flush=True)
        return "printed"


# ---- email ----------------------------------------------------------------------------------
class EmailChannel(Channel):
    name = "email"

    def __init__(
        self,
        sender: str,
        recipients: list[str],
        *,
        min_severity: str = "HIGH",
        mode: str = "file",
        outbox_dir: Path | None = None,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        starttls: bool = False,
        username: str | None = None,
        password: str | None = None,
        timeout_s: float = 10,
    ):
        super().__init__(min_severity)
        if mode not in ("file", "smtp"):
            raise ValueError("email mode must be 'file' or 'smtp'")
        if not recipients:
            raise ValueError("email needs at least one recipient")
        if mode == "file" and outbox_dir is None:
            raise ValueError("email mode 'file' needs outbox_dir")
        self.sender, self.recipients, self.mode = sender, list(recipients), mode
        self.outbox_dir = Path(outbox_dir) if outbox_dir else None
        self.smtp_host, self.smtp_port, self.starttls = smtp_host, int(smtp_port), starttls
        self.username, self._password, self.timeout_s = username, password, timeout_s

    def build(self, message: Message) -> EmailMessage:
        mail = EmailMessage()
        mail["Subject"] = message.subject
        mail["From"] = self.sender
        mail["To"] = ", ".join(self.recipients)
        mail["Date"] = format_datetime(message.ts)
        mail["Message-ID"] = make_msgid(domain="fridgeguard.local")
        mail["X-FridgeGuard-Alert"] = message.alert_id
        mail["X-FridgeGuard-Severity"] = message.severity
        if message.severity == "CRITICAL":
            mail["X-Priority"] = "1"
        mail.set_content(message.text())
        return mail

    def send(self, message: Message) -> str:
        mail = self.build(message)
        if self.mode == "file":
            self.outbox_dir.mkdir(parents=True, exist_ok=True)
            name = f"{message.ts:%Y%m%dT%H%M%S}-{message.alert_id}-{message.kind}.eml"
            path = self.outbox_dir / name
            path.write_bytes(bytes(mail))
            try:
                shown = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
            except ValueError:
                shown = f"{path.parent.name}/{path.name}"  # never log a home directory
            return f"written to {shown}"
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout_s) as smtp:
                if self.starttls:
                    smtp.starttls()
                if self.username:
                    smtp.login(self.username, self._password or "")
                smtp.send_message(mail)
        except (OSError, smtplib.SMTPException) as exc:
            # str(exc) never contains the password; the host and port are fine to show
            raise NotificationError(
                f"SMTP {self.smtp_host}:{self.smtp_port} failed: {type(exc).__name__}: {exc}"
            ) from None
        return f"sent via {self.smtp_host}:{self.smtp_port} to {len(self.recipients)} recipient(s)"


# ---- Telegram -------------------------------------------------------------------------------
class TelegramChannel(Channel):
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        min_severity: str = "HIGH",
        api_url: str = "https://api.telegram.org",
        timeout_s: float = 10,
    ):
        super().__init__(min_severity)
        if not token or not chat_id:
            raise ValueError("telegram needs a bot token and a chat ID")
        self._token, self.chat_id = token, str(chat_id)
        self.api_url, self.timeout_s = api_url.rstrip("/"), timeout_s

    def payload(self, message: Message) -> dict[str, Any]:
        e = html.escape
        lines = [
            f"<b>{e(message.severity)} · {e(message.headline)}</b>",
            e(message.description),
            "",
        ]
        lines += [f"<b>{e(k)}:</b> {e(v)}" for k, v in message.facts()]
        lines.append(
            f'\n<a href="{e(message.link, quote=True)}">Investigate {e(message.alert_id)}</a>'
        )
        return {
            "chat_id": self.chat_id,
            "text": "\n".join(lines)[:4096],  # Telegram message limit
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

    def _redact(self, text: str) -> str:
        return text.replace(self._token, "***") if self._token else text

    def send(self, message: Message) -> str:
        request = urllib.request.Request(
            f"{self.api_url}/bot{self._token}/sendMessage",
            data=json.dumps(self.payload(message)).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                body = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise NotificationError(self._redact(f"Telegram HTTP {exc.code}: {detail}")) from None
        except (OSError, ValueError) as exc:
            raise NotificationError(self._redact(f"Telegram failed: {exc}")) from None
        if not body.get("ok"):
            raise NotificationError(self._redact(f"Telegram refused: {body.get('description')}"))
        return f"telegram message {body.get('result', {}).get('message_id', '?')}"


def mask(value: str | None) -> str:
    """For status output: say whether a secret is set, never show any of it."""
    return "(set)" if value else "(not set)"
