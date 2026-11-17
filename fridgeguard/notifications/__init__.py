"""Notifications for important alerts: console, email, Telegram (Phase 3, Step 13)."""

from fridgeguard.notifications.channels import (
    Channel,
    ConsoleChannel,
    EmailChannel,
    Message,
    NotificationError,
    TelegramChannel,
)
from fridgeguard.notifications.notifier import Notifier, NotifySummary, Settings, build_channels

__all__ = [
    "Channel",
    "ConsoleChannel",
    "EmailChannel",
    "Message",
    "NotificationError",
    "Notifier",
    "NotifySummary",
    "Settings",
    "TelegramChannel",
    "build_channels",
]
