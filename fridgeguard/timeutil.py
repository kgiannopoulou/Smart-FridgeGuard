"""Time helpers: parsing config times and checking local-time windows."""

from __future__ import annotations

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def parse_hhmm(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


def parse_utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp; naive values are treated as UTC."""
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


class TimeWindow:
    """A daily local-time window, optionally limited to some weekdays.

    ``end`` before ``start`` means the window crosses midnight.
    """

    def __init__(self, start: str, end: str, tz: ZoneInfo, days: list[str] | None = None):
        self.start = parse_hhmm(start)
        self.end = parse_hhmm(end)
        self.tz = tz
        self.days = {WEEKDAYS.index(d.lower()[:3]) for d in days} if days else set(range(7))

    def contains(self, ts: datetime) -> bool:
        local = ts.astimezone(self.tz)
        if local.weekday() not in self.days:
            return False
        t = local.time()
        if self.start <= self.end:
            return self.start <= t < self.end
        return t >= self.start or t < self.end
