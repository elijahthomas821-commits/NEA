"""Time helpers. Everything is stored in UTC; display uses the configured zone (Europe/London)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Protocol
from zoneinfo import ZoneInfo

DISPLAY_TZ = ZoneInfo("Europe/London")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return utcnow()


class FixedClock:
    """A controllable clock for tests and reproducible re-evaluations."""

    def __init__(self, at: datetime) -> None:
        self._at = ensure_aware(at)

    def now(self) -> datetime:
        return self._at

    def advance(self, delta: timedelta) -> None:
        self._at = self._at + delta


def ensure_aware(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime; naive values are assumed to be UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def to_display(value: datetime, tz: ZoneInfo = DISPLAY_TZ) -> datetime:
    return ensure_aware(value).astimezone(tz)


def days_between(start: datetime | date, end: datetime | date) -> int:
    """Whole calendar days from ``start`` to ``end`` (UTC dates)."""
    start_date = ensure_aware(start).date() if isinstance(start, datetime) else start
    end_date = ensure_aware(end).date() if isinstance(end, datetime) else end
    return (end_date - start_date).days


def age_days(then: datetime, now: datetime) -> float:
    """Fractional days elapsed (never negative)."""
    seconds = (ensure_aware(now) - ensure_aware(then)).total_seconds()
    return max(seconds, 0.0) / 86400.0


def humanize_age(then: datetime, now: datetime) -> str:
    """``"just now"``, ``"6 min ago"``, ``"3 h ago"``, ``"2 days ago"``."""
    seconds = max(int((ensure_aware(now) - ensure_aware(then)).total_seconds()), 0)
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} h ago"
    days = hours // 24
    return f"{days} days ago"
