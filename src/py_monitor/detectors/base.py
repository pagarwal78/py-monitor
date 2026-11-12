from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any, Callable, ClassVar, Hashable, Iterable, Sequence, TypeVar

from py_monitor.models import EventKind, LogEvent

K = TypeVar("K", bound=Hashable)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


@dataclass
class Anomaly:
    detector: str
    category: str               # "transaction" | "performance" | "reliability"
    severity: Severity
    entity: str                 # what misbehaved: an account, a service, an operation
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[LogEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity.label,
            "entity": self.entity,
            "title": self.title,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "metrics": {k: (str(v) if not isinstance(v, (int, float, bool, type(None))) else v)
                        for k, v in self.metrics.items()},
            "evidence": [e.to_dict() for e in self.evidence],
        }


class Detector(ABC):
    name: ClassVar[str]
    category: ClassVar[str]
    summary: ClassVar[str]

    @abstractmethod
    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        """Inspect time-sorted events and return any anomalies found."""


# ---------------------------------------------------------------- shared helpers
def group_by(events: Iterable[LogEvent], key: Callable[[LogEvent], K]) -> dict[K, list[LogEvent]]:
    groups: dict[K, list[LogEvent]] = defaultdict(list)
    for e in events:
        groups[key(e)].append(e)
    for evs in groups.values():
        evs.sort(key=lambda e: e.timestamp)
    return dict(groups)


def transactions(events: Iterable[LogEvent]) -> list[LogEvent]:
    return [e for e in events if e.is_transaction]


def requests(events: Iterable[LogEvent]) -> list[LogEvent]:
    return [e for e in events if e.kind is EventKind.REQUEST]


def sliding_bursts(
    events: Sequence[LogEvent],
    window: timedelta,
    qualifies: Callable[[Sequence[LogEvent]], bool],
) -> list[list[LogEvent]]:
    """Find maximal runs of time-sorted events where some ``window``-long slice qualifies.

    Overlapping qualifying windows are merged, so one burst = one anomaly.
    """
    bursts: list[tuple[int, int]] = []
    left = 0
    for right in range(len(events)):
        while events[right].timestamp - events[left].timestamp > window:
            left += 1
        if qualifies(events[left:right + 1]):
            if bursts and left <= bursts[-1][1]:
                bursts[-1] = (bursts[-1][0], right)
            else:
                bursts.append((left, right))
    return [list(events[s:e + 1]) for s, e in bursts]


def bucket_start(ts: datetime, bucket: timedelta) -> datetime:
    return EPOCH + ((ts - EPOCH) // bucket) * bucket


def bucketize(events: Iterable[LogEvent], bucket: timedelta) -> dict[datetime, list[LogEvent]]:
    return group_by(events, lambda e: bucket_start(e.timestamp, bucket))


def consecutive_runs(starts: Iterable[datetime], bucket: timedelta) -> list[list[datetime]]:
    runs: list[list[datetime]] = []
    for s in sorted(starts):
        if runs and s - runs[-1][-1] == bucket:
            runs[-1].append(s)
        else:
            runs.append([s])
    return runs


def human_span(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"
