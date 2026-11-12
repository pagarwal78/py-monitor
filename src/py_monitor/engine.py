"""Pulls events from every source, de-duplicates them and runs the detectors."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from py_monitor.connectors.base import LogSource
from py_monitor.detectors.base import Anomaly, Detector, Severity
from py_monitor.models import LogEvent

log = logging.getLogger(__name__)


@dataclass
class SourceResult:
    name: str
    event_count: int
    error: str | None = None


@dataclass
class AnalysisReport:
    window_start: datetime
    window_end: datetime
    generated_at: datetime
    sources: list[SourceResult]
    total_events: int
    transaction_count: int
    anomalies: list[Anomaly]
    detector_errors: dict[str, str] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(a.severity for a in self.anomalies)
        return {s.label: counts.get(s, 0) for s in sorted(Severity, reverse=True)}

    @property
    def max_severity(self) -> Severity | None:
        return max((a.severity for a in self.anomalies), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "generated_at": self.generated_at.isoformat(),
            "sources": [vars(s) for s in self.sources],
            "total_events": self.total_events,
            "transaction_count": self.transaction_count,
            "severity_counts": self.severity_counts(),
            "detector_errors": self.detector_errors,
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


def deduplicate_transactions(events: Iterable[LogEvent]) -> list[LogEvent]:
    """A transfer logged by both clouds is one transfer: keep the earliest copy.

    Without this, every transfer would be counted twice and velocity /
    repeat-amount rules would fire on ordinary behaviour.
    """
    out: list[LogEvent] = []
    seen: dict[str, int] = {}
    for e in sorted(events, key=lambda e: e.timestamp):
        if not (e.is_transaction and e.transaction_id):
            out.append(e)
            continue
        if e.transaction_id in seen:
            idx = seen[e.transaction_id]
            first = out[idx]
            sources = sorted(set(first.attributes.get("seen_in", [first.source.value])) | {e.source.value})
            out[idx] = replace(first, attributes={**first.attributes, "seen_in": sources})
        else:
            seen[e.transaction_id] = len(out)
            out.append(replace(e, attributes={**e.attributes, "seen_in": [e.source.value]}))
    return out


class MonitorEngine:
    def __init__(self, sources: Sequence[LogSource], detectors: Sequence[Detector]) -> None:
        self.sources = list(sources)
        self.detectors = list(detectors)

    def collect(self, start: datetime, end: datetime) -> tuple[list[LogEvent], list[SourceResult]]:
        events: list[LogEvent] = []
        results: list[SourceResult] = []
        for source in self.sources:
            try:
                fetched = source.fetch(start, end)
            except Exception as exc:  # one broken source must not blind the others
                log.exception("Source %s failed", source.name)
                results.append(SourceResult(source.name, 0, f"{type(exc).__name__}: {exc}"))
                continue
            events.extend(fetched)
            results.append(SourceResult(source.name, len(fetched)))
        return deduplicate_transactions(events), results

    def analyse(self, events: Sequence[LogEvent]) -> tuple[list[Anomaly], dict[str, str]]:
        anomalies: list[Anomaly] = []
        errors: dict[str, str] = {}
        for detector in self.detectors:
            try:
                anomalies.extend(detector.detect(events))
            except Exception as exc:
                log.exception("Detector %s failed", detector.name)
                errors[detector.name] = f"{type(exc).__name__}: {exc}"
        anomalies.sort(key=lambda a: (-a.severity, a.first_seen))
        return anomalies, errors

    def run(self, start: datetime, end: datetime) -> AnalysisReport:
        events, results = self.collect(start, end)
        anomalies, errors = self.analyse(events)
        return AnalysisReport(
            window_start=start, window_end=end, generated_at=datetime.now(timezone.utc),
            sources=results, total_events=len(events),
            transaction_count=sum(e.is_transaction for e in events),
            anomalies=anomalies, detector_errors=errors,
        )
