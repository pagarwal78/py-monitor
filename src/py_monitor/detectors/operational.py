"""Operational detectors: latency and error-rate anomalies per service."""

from __future__ import annotations

import statistics
from datetime import timedelta
from typing import Sequence

from py_monitor.detectors.base import (
    Anomaly, Detector, Severity, bucketize, consecutive_runs, group_by, human_span, requests,
)
from py_monitor.models import LogEvent


def _percentile(values: Sequence[float], pct: int) -> float:
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[pct - 1]


class LatencySpikeDetector(Detector):
    """Time buckets where an operation's p-th percentile latency jumps far above its usual level.

    The baseline is the median of the bucket percentiles across the window, so a
    spike lasting less than half the window does not pollute its own baseline.
    """

    name = "latency_spike"
    category = "performance"
    summary = "An operation's latency jumps well above its own baseline"

    def __init__(self, bucket_minutes: float = 5, percentile: int = 90, ratio: float = 3.0,
                 min_samples: int = 5, min_buckets: int = 3, max_evidence: int = 10) -> None:
        self.bucket = timedelta(minutes=bucket_minutes)
        self.percentile = percentile
        self.ratio = ratio
        self.min_samples = min_samples
        self.min_buckets = min_buckets
        self.max_evidence = max_evidence

    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        anomalies = []
        timed = [e for e in requests(events) if e.duration_ms is not None]
        for (service, operation), evs in group_by(timed, lambda e: (e.service, e.operation)).items():
            buckets = {b: es for b, es in bucketize(evs, self.bucket).items() if len(es) >= self.min_samples}
            if len(buckets) < self.min_buckets:
                continue
            stat = {b: _percentile([e.duration_ms for e in es], self.percentile) for b, es in buckets.items()}
            baseline = statistics.median(stat.values())
            if baseline <= 0:
                continue
            flagged = [b for b, v in stat.items() if v >= baseline * self.ratio]
            for run in consecutive_runs(flagged, self.bucket):
                run_events = [e for b in run for e in buckets[b]]
                peak = max(stat[b] for b in run)
                peak_ratio = peak / baseline
                slowest = sorted(run_events, key=lambda e: e.duration_ms or 0, reverse=True)
                anomalies.append(Anomaly(
                    detector=self.name, category=self.category,
                    severity=Severity.HIGH if peak_ratio >= 2 * self.ratio else Severity.MEDIUM,
                    entity=f"{service} :: {operation}",
                    title=f"Latency spike on {operation}",
                    description=(f"p{self.percentile} latency of {service} '{operation}' peaked at "
                                 f"{peak:,.0f} ms vs a baseline of {baseline:,.0f} ms ({peak_ratio:.1f}x) "
                                 f"for {human_span(self.bucket * len(run))}."),
                    first_seen=run[0], last_seen=run[-1] + self.bucket,
                    metrics={"baseline_ms": round(baseline, 1), "peak_ms": round(peak, 1),
                             "peak_ratio": round(peak_ratio, 2), "requests_affected": len(run_events)},
                    evidence=slowest[: self.max_evidence],
                ))
        return anomalies


class ErrorRateDetector(Detector):
    """Time buckets where a service's failure rate is well above its normal rate."""

    name = "error_rate"
    category = "reliability"
    summary = "A service's failure rate rises well above its baseline"

    def __init__(self, bucket_minutes: float = 5, min_requests: int = 20, min_error_rate: float = 0.10,
                 multiplier: float = 5.0, max_evidence: int = 10) -> None:
        self.bucket = timedelta(minutes=bucket_minutes)
        self.min_requests = min_requests
        self.min_error_rate = min_error_rate
        self.multiplier = multiplier
        self.max_evidence = max_evidence

    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        anomalies = []
        for service, evs in group_by(requests(events), lambda e: e.service).items():
            buckets = {b: es for b, es in bucketize(evs, self.bucket).items() if len(es) >= self.min_requests}
            if not buckets:
                continue
            rate = {b: sum(not e.success for e in es) / len(es) for b, es in buckets.items()}
            baseline = statistics.median(rate.values())
            limit = max(self.min_error_rate, baseline * self.multiplier)
            flagged = [b for b, r in rate.items() if r >= limit]
            for run in consecutive_runs(flagged, self.bucket):
                run_events = [e for b in run for e in buckets[b]]
                failures = [e for e in run_events if not e.success]
                overall = len(failures) / len(run_events)
                peak = max(rate[b] for b in run)
                severity = (Severity.CRITICAL if peak >= 0.5
                            else Severity.HIGH if peak >= 2 * limit else Severity.MEDIUM)
                codes = sorted({str(e.status_code) for e in failures if e.status_code})
                anomalies.append(Anomaly(
                    detector=self.name, category=self.category, severity=severity, entity=service,
                    title=f"Error-rate spike on {service}",
                    description=(f"{len(failures)} of {len(run_events)} requests failed ({overall:.0%}, peak "
                                 f"{peak:.0%}) vs a baseline of {baseline:.1%} over "
                                 f"{human_span(self.bucket * len(run))}. Status codes: {', '.join(codes) or 'n/a'}."),
                    first_seen=run[0], last_seen=run[-1] + self.bucket,
                    metrics={"baseline_rate": round(baseline, 4), "peak_rate": round(peak, 4),
                             "failed": len(failures), "total": len(run_events)},
                    evidence=failures[: self.max_evidence],
                ))
        return anomalies
