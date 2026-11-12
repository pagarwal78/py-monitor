"""Transaction-monitoring detectors."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from typing import Sequence

from py_monitor.detectors.base import (
    Anomaly, Detector, Severity, group_by, human_span, sliding_bursts, transactions,
)
from py_monitor.models import LogEvent


def _dec(value: object) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _payee_text(burst: Sequence[LogEvent]) -> tuple[list[str], str]:
    payees = sorted({e.counterparty for e in burst if e.counterparty})
    if len(payees) == 1:
        return payees, f"all to the same payee {payees[0]}"
    return payees, f"to {len(payees)} different payees"


class RapidRepeatTransferDetector(Detector):
    """Same account sending the *same amount* several times in quick succession.

    Typical causes: duplicate submissions / replayed requests (same payee), or a
    compromised account being drained in fixed chunks (many payees).
    """

    name = "rapid_repeat_transfer"
    category = "transaction"
    summary = "Same amount from the same account repeated within a short window"

    def __init__(self, window_minutes: float = 5, min_count: int = 3, high_severity_count: int = 5,
                 high_value_total: float | str = 10_000, max_evidence: int = 20) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.min_count = min_count
        self.high_severity_count = high_severity_count
        self.high_value_total = _dec(high_value_total)
        self.max_evidence = max_evidence

    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        anomalies = []
        groups = group_by(transactions(events), lambda e: (e.account_id, e.amount, e.currency))
        for (account, amount, currency), evs in groups.items():
            for burst in sliding_bursts(evs, self.window, lambda w: len(w) >= self.min_count):
                total = sum((e.amount for e in burst), Decimal("0"))
                span = burst[-1].timestamp - burst[0].timestamp
                payees, payee_text = _payee_text(burst)
                severe = len(burst) >= self.high_severity_count or total >= self.high_value_total
                anomalies.append(Anomaly(
                    detector=self.name, category=self.category,
                    severity=Severity.HIGH if severe else Severity.MEDIUM,
                    entity=account,
                    title=f"Repeated transfer of {amount} {currency or ''}".strip(),
                    description=(f"{len(burst)} transfers of {amount} {currency or ''} from {account} "
                                 f"within {human_span(span)}, {payee_text}. Total {total}."),
                    first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                    metrics={"count": len(burst), "amount": amount, "currency": currency,
                             "total": total, "span_seconds": span.total_seconds(), "payees": ", ".join(payees)},
                    evidence=burst[: self.max_evidence],
                ))
        return anomalies


class VelocityDetector(Detector):
    """Unusually many transfers (or too much value) from one account in a window."""

    name = "transaction_velocity"
    category = "transaction"
    summary = "Too many transfers, or too much value, from one account in a window"

    def __init__(self, window_minutes: float = 10, max_count: int = 10, max_total: float | str = 20_000,
                 max_evidence: int = 20) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_count = max_count
        self.max_total = _dec(max_total)
        self.max_evidence = max_evidence

    def _total(self, w: Sequence[LogEvent]) -> Decimal:
        return sum((e.amount for e in w), Decimal("0"))

    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        anomalies = []
        for (account, currency), evs in group_by(transactions(events), lambda e: (e.account_id, e.currency)).items():
            qualifies = lambda w: len(w) > self.max_count or self._total(w) > self.max_total  # noqa: E731
            for burst in sliding_bursts(evs, self.window, qualifies):
                total = self._total(burst)
                span = burst[-1].timestamp - burst[0].timestamp
                severe = len(burst) >= 2 * self.max_count or total >= 2 * self.max_total
                anomalies.append(Anomaly(
                    detector=self.name, category=self.category,
                    severity=Severity.HIGH if severe else Severity.MEDIUM,
                    entity=account,
                    title=f"High transfer velocity ({len(burst)} transfers)",
                    description=(f"{account} made {len(burst)} transfers totalling {total} {currency or ''} "
                                 f"in {human_span(span)} (limit {self.max_count} transfers or "
                                 f"{self.max_total} per {human_span(self.window)})."),
                    first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                    metrics={"count": len(burst), "total": total, "currency": currency,
                             "distinct_amounts": len({e.amount for e in burst}),
                             "span_seconds": span.total_seconds()},
                    evidence=burst[: self.max_evidence],
                ))
        return anomalies


class StructuringDetector(Detector):
    """Several transfers just below a reporting threshold (a.k.a. smurfing)."""

    name = "structuring"
    category = "transaction"
    summary = "Repeated transfers just under a reporting threshold"

    def __init__(self, threshold: float | str = 10_000, margin_pct: float = 10, window_hours: float = 24,
                 min_count: int = 3, max_evidence: int = 20) -> None:
        self.threshold = _dec(threshold)
        self.floor = (self.threshold * (Decimal(1) - _dec(margin_pct) / Decimal(100))).quantize(self.threshold)
        self.window = timedelta(hours=window_hours)
        self.min_count = min_count
        self.max_evidence = max_evidence

    def detect(self, events: Sequence[LogEvent]) -> list[Anomaly]:
        near = [e for e in transactions(events) if self.floor <= e.amount < self.threshold]
        anomalies = []
        for (account, currency), evs in group_by(near, lambda e: (e.account_id, e.currency)).items():
            for burst in sliding_bursts(evs, self.window, lambda w: len(w) >= self.min_count):
                total = sum((e.amount for e in burst), Decimal("0"))
                span = burst[-1].timestamp - burst[0].timestamp
                anomalies.append(Anomaly(
                    detector=self.name, category=self.category,
                    severity=Severity.CRITICAL if len(burst) >= 2 * self.min_count else Severity.HIGH,
                    entity=account,
                    title=f"Possible structuring below {self.threshold} {currency or ''}".strip(),
                    description=(f"{account} made {len(burst)} transfers between {self.floor} and "
                                 f"{self.threshold} {currency or ''} in {human_span(span)} "
                                 f"(total {total}, which would have been reportable as one transfer)."),
                    first_seen=burst[0].timestamp, last_seen=burst[-1].timestamp,
                    metrics={"count": len(burst), "total": total, "currency": currency,
                             "threshold": self.threshold, "span_seconds": span.total_seconds()},
                    evidence=burst[: self.max_evidence],
                ))
        return anomalies
