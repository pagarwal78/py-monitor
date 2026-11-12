from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from py_monitor.models import EventKind, LogEvent, Source

T0 = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def txn(seconds: float, account: str = "ACC-1", amount: str = "100.00", payee: str = "P-1",
        currency: str = "GBP", txn_id: str | None = None, source: Source = Source.APP_INSIGHTS) -> LogEvent:
    return LogEvent(
        timestamp=T0 + timedelta(seconds=seconds), source=source, kind=EventKind.TRANSACTION,
        service="api", operation="FundsTransfer", account_id=account, amount=Decimal(amount),
        currency=currency, counterparty=payee, transaction_id=txn_id or f"T-{account}-{seconds}-{amount}",
    )


def req(seconds: float, *, service: str = "svc", operation: str = "GET /x", duration: float = 100,
        success: bool = True) -> LogEvent:
    return LogEvent(
        timestamp=T0 + timedelta(seconds=seconds), source=Source.XRAY, kind=EventKind.REQUEST,
        service=service, operation=operation, duration_ms=duration, success=success,
        status_code=200 if success else 500,
    )
