"""Normalised event model shared by every connector and detector.

Azure Application Insights and AWS X-Ray describe the same things (requests,
outbound calls, exceptions, business events) in very different shapes. Each
connector maps its native payload onto :class:`LogEvent` so detectors never
need to know where an event came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping


class Source(str, Enum):
    APP_INSIGHTS = "azure_appinsights"
    XRAY = "aws_xray"


class EventKind(str, Enum):
    REQUEST = "request"          # inbound call handled by a service
    DEPENDENCY = "dependency"    # outbound call (DB, HTTP, queue...)
    EXCEPTION = "exception"
    TRANSACTION = "transaction"  # business event: a money movement


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    source: Source
    kind: EventKind
    service: str
    operation: str
    trace_id: str | None = None          # W3C 32-hex form, comparable across clouds
    duration_ms: float | None = None
    success: bool = True
    status_code: int | None = None
    # Transaction fields (only set for EventKind.TRANSACTION)
    account_id: str | None = None
    amount: Decimal | None = None
    currency: str | None = None
    counterparty: str | None = None
    transaction_id: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_transaction(self) -> bool:
        return (
            self.kind is EventKind.TRANSACTION
            and self.account_id is not None
            and self.amount is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source.value,
            "kind": self.kind.value,
            "service": self.service,
            "operation": self.operation,
            "trace_id": self.trace_id,
            "duration_ms": self.duration_ms,
            "success": self.success,
            "status_code": self.status_code,
            "account_id": self.account_id,
            "amount": str(self.amount) if self.amount is not None else None,
            "currency": self.currency,
            "counterparty": self.counterparty,
            "transaction_id": self.transaction_id,
            "attributes": dict(self.attributes),
        }


def to_decimal(value: Any) -> Decimal | None:
    """Convert a JSON/KQL number or string to Decimal without float artefacts."""
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value)).quantize(Decimal("0.01"))
    except Exception:
        return None


def xray_to_w3c(trace_id: str | None) -> str | None:
    """``1-5759e988-bd862e3fe1be46a994272793`` -> ``5759e988bd862e3fe1be46a994272793``.

    With OpenTelemetry's X-Ray id generator, the W3C trace id that App Insights
    records and the X-Ray trace id carry the same 128 bits, so normalising lets
    us join a request across Azure and AWS.
    """
    if not trace_id:
        return None
    parts = trace_id.split("-")
    if len(parts) == 3 and parts[0] == "1":
        return (parts[1] + parts[2]).lower()
    return trace_id.lower()
