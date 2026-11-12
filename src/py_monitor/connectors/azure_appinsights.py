"""Azure Application Insights connector (workspace-based App Insights).

Live mode queries the Log Analytics workspace behind App Insights with
``azure-monitor-query``. Authentication uses ``DefaultAzureCredential`` (az
login, managed identity, or AZURE_CLIENT_ID / AZURE_TENANT_ID /
AZURE_CLIENT_SECRET environment variables).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from py_monitor.connectors import dummy_data
from py_monitor.connectors.base import LogSource, require
from py_monitor.models import EventKind, LogEvent, Source, to_decimal

log = logging.getLogger(__name__)

KQL = """
union AppRequests, AppDependencies, AppExceptions, AppEvents
| project TimeGenerated, Type, Name, OperationId, AppRoleName, DurationMs,
          Success, ResultCode, Properties, ExceptionType, OuterMessage
| order by TimeGenerated asc
"""

TYPE_TO_KIND = {
    "AppRequests": EventKind.REQUEST,
    "AppDependencies": EventKind.DEPENDENCY,
    "AppExceptions": EventKind.EXCEPTION,
    "AppEvents": EventKind.TRANSACTION,
}

# customEvent property names -> LogEvent fields. Adjust to match your telemetry.
DEFAULT_PROPERTY_MAP = {
    "account_id": "accountId",
    "amount": "amount",
    "currency": "currency",
    "counterparty": "beneficiaryId",
    "transaction_id": "transactionId",
}


class AppInsightsSource(LogSource):
    name = Source.APP_INSIGHTS.value

    def __init__(
        self,
        workspace_id: str | None = None,
        *,
        use_dummy: bool = False,
        seed: int = 42,
        transaction_event_names: Iterable[str] = ("FundsTransfer",),
        property_map: Mapping[str, str] | None = None,
        client: Any = None,
    ) -> None:
        self.workspace_id = workspace_id
        self.use_dummy = use_dummy
        self.seed = seed
        self.transaction_event_names = set(transaction_event_names)
        self.property_map = {**DEFAULT_PROPERTY_MAP, **(property_map or {})}
        self._client = client
        if not use_dummy and not workspace_id:
            raise ValueError("workspace_id is required for live App Insights queries")

    def fetch(self, start: datetime, end: datetime) -> list[LogEvent]:
        events = []
        for row in self._fetch_rows(start, end):
            event = parse_row(row, self.transaction_event_names, self.property_map)
            if event is not None and start <= event.timestamp < end:
                events.append(event)
        log.info("App Insights: %d events", len(events))
        return events

    def _fetch_rows(self, start: datetime, end: datetime) -> list[Mapping[str, Any]]:
        if self.use_dummy:
            return dummy_data.appinsights_rows(start, end, self.seed)

        client = self._client or self._build_client()
        response = client.query_workspace(self.workspace_id, KQL, timespan=(start, end))
        tables = getattr(response, "tables", None)
        if tables is None:  # LogsQueryPartialResult
            log.warning("App Insights returned partial results: %s", getattr(response, "partial_error", ""))
            tables = getattr(response, "partial_data", []) or []
        return [dict(zip(table.columns, row)) for table in tables for row in table.rows]

    @staticmethod
    def _build_client() -> Any:
        identity = require("azure.identity", "azure")
        query = require("azure.monitor.query", "azure")
        return query.LogsQueryClient(identity.DefaultAzureCredential())


def _as_datetime(value: Any) -> datetime:
    ts = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_row(
    row: Mapping[str, Any],
    transaction_event_names: set[str] | None = None,
    property_map: Mapping[str, str] | None = None,
) -> LogEvent | None:
    """Map one KQL result row to a LogEvent (or None if we don't care about it)."""
    kind = TYPE_TO_KIND.get(row.get("Type", ""))
    if kind is None:
        return None
    names = transaction_event_names or {"FundsTransfer"}
    pmap = property_map or DEFAULT_PROPERTY_MAP
    props = _as_dict(row.get("Properties"))
    common = dict(
        timestamp=_as_datetime(row["TimeGenerated"]),
        source=Source.APP_INSIGHTS,
        service=row.get("AppRoleName") or "unknown",
        trace_id=(row.get("OperationId") or None),
    )

    if kind is EventKind.TRANSACTION:
        if row.get("Name") not in names:
            return None  # an unrelated customEvent
        return LogEvent(
            **common,
            kind=kind,
            operation=row["Name"],
            account_id=props.get(pmap["account_id"]),
            amount=to_decimal(props.get(pmap["amount"])),
            currency=props.get(pmap["currency"]),
            counterparty=props.get(pmap["counterparty"]),
            transaction_id=props.get(pmap["transaction_id"]),
            attributes=props,
        )

    if kind is EventKind.EXCEPTION:
        return LogEvent(
            **common, kind=kind, operation=row.get("ExceptionType") or "exception", success=False,
            attributes={"message": row.get("OuterMessage"), **props},
        )

    success = row.get("Success")
    return LogEvent(
        **common,
        kind=kind,
        operation=row.get("Name") or "unknown",
        duration_ms=float(row["DurationMs"]) if row.get("DurationMs") is not None else None,
        success=bool(success) if success is not None else True,
        status_code=_as_int(row.get("ResultCode")),
        attributes=props,
    )
