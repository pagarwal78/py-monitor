"""AWS X-Ray connector.

Live mode uses boto3 (credentials from the standard AWS chain: env vars,
~/.aws profile, instance/task role). ``GetTraceSummaries`` only accepts a
6-hour range per call and ``BatchGetTraces`` takes 5 ids at a time, so the
fetch is chunked accordingly.

Business fields come from segment **annotations** (indexed, filterable):
``account_id``, ``amount``, ``currency``, ``counterparty``, ``txn_id``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
from urllib.parse import urlparse

from py_monitor.connectors import dummy_data
from py_monitor.connectors.base import LogSource, require
from py_monitor.models import EventKind, LogEvent, Source, to_decimal, xray_to_w3c

log = logging.getLogger(__name__)

MAX_SUMMARY_SPAN = timedelta(hours=6)
BATCH_GET_LIMIT = 5


class XRaySource(LogSource):
    name = Source.XRAY.value

    def __init__(
        self,
        region: str | None = None,
        *,
        filter_expression: str | None = None,
        use_dummy: bool = False,
        seed: int = 42,
        client: Any = None,
    ) -> None:
        self.region = region
        self.filter_expression = filter_expression or None
        self.use_dummy = use_dummy
        self.seed = seed
        self._client = client

    def fetch(self, start: datetime, end: datetime) -> list[LogEvent]:
        events = [
            e for trace in self._fetch_traces(start, end) for e in parse_trace(trace)
            if start <= e.timestamp < end
        ]
        log.info("X-Ray: %d events", len(events))
        return events

    def _fetch_traces(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        if self.use_dummy:
            return dummy_data.xray_traces(start, end, self.seed)

        client = self._client or require("boto3", "aws").client("xray", region_name=self.region)
        trace_ids: dict[str, None] = {}  # ordered set
        summaries = client.get_paginator("get_trace_summaries")
        for chunk_start, chunk_end in split_time_range(start, end, MAX_SUMMARY_SPAN):
            kwargs: dict[str, Any] = {"StartTime": chunk_start, "EndTime": chunk_end, "Sampling": False}
            if self.filter_expression:
                kwargs["FilterExpression"] = self.filter_expression
            for page in summaries.paginate(**kwargs):
                trace_ids.update((s["Id"], None) for s in page.get("TraceSummaries", []))

        traces: list[dict[str, Any]] = []
        batch = client.get_paginator("batch_get_traces")
        for ids in _chunks(list(trace_ids), BATCH_GET_LIMIT):
            for page in batch.paginate(TraceIds=ids):
                traces.extend(page.get("Traces", []))
        return traces


def split_time_range(start: datetime, end: datetime, max_span: timedelta) -> list[tuple[datetime, datetime]]:
    ranges = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + max_span, end)
        ranges.append((cursor, nxt))
        cursor = nxt
    return ranges


def _chunks(items: list[str], size: int) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def parse_trace(trace: dict[str, Any]) -> list[LogEvent]:
    events: list[LogEvent] = []
    for segment in trace.get("Segments", []):
        try:
            doc = json.loads(segment["Document"])
        except (KeyError, json.JSONDecodeError):
            log.warning("Skipping unreadable segment in trace %s", trace.get("Id"))
            continue
        events.extend(_parse_segment(doc, doc.get("trace_id") or trace.get("Id")))
    return events


def _ts(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _parse_segment(doc: dict[str, Any], raw_trace_id: str | None, parent_service: str | None = None) -> list[LogEvent]:
    is_sub = parent_service is not None or doc.get("type") == "subsegment"
    start = _ts(doc["start_time"])
    end_time = doc.get("end_time")
    duration_ms = (end_time - doc["start_time"]) * 1000 if end_time else None
    http = doc.get("http", {})
    request, response = http.get("request", {}), http.get("response", {})
    service = parent_service or doc.get("name", "unknown")
    trace_id = xray_to_w3c(raw_trace_id)
    failed = bool(doc.get("fault") or doc.get("error") or doc.get("throttle"))

    if is_sub:
        aws = doc.get("aws", {})
        operation = f"{doc.get('name')} {aws['operation']}" if aws.get("operation") else doc.get("name", "unknown")
        kind = EventKind.DEPENDENCY
    else:
        path = urlparse(request.get("url", "")).path
        operation = f"{request['method']} {path}" if request.get("method") else doc.get("name", "unknown")
        kind = EventKind.REQUEST

    events = [LogEvent(
        timestamp=start, source=Source.XRAY, kind=kind, service=service, operation=operation,
        trace_id=trace_id, duration_ms=duration_ms, success=not failed,
        status_code=response.get("status"),
        attributes={"xray_trace_id": raw_trace_id, "segment_id": doc.get("id"), "origin": doc.get("origin")},
    )]

    annotations = doc.get("annotations") or {}
    if annotations.get("account_id") and annotations.get("amount") is not None:
        events.append(LogEvent(
            timestamp=start, source=Source.XRAY, kind=EventKind.TRANSACTION, service=service,
            operation=annotations.get("event_type", "transfer"), trace_id=trace_id,
            account_id=str(annotations["account_id"]), amount=to_decimal(annotations["amount"]),
            currency=annotations.get("currency"), counterparty=annotations.get("counterparty"),
            transaction_id=annotations.get("txn_id"), attributes=dict(annotations),
        ))

    cause = doc.get("cause")  # a dict, or a string id referencing an exception elsewhere
    exceptions = cause.get("exceptions", []) if isinstance(cause, dict) else []
    for exc in exceptions:
        events.append(LogEvent(
            timestamp=start, source=Source.XRAY, kind=EventKind.EXCEPTION, service=service,
            operation=exc.get("type") or "exception", trace_id=trace_id, success=False,
            attributes={"message": exc.get("message")},
        ))

    for sub in doc.get("subsegments", []):
        events.extend(_parse_segment(sub, raw_trace_id, service))
    return events
