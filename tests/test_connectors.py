import json
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

from helpers import T0

from py_monitor.connectors import AppInsightsSource, XRaySource
from py_monitor.connectors.aws_xray import parse_trace, split_time_range
from py_monitor.connectors.azure_appinsights import parse_row
from py_monitor.models import EventKind, Source, xray_to_w3c


class TestAppInsights:
    def test_parses_funds_transfer_event(self):
        row = {"TimeGenerated": "2026-11-12T12:00:00+00:00", "Type": "AppEvents", "Name": "FundsTransfer",
               "OperationId": "abc", "AppRoleName": "api",
               "Properties": json.dumps({"accountId": "ACC-1", "amount": "2500", "currency": "GBP",
                                         "beneficiaryId": "P-9", "transactionId": "TXN-1"})}
        e = parse_row(row)
        assert e.kind is EventKind.TRANSACTION and e.is_transaction
        assert (e.account_id, e.amount, e.counterparty, e.transaction_id) == ("ACC-1", Decimal("2500.00"), "P-9", "TXN-1")

    def test_ignores_unrelated_custom_events(self):
        assert parse_row({"TimeGenerated": "2026-11-12T12:00:00Z", "Type": "AppEvents", "Name": "PageView"}) is None

    def test_parses_failed_request(self):
        e = parse_row({"TimeGenerated": "2026-11-12T12:00:00Z", "Type": "AppRequests", "Name": "GET /a",
                       "AppRoleName": "api", "DurationMs": 12.5, "Success": False, "ResultCode": "500"})
        assert (e.kind, e.success, e.status_code, e.duration_ms) == (EventKind.REQUEST, False, 500, 12.5)

    def test_custom_property_map(self):
        row = {"TimeGenerated": "2026-11-12T12:00:00Z", "Type": "AppEvents", "Name": "Payment",
               "Properties": {"acct": "A", "value": 5}}
        e = parse_row(row, {"Payment"}, {"account_id": "acct", "amount": "value", "currency": "c",
                                         "counterparty": "p", "transaction_id": "t"})
        assert (e.account_id, e.amount) == ("A", Decimal("5.00"))

    def test_live_mode_uses_client_tables(self):
        table = SimpleNamespace(columns=["TimeGenerated", "Type", "Name", "AppRoleName", "Success"],
                                rows=[[T0, "AppRequests", "GET /a", "api", True]])
        client = SimpleNamespace(query_workspace=lambda *a, **k: SimpleNamespace(tables=[table]))
        events = AppInsightsSource("ws-id", client=client).fetch(T0, T0 + timedelta(hours=1))
        assert len(events) == 1 and events[0].source is Source.APP_INSIGHTS

    def test_live_mode_requires_workspace(self):
        try:
            AppInsightsSource(None)
        except ValueError:
            return
        raise AssertionError("expected ValueError")


class TestXRay:
    def _trace(self, **doc_overrides):
        doc = {"id": "s1", "name": "payments", "trace_id": "1-5759e988-bd862e3fe1be46a994272793",
               "start_time": T0.timestamp(), "end_time": T0.timestamp() + 0.25,
               "http": {"request": {"method": "POST", "url": "https://x/payments/transfer"},
                        "response": {"status": 201}},
               "annotations": {"account_id": "ACC-1", "amount": 99.5, "currency": "GBP", "txn_id": "TXN-1"},
               "subsegments": [{"id": "s2", "name": "DynamoDB", "start_time": T0.timestamp(),
                                "end_time": T0.timestamp() + 0.1, "aws": {"operation": "PutItem"}}]}
        doc.update(doc_overrides)
        return {"Id": doc["trace_id"], "Segments": [{"Id": "s1", "Document": json.dumps(doc)}]}

    def test_parses_segment_subsegment_and_annotations(self):
        events = parse_trace(self._trace())
        kinds = {e.kind: e for e in events}
        assert kinds[EventKind.REQUEST].operation == "POST /payments/transfer"
        assert round(kinds[EventKind.REQUEST].duration_ms) == 250
        assert kinds[EventKind.DEPENDENCY].operation == "DynamoDB PutItem"
        assert kinds[EventKind.TRANSACTION].amount == Decimal("99.50")
        assert kinds[EventKind.TRANSACTION].trace_id == "5759e988bd862e3fe1be46a994272793"

    def test_fault_and_exceptions(self):
        events = parse_trace(self._trace(fault=True, cause={"exceptions": [{"type": "Timeout", "message": "x"}]}))
        assert not next(e for e in events if e.kind is EventKind.REQUEST).success
        assert any(e.kind is EventKind.EXCEPTION and e.operation == "Timeout" for e in events)

    def test_bad_segment_document_is_skipped(self):
        assert parse_trace({"Id": "t", "Segments": [{"Id": "s", "Document": "{not json"}]}) == []

    def test_time_range_split_respects_six_hour_limit(self):
        ranges = split_time_range(T0, T0 + timedelta(hours=13), timedelta(hours=6))
        assert [(e - s).total_seconds() / 3600 for s, e in ranges] == [6, 6, 1]

    def test_live_mode_paginates_and_batches(self):
        ids = [f"1-00000000-{i:024x}" for i in range(7)]
        calls = []

        class Paginator:
            def __init__(self, op):
                self.op = op

            def paginate(self, **kw):
                calls.append((self.op, kw))
                if self.op == "get_trace_summaries":
                    return [{"TraceSummaries": [{"Id": i} for i in ids]}]
                return [{"Traces": [{"Id": t, "Segments": []} for t in kw["TraceIds"]]}]

        client = SimpleNamespace(get_paginator=Paginator)
        XRaySource("eu-west-2", client=client).fetch(T0, T0 + timedelta(hours=7))
        summary_calls = [c for c in calls if c[0] == "get_trace_summaries"]
        batch_calls = [c for c in calls if c[0] == "batch_get_traces"]
        assert len(summary_calls) == 2                       # 7h -> 6h + 1h
        assert [len(c[1]["TraceIds"]) for c in batch_calls] == [5, 2]  # 7 unique ids, 5 per call


def test_xray_to_w3c():
    assert xray_to_w3c("1-5759e988-bd862e3fe1be46a994272793") == "5759e988bd862e3fe1be46a994272793"
    assert xray_to_w3c(None) is None
