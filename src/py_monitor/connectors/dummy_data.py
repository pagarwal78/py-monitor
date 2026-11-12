"""Deterministic dummy telemetry in each cloud's *native* shape.

The rows/traces produced here look like what the real SDKs return, so dummy
mode exercises exactly the same parsing code as live mode.

Scenario: a banking app. ``mobile-banking-api`` runs on Azure (App Insights)
and calls ``payments-service`` on AWS (X-Ray) for every transfer, so each
transfer shows up in both sources with the same transaction id.

Injected anomalies (positions are fractions of the requested window):

* RAPID_REPEAT_ACCOUNT  - 5 x 2,500.00 GBP to the same payee within ~3 minutes
* VELOCITY_ACCOUNT      - 14 transfers of varying amounts within 10 minutes
* STRUCTURING_ACCOUNT   - 4 transfers just under the 10,000 reporting threshold
* ERROR_BURST_SERVICE   - ~35% HTTP 500s for 12 minutes
* LATENCY_SPIKE_SERVICE - ~20x slower responses for 20 minutes
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

RAPID_REPEAT_ACCOUNT = "ACC-1007"
VELOCITY_ACCOUNT = "ACC-1013"
STRUCTURING_ACCOUNT = "ACC-1042"
ERROR_BURST_SERVICE = "mobile-banking-api"
LATENCY_SPIKE_SERVICE = "payments-service"

ACCOUNTS = [f"ACC-{1000 + i}" for i in range(60)]
PAYEES = [f"PAYEE-{i:03d}" for i in range(200)]
API_ROUTES = [
    ("GET /api/accounts/{id}/balance", 60),
    ("GET /api/accounts/{id}/statements", 25),
    ("POST /api/auth/login", 15),
]


@dataclass(frozen=True)
class Transfer:
    timestamp: datetime
    account_id: str
    amount: Decimal
    currency: str
    payee: str
    transaction_id: str
    trace_hex: str  # 32-hex W3C trace id, first 8 hex = epoch seconds (X-Ray compatible)


def scenario_windows(start: datetime, end: datetime) -> dict[str, tuple[datetime, datetime]]:
    span = end - start
    def at(frac: float, length: timedelta) -> tuple[datetime, datetime]:
        s = start + span * frac
        return s, s + length
    return {
        "structuring": at(0.10, min(timedelta(hours=2), span * 0.4)),
        "rapid_repeat": at(0.25, timedelta(minutes=3)),
        "velocity": at(0.40, timedelta(minutes=10)),
        "error_burst": at(0.60, timedelta(minutes=12)),
        "latency_spike": at(0.75, timedelta(minutes=20)),
    }


def _in(ts: datetime, window: tuple[datetime, datetime]) -> bool:
    return window[0] <= ts < window[1]


def _trace_hex(rng: random.Random, ts: datetime) -> str:
    return f"{int(ts.timestamp()):08x}{rng.getrandbits(96):024x}"


def _uniform_ts(rng: random.Random, start: datetime, end: datetime) -> datetime:
    return start + (end - start) * rng.random()


def _money(value: float) -> Decimal:
    return Decimal(f"{value:.2f}")


def build_transfers(start: datetime, end: datetime, seed: int = 42) -> list[Transfer]:
    """The shared list of money movements both clouds will report on."""
    rng = random.Random(seed)
    windows = scenario_windows(start, end)
    transfers: list[Transfer] = []

    def add(ts: datetime, account: str, amount: Decimal, payee: str, currency: str = "GBP") -> None:
        transfers.append(Transfer(
            timestamp=ts, account_id=account, amount=amount, currency=currency, payee=payee,
            transaction_id=f"TXN-{rng.getrandbits(48):012x}", trace_hex=_trace_hex(rng, ts),
        ))

    # Normal behaviour: ~0.5 transfers per account per hour, long-tailed amounts.
    hours = (end - start).total_seconds() / 3600
    for _ in range(int(len(ACCOUNTS) * 0.5 * hours)):
        amount = min(rng.lognormvariate(4.5, 1.0), 5000.0)
        add(_uniform_ts(rng, start, end), rng.choice(ACCOUNTS), _money(max(amount, 1.0)),
            rng.choice(PAYEES), "GBP" if rng.random() < 0.9 else "EUR")

    # Anomaly: same amount, same account, quick succession.
    w0, _ = windows["rapid_repeat"]
    for i in range(5):
        add(w0 + timedelta(seconds=40 * i + rng.randint(0, 5)), RAPID_REPEAT_ACCOUNT,
            Decimal("2500.00"), "PAYEE-777")

    # Anomaly: lots of transfers, different amounts and payees.
    v0, v1 = windows["velocity"]
    for _ in range(14):
        add(_uniform_ts(rng, v0, v1), VELOCITY_ACCOUNT, _money(rng.uniform(20, 400)), rng.choice(PAYEES))

    # Anomaly: amounts just below a 10,000 reporting threshold.
    s0, s1 = windows["structuring"]
    for i, amount in enumerate(["9850.00", "9900.00", "9750.00", "9950.00"]):
        add(s0 + (s1 - s0) * (i / 4), STRUCTURING_ACCOUNT, Decimal(amount), PAYEES[10 + i])

    return sorted((t for t in transfers if start <= t.timestamp < end), key=lambda t: t.timestamp)


# --------------------------------------------------------------------------- Azure
def _ai_row(ts: datetime, type_: str, name: str, op_id: str, role: str, *, duration: float | None = None,
            success: bool | None = True, code: str | None = None, props: dict | None = None,
            exc_type: str | None = None, message: str | None = None) -> dict[str, Any]:
    """One row of the App Insights (workspace-based) union query."""
    return {
        "TimeGenerated": ts.isoformat(),
        "Type": type_,
        "Name": name,
        "OperationId": op_id,
        "AppRoleName": role,
        "DurationMs": round(duration, 2) if duration is not None else None,
        "Success": success,
        "ResultCode": code,
        "Properties": json.dumps(props or {}),  # dynamic columns arrive as JSON strings
        "ExceptionType": exc_type,
        "OuterMessage": message,
    }


def appinsights_rows(start: datetime, end: datetime, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed + 1)
    windows = scenario_windows(start, end)
    role = ERROR_BURST_SERVICE
    rows: list[dict[str, Any]] = []

    for t in build_transfers(start, end, seed):
        rows.append(_ai_row(t.timestamp, "AppRequests", "POST /api/transfers", t.trace_hex, role,
                            duration=rng.lognormvariate(5.2, 0.3), code="201"))
        rows.append(_ai_row(t.timestamp, "AppDependencies", "POST payments-service/payments/transfer",
                            t.trace_hex, role, duration=rng.lognormvariate(4.8, 0.3), code="201",
                            props={"target": "payments.eu-west-2.example.internal"}))
        rows.append(_ai_row(t.timestamp, "AppEvents", "FundsTransfer", t.trace_hex, role, success=None,
                            props={"accountId": t.account_id, "amount": str(t.amount),
                                   "currency": t.currency, "beneficiaryId": t.payee,
                                   "transactionId": t.transaction_id, "channel": "mobile"}))

    names, weights = zip(*API_ROUTES)
    minute = start
    while minute < end:
        for _ in range(rng.randint(15, 25)):
            ts = minute + timedelta(seconds=rng.uniform(0, 60))
            if ts >= end:
                continue
            op_id = _trace_hex(rng, ts)
            name = rng.choices(names, weights)[0]
            failed = rng.random() < (0.35 if _in(ts, windows["error_burst"]) else 0.01)
            rows.append(_ai_row(ts, "AppRequests", name, op_id, role,
                                duration=rng.lognormvariate(4.6, 0.35),  # fail-fast 500s
                                success=not failed, code="500" if failed else "200"))
            if failed:
                rows.append(_ai_row(ts, "AppExceptions", None, op_id, role, success=None,
                                    exc_type="Microsoft.Data.SqlClient.SqlException",
                                    message="Connection pool exhausted"))
        minute += timedelta(minutes=1)

    rows.sort(key=lambda r: r["TimeGenerated"])
    return rows


# --------------------------------------------------------------------------- AWS
def _xray_trace(rng: random.Random, ts: datetime, trace_hex: str, method: str, path: str,
                duration_s: float, *, annotations: dict | None = None, status: int = 200,
                fault: bool = False) -> dict[str, Any]:
    trace_id = f"1-{trace_hex[:8]}-{trace_hex[8:]}"
    start_s = ts.timestamp()
    db_s = duration_s * rng.uniform(0.3, 0.7)
    doc = {
        "id": f"{rng.getrandbits(64):016x}",
        "name": LATENCY_SPIKE_SERVICE,
        "trace_id": trace_id,
        "start_time": start_s,
        "end_time": start_s + duration_s,
        "origin": "AWS::ECS::Container",
        "http": {"request": {"method": method, "url": f"https://payments.example.internal{path}"},
                 "response": {"status": status}},
        "fault": fault,
        "error": False,
        "annotations": annotations or {},
        "subsegments": [{
            "id": f"{rng.getrandbits(64):016x}",
            "name": "DynamoDB",
            "namespace": "aws",
            "start_time": start_s + duration_s * 0.1,
            "end_time": start_s + duration_s * 0.1 + db_s,
            "aws": {"operation": "PutItem" if method == "POST" else "GetItem", "table_name": "payments"},
        }],
    }
    return {"Id": trace_id, "Duration": round(duration_s, 3), "LimitExceeded": False,
            "Segments": [{"Id": doc["id"], "Document": json.dumps(doc)}]}


def xray_traces(start: datetime, end: datetime, seed: int = 42) -> list[dict[str, Any]]:
    """Traces in the shape returned by ``xray.batch_get_traces``."""
    rng = random.Random(seed + 2)
    spike = scenario_windows(start, end)["latency_spike"]

    def duration(ts: datetime) -> float:
        return rng.uniform(2.0, 4.0) if _in(ts, spike) else rng.lognormvariate(-2.1, 0.3)  # ~120 ms

    traces = []
    for t in build_transfers(start, end, seed):
        traces.append(_xray_trace(rng, t.timestamp, t.trace_hex, "POST", "/payments/transfer",
                                  duration(t.timestamp), status=201, annotations={
                                      "event_type": "transfer", "account_id": t.account_id,
                                      "amount": float(t.amount), "currency": t.currency,
                                      "counterparty": t.payee, "txn_id": t.transaction_id}))

    minute = start
    while minute < end:
        for _ in range(rng.randint(4, 8)):
            ts = minute + timedelta(seconds=rng.uniform(0, 60))
            if ts < end:
                traces.append(_xray_trace(rng, ts, _trace_hex(rng, ts), "GET", "/payments/status",
                                          duration(ts)))
        minute += timedelta(minutes=1)
    return traces
