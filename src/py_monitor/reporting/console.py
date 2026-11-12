from __future__ import annotations

import os
import sys

from py_monitor.detectors.base import Severity
from py_monitor.engine import AnalysisReport

COLOURS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
RESET = "\033[0m"


def _use_colour() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _fmt_time(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def render_console(report: AnalysisReport, *, colour: bool | None = None, evidence_rows: int = 5) -> str:
    colour = _use_colour() if colour is None else colour
    paint = (lambda s, text: f"{COLOURS[s]}{text}{RESET}") if colour else (lambda s, text: text)
    lines = [
        "=" * 78,
        "py-monitor anomaly report",
        f"Window : {_fmt_time(report.window_start)} -> {_fmt_time(report.window_end)} UTC",
        "Sources: " + ", ".join(
            f"{s.name}={s.event_count}" + (f" (ERROR: {s.error})" if s.error else "") for s in report.sources),
        f"Events : {report.total_events:,} total, {report.transaction_count:,} transactions (de-duplicated)",
        "Found  : " + ", ".join(f"{n} {label}" for label, n in report.severity_counts().items()),
        "=" * 78,
    ]
    for name, err in report.detector_errors.items():
        lines.append(f"! detector {name} failed: {err}")
    if not report.anomalies:
        lines.append("No anomalies detected.")
    for i, a in enumerate(report.anomalies, 1):
        lines += [
            "",
            f"[{i}] {paint(a.severity, f'{a.severity.label.upper():<8}')} {a.title}",
            f"    detector : {a.detector} ({a.category})",
            f"    entity   : {a.entity}",
            f"    when     : {_fmt_time(a.first_seen)} -> {_fmt_time(a.last_seen)}",
            f"    detail   : {a.description}",
        ]
        for e in a.evidence[:evidence_rows]:
            if e.is_transaction:
                lines.append(f"      - {_fmt_time(e.timestamp)}  {e.transaction_id}  {e.amount} {e.currency}"
                             f"  -> {e.counterparty}  [{', '.join(e.attributes.get('seen_in', [e.source.value]))}]")
            else:
                lines.append(f"      - {_fmt_time(e.timestamp)}  {e.operation}  {e.status_code or ''}"
                             f"  {e.duration_ms or 0:,.0f} ms  trace={e.trace_id}")
        if len(a.evidence) > evidence_rows:
            lines.append(f"      ... {len(a.evidence) - evidence_rows} more")
    return "\n".join(lines)
