"""Self-contained HTML report (no external assets, safe to email or attach)."""

from __future__ import annotations

from html import escape

from py_monitor.detectors.base import Anomaly
from py_monitor.engine import AnalysisReport

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;
--critical:#b3261e;--high:#d0461f;--medium:#b07a00;--low:#2f6f9f}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecece8;--muted:#a3a39c;
--line:#33332f;--critical:#ff6b61;--high:#ff8a5c;--medium:#e0b23a;--low:#6fb3e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.card h2{font-size:16px;margin:0 0 6px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;
border-radius:99px;color:#fff}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}
.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}
.meta{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-bottom:6px}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted)}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td.num{text-align:right;font-variant-numeric:tabular-nums}.err{color:var(--critical)}
"""


def _t(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _evidence_table(a: Anomaly) -> str:
    if not a.evidence:
        return ""
    if a.category == "transaction":
        head = "<tr><th>Time (UTC)</th><th>Transaction</th><th>Account</th><th>Amount</th><th>Payee</th><th>Seen in</th></tr>"
        rows = "".join(
            f"<tr><td>{_t(e.timestamp)}</td><td>{escape(e.transaction_id or '')}</td>"
            f"<td>{escape(e.account_id or '')}</td><td class=num>{e.amount} {escape(e.currency or '')}</td>"
            f"<td>{escape(e.counterparty or '')}</td>"
            f"<td>{escape(', '.join(e.attributes.get('seen_in', [e.source.value])))}</td></tr>"
            for e in a.evidence)
    else:
        head = "<tr><th>Time (UTC)</th><th>Source</th><th>Operation</th><th>Status</th><th>Duration</th><th>Trace</th></tr>"
        rows = "".join(
            f"<tr><td>{_t(e.timestamp)}</td><td>{escape(e.source.value)}</td><td>{escape(e.operation)}</td>"
            f"<td>{e.status_code or ''}</td><td class=num>{(e.duration_ms or 0):,.0f} ms</td>"
            f"<td>{escape(e.trace_id or '')}</td></tr>"
            for e in a.evidence)
    return (f"<details><summary>Evidence ({len(a.evidence)} events)</summary>"
            f"<div class=scroll><table>{head}{rows}</table></div></details>")


def _card(a: Anomaly) -> str:
    return (
        f"<section class=card><h2><span class='sev {a.severity.label}'>{a.severity.label}</span>"
        f"{escape(a.title)}</h2>"
        f"<div class=meta><span>{escape(a.entity)}</span><span>{escape(a.detector)}</span>"
        f"<span>{_t(a.first_seen)} &rarr; {_t(a.last_seen)}</span></div>"
        f"<div>{escape(a.description)}</div>{_evidence_table(a)}</section>"
    )


def render_html(report: AnalysisReport) -> str:
    counts = report.severity_counts()
    tiles = "".join(
        f"<div class=tile><span class=muted>{label.title()}</span><b>{n}</b></div>" for label, n in counts.items())
    tiles += (f"<div class=tile><span class=muted>Events</span><b>{report.total_events:,}</b></div>"
              f"<div class=tile><span class=muted>Transactions</span><b>{report.transaction_count:,}</b></div>")
    sources = " &middot; ".join(
        f"{escape(s.name)}: {s.event_count:,}" + (f" <span class=err>({escape(s.error)})</span>" if s.error else "")
        for s in report.sources)
    errors = "".join(f"<p class=err>Detector {escape(k)} failed: {escape(v)}</p>"
                     for k, v in report.detector_errors.items())
    body = "".join(_card(a) for a in report.anomalies) or "<p>No anomalies detected.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>py-monitor report</title><style>{CSS}</style></head>
<body><main>
<h1>Anomaly report</h1>
<div class=muted>{_t(report.window_start)} &rarr; {_t(report.window_end)} UTC &middot; generated {_t(report.generated_at)} UTC</div>
<div class=muted>{sources}</div>
<div class=tiles>{tiles}</div>
{errors}{body}
</main></body></html>
"""
