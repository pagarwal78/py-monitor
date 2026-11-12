from __future__ import annotations

import json

from py_monitor.engine import AnalysisReport
from py_monitor.reporting.console import render_console
from py_monitor.reporting.html import render_html


def render_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


RENDERERS = {"console": render_console, "json": render_json, "html": render_html}

__all__ = ["RENDERERS", "render_console", "render_html", "render_json"]
