import json
from datetime import timedelta

import pytest
from helpers import T0, txn

from py_monitor import cli
from py_monitor.config import build_detectors, build_sources, load_config
from py_monitor.connectors import dummy_data
from py_monitor.connectors.base import LogSource
from py_monitor.engine import MonitorEngine, deduplicate_transactions
from py_monitor.models import Source
from py_monitor.reporting import render_console, render_html, render_json

START, END = T0, T0 + timedelta(hours=6)


@pytest.fixture(scope="module")
def report():
    cfg = load_config()
    return MonitorEngine(build_sources(cfg, use_dummy=True), build_detectors(cfg)).run(START, END)


def _by_detector(report, name):
    return [a for a in report.anomalies if a.detector == name]


def test_dedupe_merges_same_transaction_from_both_clouds():
    a = txn(0, txn_id="TXN-1", source=Source.APP_INSIGHTS)
    b = txn(0.2, txn_id="TXN-1", source=Source.XRAY)
    [only] = deduplicate_transactions([b, a])
    assert only.source is Source.APP_INSIGHTS
    assert only.attributes["seen_in"] == ["aws_xray", "azure_appinsights"]


def test_every_injected_scenario_is_detected(report):
    [rapid] = _by_detector(report, "rapid_repeat_transfer")
    assert rapid.entity == dummy_data.RAPID_REPEAT_ACCOUNT and rapid.metrics["count"] == 5
    [velocity] = _by_detector(report, "transaction_velocity")
    assert velocity.entity == dummy_data.VELOCITY_ACCOUNT and velocity.metrics["count"] >= 14
    [struct] = _by_detector(report, "structuring")
    assert struct.entity == dummy_data.STRUCTURING_ACCOUNT and struct.metrics["count"] == 4
    [errors] = _by_detector(report, "error_rate")
    assert errors.entity == dummy_data.ERROR_BURST_SERVICE
    latency = _by_detector(report, "latency_spike")
    assert latency and all(a.entity.startswith(dummy_data.LATENCY_SPIKE_SERVICE) for a in latency)


def test_no_false_positives_on_normal_accounts(report):
    flagged = {a.entity for a in report.anomalies if a.category == "transaction"}
    assert flagged == {dummy_data.RAPID_REPEAT_ACCOUNT, dummy_data.VELOCITY_ACCOUNT, dummy_data.STRUCTURING_ACCOUNT}


def test_transfers_seen_in_both_sources_are_counted_once(report):
    [rapid] = _by_detector(report, "rapid_repeat_transfer")
    assert all(e.attributes["seen_in"] == ["aws_xray", "azure_appinsights"] for e in rapid.evidence)
    assert report.transaction_count == len(dummy_data.build_transfers(START, END))


def test_failing_source_does_not_stop_the_run():
    class Broken(LogSource):
        name = "broken"

        def fetch(self, start, end):
            raise ConnectionError("unreachable")

    cfg = load_config()
    sources = [Broken(), *build_sources(cfg, use_dummy=True)]
    report = MonitorEngine(sources, build_detectors(cfg)).run(START, END)
    assert report.sources[0].error == "ConnectionError: unreachable"
    assert report.anomalies


def test_renderers(report):
    assert "Repeated transfer of 2500.00 GBP" in render_console(report, colour=False)
    data = json.loads(render_json(report))
    assert data["severity_counts"]["high"] >= 1
    html = render_html(report)
    assert html.startswith("<!doctype html>") and dummy_data.RAPID_REPEAT_ACCOUNT in html


def test_config_file_overrides_and_disables(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("[detectors.rapid_repeat_transfer]\nmin_count = 6\n[detectors.error_rate]\nenabled = false\n")
    detectors = build_detectors(load_config(path))
    names = [d.name for d in detectors]
    assert "error_rate" not in names
    assert next(d for d in detectors if d.name == "rapid_repeat_transfer").min_count == 6


def test_cli_writes_report_and_fail_on(tmp_path):
    out = tmp_path / "r.html"
    code = cli.main(["--end", END.isoformat(), "--format", "html", "-o", str(out), "--fail-on", "high"])
    assert code == cli.EXIT_ANOMALIES
    assert out.read_text().startswith("<!doctype html>")
