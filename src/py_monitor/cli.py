"""Command line entry point: ``py-monitor`` / ``python -m py_monitor``."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from py_monitor.config import build_detectors, build_sources, load_config
from py_monitor.detectors.base import Severity
from py_monitor.engine import MonitorEngine
from py_monitor.reporting import RENDERERS

EXIT_ANOMALIES = 2


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="py-monitor", description=__doc__)
    p.add_argument("--live", action="store_true",
                   help="query real App Insights / X-Ray (default: generated dummy data)")
    p.add_argument("--config", type=Path, help="TOML config file (see config/settings.example.toml)")
    p.add_argument("--hours", type=float, help="look-back window in hours (default from config: 6)")
    p.add_argument("--end", help="window end, ISO-8601 (default: now, UTC)")
    p.add_argument("--format", choices=sorted(RENDERERS), default="console")
    p.add_argument("--output", "-o", type=Path, help="write the report to a file instead of stdout")
    p.add_argument("--seed", type=int, default=42, help="random seed for dummy data")
    p.add_argument("--fail-on", choices=[s.label for s in Severity],
                   help=f"exit with code {EXIT_ANOMALIES} if any anomaly is at or above this severity")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)
    hours = args.hours or cfg["window"]["hours"]
    end = datetime.fromisoformat(args.end) if args.end else datetime.now(timezone.utc)
    end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
    start = end - timedelta(hours=hours)

    try:
        engine = MonitorEngine(build_sources(cfg, use_dummy=not args.live, seed=args.seed), build_detectors(cfg))
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    report = engine.run(start, end)
    rendered = RENDERERS[args.format](report)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {args.format} report with {len(report.anomalies)} anomalies to {args.output}")
    else:
        print(rendered)

    if args.fail_on and report.max_severity and report.max_severity >= Severity.parse(args.fail_on):
        return EXIT_ANOMALIES
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
