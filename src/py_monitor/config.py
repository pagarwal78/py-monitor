"""Configuration: built-in defaults, overridden by a TOML file and env vars."""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path
from typing import Any

from py_monitor.connectors import AppInsightsSource, LogSource, XRaySource
from py_monitor.detectors import REGISTRY, Detector

DEFAULTS: dict[str, Any] = {
    "window": {"hours": 6},
    "sources": {
        "azure_appinsights": {
            "enabled": True,
            "workspace_id": "",
            "transaction_event_names": ["FundsTransfer"],
        },
        "aws_xray": {
            "enabled": True,
            "region": "eu-west-2",
            "filter_expression": "",
        },
    },
    "detectors": {
        "rapid_repeat_transfer": {"enabled": True, "window_minutes": 5, "min_count": 3},
        "transaction_velocity": {"enabled": True, "window_minutes": 10, "max_count": 10, "max_total": 20000},
        "structuring": {"enabled": True, "threshold": 10000, "margin_pct": 10, "window_hours": 24, "min_count": 3},
        "latency_spike": {"enabled": True, "bucket_minutes": 5, "percentile": 90, "ratio": 3.0},
        "error_rate": {"enabled": True, "bucket_minutes": 5, "min_requests": 20, "min_error_rate": 0.10},
    },
}

ENV_OVERRIDES = {
    ("sources", "azure_appinsights", "workspace_id"): "APPINSIGHTS_WORKSPACE_ID",
    ("sources", "aws_xray", "region"): "AWS_REGION",
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        with open(path, "rb") as fh:
            cfg = _merge(cfg, tomllib.load(fh))
    for (*parents, leaf), env in ENV_OVERRIDES.items():
        if os.environ.get(env):
            node = cfg
            for p in parents:
                node = node.setdefault(p, {})
            node[leaf] = os.environ[env]
    return cfg


def build_sources(cfg: dict[str, Any], *, use_dummy: bool, seed: int = 42) -> list[LogSource]:
    sources: list[LogSource] = []
    ai = cfg["sources"].get("azure_appinsights", {})
    if ai.get("enabled", True):
        sources.append(AppInsightsSource(
            ai.get("workspace_id") or None, use_dummy=use_dummy, seed=seed,
            transaction_event_names=ai.get("transaction_event_names", ["FundsTransfer"]),
            property_map=ai.get("property_map"),
        ))
    xr = cfg["sources"].get("aws_xray", {})
    if xr.get("enabled", True):
        sources.append(XRaySource(
            xr.get("region") or None, filter_expression=xr.get("filter_expression") or None,
            use_dummy=use_dummy, seed=seed,
        ))
    return sources


def build_detectors(cfg: dict[str, Any]) -> list[Detector]:
    detectors: list[Detector] = []
    for name, params in cfg.get("detectors", {}).items():
        params = dict(params)
        if not params.pop("enabled", True):
            continue
        if name not in REGISTRY:
            raise ValueError(f"Unknown detector '{name}'. Known: {', '.join(REGISTRY)}")
        detectors.append(REGISTRY[name](**params))
    return detectors
