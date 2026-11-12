from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from py_monitor.models import LogEvent


class LogSource(ABC):
    """A place we can pull telemetry from for a time window."""

    name: str = "source"

    @abstractmethod
    def fetch(self, start: datetime, end: datetime) -> list[LogEvent]:
        """Return normalised events with ``start <= timestamp < end``."""


class MissingDependencyError(RuntimeError):
    pass


def require(module: str, extra: str):
    """Import an optional SDK lazily so dummy mode needs no cloud packages."""
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise MissingDependencyError(
            f"'{module}' is not installed. Install it with: pip install 'py-monitor[{extra}]'"
        ) from exc
