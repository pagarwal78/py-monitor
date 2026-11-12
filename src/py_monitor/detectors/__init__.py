from py_monitor.detectors.base import Anomaly, Detector, Severity
from py_monitor.detectors.operational import ErrorRateDetector, LatencySpikeDetector
from py_monitor.detectors.transaction import (
    RapidRepeatTransferDetector, StructuringDetector, VelocityDetector,
)

REGISTRY: dict[str, type[Detector]] = {
    cls.name: cls
    for cls in (
        RapidRepeatTransferDetector,
        VelocityDetector,
        StructuringDetector,
        LatencySpikeDetector,
        ErrorRateDetector,
    )
}

__all__ = [
    "REGISTRY", "Anomaly", "Detector", "Severity", "ErrorRateDetector", "LatencySpikeDetector",
    "RapidRepeatTransferDetector", "StructuringDetector", "VelocityDetector",
]
