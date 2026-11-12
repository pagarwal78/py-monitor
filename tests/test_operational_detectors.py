from helpers import req

from py_monitor.detectors import ErrorRateDetector, LatencySpikeDetector, Severity


def _steady(minutes: int, per_minute: int = 10, **kw):
    return [req(m * 60 + i * (60 / per_minute), **kw) for m in range(minutes) for i in range(per_minute)]


class TestLatencySpike:
    det = LatencySpikeDetector(bucket_minutes=5, percentile=90, ratio=3.0, min_samples=5)

    def test_flags_slow_period(self):
        events = _steady(60, duration=100)
        events += [req(30 * 60 + i * 10, duration=2000) for i in range(30)]  # 30:00-35:00 slow
        [a] = self.det.detect(sorted(events, key=lambda e: e.timestamp))
        assert a.entity == "svc :: GET /x"
        assert a.metrics["peak_ms"] >= 2000
        assert a.severity is Severity.HIGH

    def test_steady_traffic_is_quiet(self):
        assert self.det.detect(_steady(60, duration=100)) == []

    def test_operations_have_separate_baselines(self):
        fast = _steady(60, operation="GET /fast", duration=50)
        slow = _steady(60, operation="GET /slow", duration=900)  # always slow = its normal
        assert self.det.detect(sorted(fast + slow, key=lambda e: e.timestamp)) == []


class TestErrorRate:
    det = ErrorRateDetector(bucket_minutes=5, min_requests=20, min_error_rate=0.10, multiplier=5)

    def test_flags_error_burst(self):
        events = _steady(60)
        burst = [req(20 * 60 + i * 6, success=False) for i in range(50)]  # 20:00-25:00 failing
        [a] = self.det.detect(sorted(events + burst, key=lambda e: e.timestamp))
        assert a.entity == "svc"
        assert a.metrics["failed"] == 50
        assert a.severity is Severity.CRITICAL  # >50% in the bucket

    def test_low_volume_buckets_ignored(self):
        events = [req(i * 60, success=False) for i in range(5)]
        assert self.det.detect(events) == []

    def test_background_errors_are_quiet(self):
        events = _steady(60)
        events = [e if i % 100 else req(e.timestamp.minute * 60, success=False) for i, e in enumerate(events)]
        assert self.det.detect(sorted(events, key=lambda e: e.timestamp)) == []
