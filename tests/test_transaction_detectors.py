from decimal import Decimal

from helpers import txn

from py_monitor.detectors import (
    RapidRepeatTransferDetector, Severity, StructuringDetector, VelocityDetector,
)


class TestRapidRepeatTransfer:
    det = RapidRepeatTransferDetector(window_minutes=5, min_count=3)

    def test_flags_same_amount_in_quick_succession(self):
        events = [txn(0), txn(60), txn(120)]
        [a] = self.det.detect(events)
        assert a.entity == "ACC-1"
        assert a.metrics["count"] == 3
        assert a.metrics["total"] == Decimal("300.00")
        assert a.severity is Severity.MEDIUM
        assert "same payee P-1" in a.description

    def test_ignores_when_spread_beyond_window(self):
        assert self.det.detect([txn(0), txn(200), txn(400)]) == []  # first..third = 6m40s

    def test_ignores_different_amounts(self):
        assert self.det.detect([txn(0, amount="100.00"), txn(30, amount="100.01"), txn(60)]) == []

    def test_ignores_different_accounts(self):
        assert self.det.detect([txn(0, "A"), txn(30, "B"), txn(60, "C")]) == []

    def test_ignores_different_currencies(self):
        assert self.det.detect([txn(0), txn(30, currency="EUR"), txn(60)]) == []

    def test_overlapping_windows_merge_into_one_burst(self):
        events = [txn(i * 100) for i in range(8)]  # every 100s for ~12 min
        [a] = self.det.detect(events)
        assert a.metrics["count"] == 8
        assert a.severity is Severity.HIGH

    def test_separate_bursts_are_reported_separately(self):
        events = [txn(0), txn(30), txn(60), txn(3600), txn(3630), txn(3660)]
        assert len(self.det.detect(events)) == 2

    def test_high_value_escalates(self):
        events = [txn(0, amount="4000.00"), txn(30, amount="4000.00"), txn(60, amount="4000.00")]
        [a] = self.det.detect(events)
        assert a.severity is Severity.HIGH

    def test_multiple_payees_described(self):
        [a] = self.det.detect([txn(0, payee="X"), txn(30, payee="Y"), txn(60, payee="Z")])
        assert "3 different payees" in a.description


class TestVelocity:
    def test_flags_count_over_limit(self):
        det = VelocityDetector(window_minutes=10, max_count=5)
        events = [txn(i * 30, amount=f"{10 + i}.00") for i in range(6)]
        [a] = det.detect(events)
        assert a.metrics["count"] == 6

    def test_flags_total_over_limit(self):
        det = VelocityDetector(window_minutes=10, max_count=100, max_total=1000)
        [a] = det.detect([txn(0, amount="600.00"), txn(60, amount="500.00")])
        assert a.metrics["total"] == Decimal("1100.00")

    def test_quiet_account_not_flagged(self):
        det = VelocityDetector(window_minutes=10, max_count=5)
        assert det.detect([txn(i * 700) for i in range(10)]) == []


class TestStructuring:
    det = StructuringDetector(threshold=10_000, margin_pct=10, window_hours=24, min_count=3)

    def test_flags_amounts_just_under_threshold(self):
        events = [txn(0, amount="9500.00"), txn(3600, amount="9990.00"), txn(7200, amount="9001.00")]
        [a] = self.det.detect(events)
        assert a.severity is Severity.HIGH
        assert "9000" in a.description

    def test_threshold_and_below_margin_are_not_counted(self):
        events = [txn(0, amount="10000.00"), txn(60, amount="8999.99"), txn(120, amount="9500.00")]
        assert self.det.detect(events) == []
