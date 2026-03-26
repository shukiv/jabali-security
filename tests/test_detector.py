"""Tests for lib.bruteforce.detector — BruteForceDetector."""

from __future__ import annotations

from lib.bruteforce.detector import BruteForceDetector
from lib.bruteforce.models import AuthEvent


def _make_auth_event(ip: str = "192.168.1.100", service: str = "ssh") -> AuthEvent:
    return AuthEvent(ip=ip, service=service, username="root", success=False)


class TestBelowThreshold:
    def test_single_attempt_no_block(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (5, 300)})
        result = detector.record(_make_auth_event())
        assert result is None

    def test_attempts_below_threshold_no_block(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (5, 300)})
        for _ in range(4):
            result = detector.record(_make_auth_event())
        assert result is None
        assert detector.blocked_count == 0


class TestAtThreshold:
    def test_threshold_reached_returns_block(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (5, 300)})
        result = None
        for _ in range(5):
            result = detector.record(_make_auth_event())
        assert result is not None
        assert result.ip == "192.168.1.100"
        assert result.service == "ssh"
        assert result.attempt_count == 5
        assert result.offense_number == 1

    def test_blocked_count_incremented(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (5, 300)})
        for _ in range(5):
            detector.record(_make_auth_event())
        assert detector.blocked_count == 1


class TestWhitelist:
    def test_whitelisted_ip_never_blocked(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            whitelist={"10.0.0.1"},
        )
        for _ in range(10):
            result = detector.record(_make_auth_event(ip="10.0.0.1"))
            assert result is None
        assert detector.blocked_count == 0

    def test_non_whitelisted_ip_blocked(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            whitelist={"10.0.0.1"},
        )
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip="10.0.0.2"))
        assert result is not None


class TestProgressiveBlocking:
    def test_first_offense_uses_first_duration(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            block_durations=[600, 3600, 86400, 0],
        )
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event())
        assert result is not None
        assert result.duration == 600
        assert result.offense_number == 1

    def test_second_offense_uses_second_duration(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            block_durations=[600, 3600, 86400, 0],
        )
        ip = "192.168.1.200"
        # First offense
        for _ in range(3):
            detector.record(_make_auth_event(ip=ip))
        # Unblock
        detector.unblock(ip)
        # Second offense
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip=ip))
        assert result is not None
        assert result.duration == 3600
        assert result.offense_number == 2

    def test_third_offense_uses_third_duration(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            block_durations=[600, 3600, 86400, 0],
        )
        ip = "192.168.1.201"
        # First two offenses
        for offense in range(2):
            for _ in range(3):
                detector.record(_make_auth_event(ip=ip))
            detector.unblock(ip)
        # Third offense
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip=ip))
        assert result is not None
        assert result.duration == 86400
        assert result.offense_number == 3

    def test_fourth_offense_permanent_block(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300)},
            block_durations=[600, 3600, 86400, 0],
        )
        ip = "192.168.1.202"
        for offense in range(3):
            for _ in range(3):
                detector.record(_make_auth_event(ip=ip))
            detector.unblock(ip)
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip=ip))
        assert result is not None
        assert result.duration == 0  # permanent
        assert result.offense_number == 4


class TestAlreadyBlocked:
    def test_already_blocked_ip_no_duplicate_decision(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (3, 300)})
        ip = "192.168.1.150"
        # Block the IP
        for _ in range(3):
            detector.record(_make_auth_event(ip=ip))
        # Additional attempts should return None (already blocked)
        for _ in range(5):
            result = detector.record(_make_auth_event(ip=ip))
            assert result is None


class TestUnblock:
    def test_unblock_allows_reblocking(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (3, 300)})
        ip = "192.168.1.160"
        for _ in range(3):
            detector.record(_make_auth_event(ip=ip))
        assert detector.blocked_count == 1
        detector.unblock(ip)
        # Now the IP can be blocked again
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip=ip))
        assert result is not None
        assert detector.blocked_count == 1


class TestCleanup:
    def test_cleanup_stale_entries(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (5, 300)})
        ip = "192.168.1.170"
        # Record a couple attempts
        detector.record(_make_auth_event(ip=ip))
        detector.record(_make_auth_event(ip=ip))
        assert detector.tracked_ips == 1

        # Force cleanup by manipulating _last_cleanup to be old
        import time
        detector._last_cleanup = time.monotonic() - 120
        # Make the attempt timestamps old (> 3600s ago)
        for dq in detector._attempts.values():
            for i in range(len(dq)):
                dq[i] = time.monotonic() - 7200
        # Trigger cleanup
        detector._maybe_cleanup(time.monotonic())
        assert detector.tracked_ips == 0


class TestMultipleServices:
    def test_different_services_tracked_separately(self) -> None:
        detector = BruteForceDetector(
            thresholds={"ssh": (3, 300), "dovecot": (5, 600)},
        )
        ip = "192.168.1.180"
        # 3 SSH attempts -> block
        result = None
        for _ in range(3):
            result = detector.record(_make_auth_event(ip=ip, service="ssh"))
        assert result is not None
        assert result.service == "ssh"

    def test_different_ips_tracked_separately(self) -> None:
        detector = BruteForceDetector(thresholds={"ssh": (3, 300)})
        # 2 attempts from IP A
        for _ in range(2):
            detector.record(_make_auth_event(ip="10.0.0.1"))
        # 2 attempts from IP B
        for _ in range(2):
            detector.record(_make_auth_event(ip="10.0.0.2"))
        # Neither should be blocked
        assert detector.blocked_count == 0
        assert detector.tracked_ips == 2
