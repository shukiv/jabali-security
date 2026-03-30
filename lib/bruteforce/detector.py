"""Brute-force detector — sliding window rate limiter with progressive blocking."""
from __future__ import annotations

import logging
import threading
import time
from collections import deque

from lib.bruteforce.models import AuthEvent, BlockDecision

logger = logging.getLogger(__name__)


class BruteForceDetector:
    """Detect brute-force attacks via sliding window per IP per service."""

    def __init__(
        self,
        thresholds: dict[str, tuple[int, int]] | None = None,
        block_durations: list[int] | None = None,
        whitelist: set[str] | None = None,
    ) -> None:
        """
        thresholds: {service: (max_attempts, window_seconds)}
        block_durations: progressive durations in seconds [600, 3600, 86400, 0]
                         0 = permanent
        whitelist: set of IPs to never block
        """
        self._thresholds = thresholds or {
            "ssh": (5, 300),
            "dovecot": (10, 600),
            "exim": (10, 600),
            "postfix": (10, 600),
        }
        self._block_durations = block_durations or [600, 3600, 86400, 0]
        self._whitelist = whitelist or set()

        # Per-IP attempt tracking: {ip: deque of timestamps}
        self._attempts: dict[str, deque[float]] = {}
        # Per-IP offense counter: {ip: offense_count}
        self._offenses: dict[str, int] = {}
        # Already blocked IPs (avoid re-blocking)
        self._blocked: set[str] = set()
        # Per-IP threshold multiplier (lower = stricter, from CrowdSec enrichment)
        self._urgency: dict[str, float] = {}
        self._last_cleanup = time.monotonic()
        self._lock = threading.Lock()

    def record(self, event: AuthEvent) -> BlockDecision | None:
        """Record a failed auth event. Returns BlockDecision if threshold exceeded."""
        with self._lock:
            if event.ip in self._whitelist:
                return None
            if event.ip in self._blocked:
                return None

            now = time.monotonic()
            self._maybe_cleanup(now)

            # Get threshold for this service
            base_threshold, window = self._thresholds.get(
                event.service, (10, 600)  # default: 10 attempts in 10 minutes
            )
            # Apply urgency multiplier (CrowdSec-enriched IPs have lower threshold)
            urgency = self._urgency.get(event.ip, 1.0)
            threshold = max(2, int(base_threshold * urgency))

            # Record attempt
            attempts = self._attempts.setdefault(event.ip, deque())
            attempts.append(now)

            # Trim to window
            cutoff = now - window
            while attempts and attempts[0] < cutoff:
                attempts.popleft()

            # Check threshold
            if len(attempts) >= threshold:
                offense = self._offenses.get(event.ip, 0) + 1
                self._offenses[event.ip] = offense
                self._blocked.add(event.ip)
                del self._attempts[event.ip]  # Stop tracking

                # Progressive duration
                idx = min(offense - 1, len(self._block_durations) - 1)
                duration = self._block_durations[idx]

                decision = BlockDecision(
                    ip=event.ip,
                    duration=duration,
                    reason="Brute-force: %d failed %s attempts in %ds (offense #%d)" % (
                        threshold,
                        event.service,
                        window,
                        offense,
                    ),
                    service=event.service,
                    attempt_count=threshold,
                    offense_number=offense,
                )
                logger.warning(
                    "BRUTE-FORCE: blocking %s for %s (%s, offense #%d)",
                    event.ip,
                    "%ds" % duration if duration else "permanent",
                    event.service,
                    offense,
                )
                return decision

            return None

    def unblock(self, ip: str) -> None:
        """Remove IP from blocked set (e.g., when block expires)."""
        with self._lock:
            self._blocked.discard(ip)
            self._urgency.pop(ip, None)

    def set_ip_urgency(self, ip: str, multiplier: float = 0.5) -> None:
        """Lower the threshold for an IP (CrowdSec enrichment).

        multiplier=0.5 means the IP needs half the normal attempts to trigger a block.
        """
        self._urgency[ip] = max(0.2, min(1.0, multiplier))

    def load_offenses(self, offenses: dict[str, int]) -> None:
        """Load offense counts from database (for progressive blocking across restarts)."""
        self._offenses.update(offenses)

    def _maybe_cleanup(self, now: float) -> None:
        """Evict stale entries every 60 seconds."""
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        stale = [ip for ip, dq in self._attempts.items() if not dq or dq[-1] < now - 3600]
        for ip in stale:
            del self._attempts[ip]

    @property
    def tracked_ips(self) -> int:
        return len(self._attempts)

    @property
    def blocked_count(self) -> int:
        return len(self._blocked)

    def add_to_whitelist(self, ip: str) -> None:
        with self._lock:
            self._whitelist.add(ip)

    def remove_from_whitelist(self, ip: str) -> None:
        with self._lock:
            self._whitelist.discard(ip)

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._whitelist

    def get_all_tracked(self) -> dict[str, dict]:
        """Return all tracked IPs with attempt counts (for attack mode)."""
        with self._lock:
            return {ip: {"count": len(dq)} for ip, dq in self._attempts.items()}
