"""Scoring engine — aggregate findings into threat scores and determine actions."""

from __future__ import annotations

import logging

from lib.config import JabaliConfig
from lib.models import FileEvent, Finding, ThreatScore

logger = logging.getLogger(__name__)


class ScoringEngine:
    def __init__(self, config: JabaliConfig) -> None:
        self._score_log = config.score_log
        self._score_quarantine = config.score_quarantine
        self._score_suspend = config.score_suspend

    def evaluate(self, event: FileEvent, findings: list[Finding]) -> ThreatScore:
        """Aggregate findings, apply context multipliers, determine action."""
        if not findings:
            return ThreatScore(total=0, findings=[], action="ignore")

        total = sum(f.score for f in findings)

        # Context multipliers
        if event.in_uploads_dir:
            total = int(total * 1.5)

        # Rapid file creation (age < 10 seconds from event timestamp)
        # Future: integrate with behavior tracker

        # Determine action
        action = self._determine_action(total)

        return ThreatScore(total=total, findings=findings, action=action)

    def _determine_action(self, score: int) -> str:
        if score >= self._score_suspend:
            return "suspend"
        if score >= self._score_quarantine:
            return "quarantine"
        if score >= self._score_log:
            return "log"
        return "ignore"

    @staticmethod
    def severity_from_score(score: int) -> str:
        if score >= 100:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
