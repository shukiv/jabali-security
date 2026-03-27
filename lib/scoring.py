"""Scoring engine — aggregate findings into threat scores and determine actions."""

from __future__ import annotations

import logging
from pathlib import PurePosixPath

from lib.config import JabaliConfig
from lib.models import FileEvent, Finding, ThreatScore

logger = logging.getLogger(__name__)

# Known CMS core directories — files here are likely legitimate
_CMS_CORE_DIRS = frozenset({
    "wp-admin", "wp-includes",  # WordPress
    "administrator", "libraries", "components",  # Joomla
    "core", "modules", "profiles",  # Drupal
})


class ScoringEngine:
    def __init__(self, config: JabaliConfig) -> None:
        self._score_log = config.score_log
        self._score_quarantine = config.score_quarantine
        self._score_suspend = config.score_suspend

    def evaluate(self, event: FileEvent, findings: list[Finding]) -> ThreatScore:
        """Aggregate findings, apply context multipliers, determine action."""
        if not findings:
            return ThreatScore(total=0, findings=[], action="ignore")

        # Check if file is in a known CMS core directory
        is_cms_core = self._is_cms_core_path(event.path)

        # In CMS core dirs: only YARA/ClamAV signature matches matter.
        # Heuristic, entropy, and behavior findings are noise from legitimate code.
        if is_cms_core:
            real_threats = [f for f in findings if f.scanner in ("yara", "clamav")]
            if not real_threats:
                # No signature matches — all findings are false positives from CMS code.
                # Cap action at "log" regardless of score.
                total = sum(f.score for f in findings)
                action = "log" if total >= self._score_log else "ignore"
                return ThreatScore(total=total, findings=findings, action=action)
            # Has real signature matches — score normally but only count those
            findings = real_threats

        total = sum(f.score for f in findings)

        # Context multipliers
        if event.in_uploads_dir:
            total = int(total * 1.5)

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
    def _is_cms_core_path(path: str) -> bool:
        """Check if a file path is inside a known CMS core directory."""
        parts = PurePosixPath(path).parts
        return any(part in _CMS_CORE_DIRS for part in parts)

    @staticmethod
    def severity_from_score(score: int) -> str:
        if score >= 100:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
