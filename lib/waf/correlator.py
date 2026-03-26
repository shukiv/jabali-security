"""WAF event correlator — links WAF attacks with file-based detections."""
from __future__ import annotations

import logging

from lib.incidents import IncidentStore
from lib.waf.models import WafEvent

logger = logging.getLogger(__name__)


class WafCorrelator:
    """Correlate WAF events with file incidents for enhanced threat scoring."""

    def __init__(self, incidents: IncidentStore) -> None:
        self._incidents = incidents

    async def check_correlation(self, event: WafEvent) -> dict | None:
        """Check if a WAF event correlates with any file incidents."""
        if not event.uri or not self._incidents._db:
            return None

        # Check if the attacked URI path has any file incidents
        uri_path = event.uri.split("?")[0]
        db = self._incidents._db
        async with db.execute(
            "SELECT id, total_score, severity FROM incidents "
            "WHERE path LIKE ? ORDER BY created_at DESC LIMIT 1",
            ("%" + uri_path + "%",),
        ) as cursor:
            row = await cursor.fetchone()

        if row:
            logger.info(
                "WAF-file correlation: WAF attack on %s matches incident %s (score=%d)",
                event.uri, row[0], row[1],
            )
            return {
                "incident_id": row[0],
                "incident_score": row[1],
                "incident_severity": row[2],
                "waf_event_id": event.id,
                "correlation_type": "waf_attack_on_known_threat",
            }

        return None

    async def save_event(self, event: WafEvent) -> None:
        """Persist WAF event to database."""
        db = self._incidents._db
        if db is None:
            return
        await db.execute(
            """INSERT OR IGNORE INTO waf_events
               (id, client_ip, uri, method, rule_id, rule_msg, severity, action,
                hostname, username, matched_data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id, event.client_ip, event.uri[:500], event.method,
                event.rule_id, event.rule_msg[:500], event.severity, event.action,
                event.hostname[:200], event.username, event.matched_data[:200],
                event.timestamp.isoformat(),
            ),
        )
        await db.commit()
