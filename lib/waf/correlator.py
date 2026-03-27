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
        if not event.uri:
            return None

        # Check if the attacked URI path has any file incidents
        uri_path = event.uri.split("?")[0]
        match = await self._incidents.find_incident_by_path("%" + uri_path + "%")

        if match:
            logger.info(
                "WAF-file correlation: WAF attack on %s matches incident %s (score=%d)",
                event.uri, match["id"], match["total_score"],
            )
            return {
                "incident_id": match["id"],
                "incident_score": match["total_score"],
                "incident_severity": match["severity"],
                "waf_event_id": event.id,
                "correlation_type": "waf_attack_on_known_threat",
            }

        return None

    async def save_event(self, event: WafEvent) -> None:
        """Persist WAF event to database."""
        await self._incidents.save_waf_event(event)
