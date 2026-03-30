"""CrowdSec LAPI integration endpoints."""

from __future__ import annotations

import logging

from aiohttp import web

from api.routes.helpers import _err, _ok

logger = logging.getLogger(__name__)


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/crowdsec/status", get_crowdsec_status)
    app.router.add_get("/api/v1/crowdsec/decisions", get_crowdsec_decisions)
    app.router.add_get("/api/v1/crowdsec/check/{ip}", get_crowdsec_check_ip)


async def get_crowdsec_status(request: web.Request) -> web.Response:
    """CrowdSec integration status: connected, decision count, last poll."""
    client = request.app.get("crowdsec")
    if not client:
        return _ok({
            "enabled": False,
            "connected": False,
            "lapi_url": "",
            "active_decisions": 0,
            "blocked_ips": 0,
            "last_poll": "",
            "error": "CrowdSec integration not enabled",
        })

    return _ok({
        "enabled": True,
        "connected": client.connected,
        "lapi_url": request.app["config"].crowdsec_lapi_url,
        "active_decisions": client.active_decisions_count,
        "blocked_ips": len(client.blocked_ips),
        "last_poll": client.last_poll,
        "error": client.error,
    })


async def get_crowdsec_decisions(request: web.Request) -> web.Response:
    """List all active CrowdSec decisions."""
    client = request.app.get("crowdsec")
    if not client:
        return _err("CrowdSec not enabled", 404)

    decisions = client.get_all_decisions()
    return _ok({"decisions": decisions, "count": len(decisions)})


async def get_crowdsec_check_ip(request: web.Request) -> web.Response:
    """Check a specific IP against CrowdSec decisions (cached + live query)."""
    client = request.app.get("crowdsec")
    if not client:
        return _err("CrowdSec not enabled", 404)

    ip = request.match_info["ip"]

    # Check in-memory cache first
    cached = client.check_ip(ip)
    score = client.check_ip_score(ip)

    # Also query LAPI live for the most current data
    live = await client.query_ip(ip)

    return _ok({
        "ip": ip,
        "cached_decisions": [d.model_dump() for d in cached],
        "live_decisions": live,
        "score": score,
        "is_blocked": len(cached) > 0,
    })
