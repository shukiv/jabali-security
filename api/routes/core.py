"""Health and status route handlers."""

from __future__ import annotations

import resource
from datetime import datetime, timezone

from aiohttp import web

from api.routes.helpers import _ok
from lib.constants import VERSION


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/health", get_health)
    app.router.add_get("/api/v1/status", get_status)


async def get_health(request: web.Request) -> web.Response:
    return _ok({"status": "ok"})


async def get_status(request: web.Request) -> web.Response:
    daemon = request.app["daemon"]
    incidents = request.app["incidents"]
    quarantine = request.app["quarantine"]

    mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KB to MB on Linux

    uptime = 0.0
    if daemon and daemon._start_time:
        uptime = (datetime.now(timezone.utc) - daemon._start_time).total_seconds()

    # WAF events count
    waf_events_24h = 0
    if incidents:
        waf_stats = await incidents.get_waf_stats()
        waf_events_24h = waf_stats.get("total_events_24h", 0)

    # WebShield blocks
    webshield = request.app.get("webshield")
    webshield_blocked_24h = 0
    if webshield:
        config = request.app["config"]
        access_log = config.nginx_access_log if config else "/var/log/nginx/access.log"
        ws_status = webshield.get_status(access_log=access_log)
        webshield_blocked_24h = ws_status.bot_blocked_24h + ws_status.rate_limited_24h

    data = {
        "running": True,
        "version": VERSION,
        "uptime_seconds": round(uptime, 1),
        "incidents_24h": await incidents.count_recent(24),
        "quarantined_count": await quarantine.count(),
        "watched_dirs": daemon._registry.watcher.watch_count if daemon and daemon._registry else 0,
        "scan_queue_size": 0,
        "workers": request.app["config"].workers,
        "memory_mb": round(mem_mb, 1),
        "attacks_blocked_24h": waf_events_24h + webshield_blocked_24h,
        "waf_events_24h": waf_events_24h,
        "webshield_blocked_24h": webshield_blocked_24h,
    }

    return _ok(data)
