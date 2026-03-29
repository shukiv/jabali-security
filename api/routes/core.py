"""Health and status route handlers."""

from __future__ import annotations

import asyncio
import resource
import time
from datetime import datetime, timezone

from aiohttp import web

from api.routes.helpers import _ok
from lib.constants import VERSION


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/health", get_health)
    app.router.add_get("/api/v1/status", get_status)
    app.router.add_post("/api/v1/daemon/restart", post_daemon_restart)


async def get_health(request: web.Request) -> web.Response:
    components: dict[str, str] = {}

    # Database check (short timeout)
    incidents = request.app.get("incidents")
    if incidents and incidents._db is not None:
        try:
            await asyncio.wait_for(incidents._db.execute("SELECT 1"), timeout=2.0)
            components["database"] = "ok"
        except Exception:
            components["database"] = "error"
    else:
        components["database"] = "unavailable"

    # Scanner check
    scanner = request.app.get("scanner")
    components["scanner"] = "ok" if scanner is not None else "unavailable"

    # Watcher check
    daemon = request.app.get("daemon")
    if daemon and daemon._registry and daemon._registry.watcher:
        watcher = daemon._registry.watcher
        components["watcher"] = "ok" if watcher.watch_count > 0 else "unavailable"
    else:
        components["watcher"] = "unavailable"

    # Uptime
    start_time = request.app.get("start_time")
    uptime_seconds = round(time.time() - start_time, 1) if start_time else 0

    # Overall status
    has_error = any(v.startswith("error") for v in components.values())
    status = "degraded" if has_error else "healthy"

    return _ok({
        "status": status,
        "components": components,
        "uptime_seconds": uptime_seconds,
    })


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


async def post_daemon_restart(request: web.Request) -> web.Response:
    """Restart the daemon via systemctl. Runs as root so this works."""
    import logging
    logger = logging.getLogger(__name__)
    logger.warning("Daemon restart requested via API")
    # Send response first, then restart
    response = _ok({"restarting": True, "message": "Daemon is restarting..."})
    # Schedule restart after response is sent
    asyncio.get_event_loop().call_later(1.0, _trigger_restart)
    return response


def _trigger_restart() -> None:
    """Trigger systemctl restart in a subprocess (non-blocking)."""
    import subprocess
    subprocess.Popen(  # noqa: S603
        ["/usr/bin/systemctl", "restart", "jabali-security"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
