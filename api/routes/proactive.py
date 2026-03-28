"""Proactive defense status/pools/kills route handlers."""

from __future__ import annotations

from aiohttp import web

from api.routes.helpers import _ok


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/proactive/status", get_proactive_status)
    app.router.add_get("/api/v1/proactive/php/pools", get_proactive_php_pools)
    app.router.add_get("/api/v1/proactive/kills", get_proactive_kills)


async def get_proactive_status(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")

    return _ok({
        "process_kill_enabled": killer.enabled if killer else False,
        "process_kill_count": killer.kill_count if killer else 0,
    })


async def get_proactive_php_pools(request: web.Request) -> web.Response:
    scanner = request.app.get("php_pool_scanner")
    if scanner is None:
        from lib.proactive.php_hardener import PHPPoolScanner
        scanner = PHPPoolScanner()

    pools = await scanner.scan_pools()
    return _ok([p.model_dump() for p in pools])


async def get_proactive_kills(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")
    if not killer:
        return _ok([])

    records = killer.recent_kills
    return _ok([r.model_dump(mode="json") for r in records])
