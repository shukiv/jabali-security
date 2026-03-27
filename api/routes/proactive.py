"""Proactive defense status/pools/harden/kills route handlers."""

from __future__ import annotations

from aiohttp import web

from api.routes.helpers import _err, _ok


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/proactive/status", get_proactive_status)
    app.router.add_get("/api/v1/proactive/php/pools", get_proactive_php_pools)
    app.router.add_post("/api/v1/proactive/php/harden", post_proactive_php_harden)
    app.router.add_post("/api/v1/proactive/php/unharden", post_proactive_php_unharden)
    app.router.add_get("/api/v1/proactive/kills", get_proactive_kills)


async def get_proactive_status(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")
    hardener = request.app.get("php_hardener")

    return _ok({
        "process_kill_enabled": killer.enabled if killer else False,
        "process_kill_count": killer.kill_count if killer else 0,
        "php_hardening_enabled": hardener is not None and hardener.enabled,
    })


async def get_proactive_php_pools(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    pools = await hardener.scan_pools()
    return _ok([p.model_dump() for p in pools])


async def post_proactive_php_harden(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    harden_all = body.get("all", False)
    conf_path = body.get("conf_path")

    if harden_all:
        pools = await hardener.scan_pools()
        count = 0
        for pool in pools:
            if not pool.hardened:
                if await hardener.harden_pool(pool.socket_path):
                    count += 1
        return _ok({"hardened_count": count})

    if not conf_path or not isinstance(conf_path, str):
        return _err("'conf_path' is required (or set 'all': true)")

    # Validate conf_path is a real PHP-FPM pool config path
    if not conf_path.endswith(".conf"):
        return _err("conf_path must be a .conf file")

    success = await hardener.harden_pool(conf_path)
    if not success:
        return _err("Failed to harden pool at %s" % conf_path, 500)

    return _ok({"hardened": True, "conf_path": conf_path})


async def post_proactive_php_unharden(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    conf_path = body.get("conf_path")
    if not conf_path or not isinstance(conf_path, str):
        return _err("'conf_path' is required")

    if not conf_path.endswith(".conf"):
        return _err("conf_path must be a .conf file")

    success = await hardener.unharden_pool(conf_path)
    if not success:
        return _err("Failed to unharden pool at %s (no hardening block found)" % conf_path, 404)

    return _ok({"unhardened": True, "conf_path": conf_path})


async def get_proactive_kills(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")
    if not killer:
        return _ok([])

    records = killer.recent_kills
    return _ok([r.model_dump(mode="json") for r in records])
