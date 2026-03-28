"""WebShield status/install/uninstall/rules/blocklist route handlers."""

from __future__ import annotations

from aiohttp import web

from api.routes.helpers import _err, _ok, _validate_ip


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/webshield/status", get_webshield_status)
    app.router.add_post("/api/v1/webshield/install", post_webshield_install)
    app.router.add_post("/api/v1/webshield/uninstall", post_webshield_uninstall)
    app.router.add_get("/api/v1/webshield/rules", get_webshield_rules)
    app.router.add_post("/api/v1/webshield/update-blocklist", post_webshield_update_blocklist)


async def get_webshield_status(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    config = request.app.get("config")
    access_log = config.nginx_access_log if config else "/var/log/nginx/access.log"
    status = webshield.get_status(access_log=access_log)
    return _ok(status.model_dump())


async def post_webshield_install(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    result = await webshield.install()
    if not result.get("success"):
        return _err(result.get("error", "Install failed"), 500)

    return _ok(result)


async def post_webshield_uninstall(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    result = await webshield.uninstall()
    return _ok(result)


async def get_webshield_rules(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    rules = webshield.get_rules()
    return _ok(rules)


async def post_webshield_update_blocklist(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    ips = body.get("ips")
    if not isinstance(ips, list):
        return _err("'ips' must be a list of IP addresses")

    # Validate each IP
    for ip in ips:
        if not isinstance(ip, str) or not _validate_ip(ip):
            return _err("Invalid IP address: %s" % ip)

    success = await webshield.update_blocked_ips(ips)
    if not success:
        return _err("Failed to write blocked IPs file", 500)

    return _ok({"updated": True, "count": len(ips)})
