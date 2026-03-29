"""Brute-force stats/blocked/whitelist route handlers."""

from __future__ import annotations

from aiohttp import web

from api.routes.helpers import _err, _ok, _validate_ip


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/bruteforce/stats", get_bruteforce_stats)
    app.router.add_get("/api/v1/bruteforce/blocked", get_bruteforce_blocked)
    app.router.add_post("/api/v1/bruteforce/whitelist", post_bruteforce_whitelist)
    app.router.add_delete("/api/v1/bruteforce/whitelist/{ip}", delete_bruteforce_whitelist)


async def get_bruteforce_stats(request: web.Request) -> web.Response:
    detector = request.app.get("bruteforce_detector")
    if not detector:
        return _err("Brute-force protection not enabled", 404)
    return _ok({
        "tracked_ips": detector.tracked_ips,
        "blocked_count": detector.blocked_count,
    })


async def get_bruteforce_blocked(request: web.Request) -> web.Response:
    incidents = request.app.get("incidents")
    if not incidents:
        return _err("Incident store not available", 404)
    ips = await incidents.get_blocked_ips()
    return _ok({"blocked_ips": ips, "count": len(ips)})


async def post_bruteforce_whitelist(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    ip = body.get("ip")
    if not ip or not isinstance(ip, str):
        return _err("'ip' is required")

    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    detector = request.app.get("bruteforce_detector")
    if not detector:
        return _err("Brute-force protection not enabled", 404)

    detector._whitelist.add(ip)

    # Also unblock if currently blocked
    firewall = request.app.get("firewall")
    if firewall:
        await firewall.unblock_ip(ip)
    detector.unblock(ip)

    return _ok({"whitelisted": True, "ip": ip})


async def delete_bruteforce_whitelist(request: web.Request) -> web.Response:
    ip = request.match_info["ip"]

    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    detector = request.app.get("bruteforce_detector")
    if not detector:
        return _err("Brute-force protection not enabled", 404)

    if ip not in detector._whitelist:
        return _err("IP not in whitelist", 404)

    detector._whitelist.discard(ip)
    return _ok({"removed": True, "ip": ip})
