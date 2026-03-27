"""IP block/unblock/blocklist route handlers."""

from __future__ import annotations

from datetime import datetime, timezone

from aiohttp import web

from api.routes.helpers import _err, _ok, _validate_ip


def setup_routes(app: web.Application) -> None:
    app.router.add_post("/api/v1/block", post_block)
    app.router.add_delete("/api/v1/block/{ip}", delete_block)
    app.router.add_get("/api/v1/blocklist", get_blocklist)


async def post_block(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    ip = body.get("ip")
    if not ip or not isinstance(ip, str):
        return _err("'ip' is required")

    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    reason = str(body.get("reason", "manual block"))
    duration = body.get("duration")

    now = datetime.now(timezone.utc)
    expires_at = None
    if duration is not None:
        try:
            duration = int(duration)
            if duration < 0:
                return _err("'duration' must be a positive integer (seconds)")
        except (ValueError, TypeError):
            return _err("'duration' must be an integer (seconds)")
        from datetime import timedelta
        expires_at = (now + timedelta(seconds=duration)).isoformat()

    incidents = request.app["incidents"]
    await incidents.save_blocked_ip(ip, reason, now.isoformat(), expires_at, "api")

    # Also block in firewall
    firewall = request.app.get("firewall")
    fw_ok = False
    if firewall:
        dur = int(duration) if duration else 0
        fw_ok = await firewall.block_ip(ip, dur)

    return _ok({
        "blocked": True,
        "ip": ip,
        "reason": reason,
        "expires_at": expires_at,
        "firewall": fw_ok,
    })


async def delete_block(request: web.Request) -> web.Response:
    ip = request.match_info["ip"]

    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    incidents = request.app["incidents"]
    deleted = await incidents.delete_blocked_ip(ip)

    if not deleted:
        return _err("IP not found in blocklist", 404)

    # Also unblock in firewall
    firewall = request.app.get("firewall")
    if firewall:
        await firewall.unblock_ip(ip)

    return _ok({"unblocked": True, "ip": ip})


async def get_blocklist(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    blocked = await incidents.get_blocked_ips()
    return _ok(blocked)
