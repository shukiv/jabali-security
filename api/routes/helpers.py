"""Shared response helpers and validators for API route handlers."""

from __future__ import annotations

import ipaddress

from aiohttp import web


def _ok(data) -> web.Response:
    return web.json_response({"success": True, "data": data, "error": None})


def _err(msg: str, status: int = 400) -> web.Response:
    return web.json_response(
        {"success": False, "data": None, "error": msg}, status=status,
    )


def _validate_ip(ip_str: str) -> bool:
    """Validate an IP address (IPv4 or IPv6) using the standard library."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _validate_path(path: str, allowed_roots: list[str] | None = None) -> bool:
    """Validate a file path is under allowed directories (default: /home/)."""
    from pathlib import Path

    if not path or not isinstance(path, str):
        return False

    resolved = str(Path(path).resolve())

    if allowed_roots is None:
        allowed_roots = ["/home/", "/var/www/"]

    return any(resolved.startswith(root) for root in allowed_roots)
