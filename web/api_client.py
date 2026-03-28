"""API client for Flask routes -- calls the daemon REST API."""
from __future__ import annotations

import json
import logging
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def api_call(method: str, path: str, body: dict | None = None) -> dict | list | None:
    """Call the daemon API via Unix socket or TCP fallback."""
    import http.client
    import socket as socket_mod

    from lib.config import parse_conf
    from lib.constants import CONFIG_FILE
    raw = parse_conf(CONFIG_FILE)
    api_key = raw.get("API_KEY", "")
    api_socket = raw.get("API_SOCKET", "/run/jabali-security/jabali-security.sock")

    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        if api_socket and os.path.exists(api_socket):
            conn = http.client.HTTPConnection("localhost")
            sock = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(api_socket)
            conn.sock = sock
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            result = json.loads(resp.read().decode())
            conn.close()
        else:
            # TCP fallback
            api_bind = raw.get("API_BIND", "127.0.0.1")
            api_port = raw.get("API_PORT", "9876")
            url = "http://%s:%s%s" % (api_bind, api_port, path)
            req = Request(url, data=data, headers=headers, method=method)  # noqa: S310
            with urlopen(req, timeout=10) as resp:  # noqa: S310
                result = json.loads(resp.read().decode())

        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return result
    except (URLError, OSError, json.JSONDecodeError) as exc:
        logger.error("API call failed: %s %s -- %s", method, path, exc)
        return None
