"""API client for Flask routes -- calls the daemon REST API."""
from __future__ import annotations

import json
import logging
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def api_call(method: str, path: str, body: dict | None = None) -> dict | list | None:
    """Call the daemon API. Returns parsed data payload or None on error."""
    # Read API key fresh from config file each time (not cached at app startup)
    from lib.config import parse_conf
    from lib.constants import CONFIG_FILE
    raw = parse_conf(CONFIG_FILE)
    api_key = raw.get("API_KEY", "")
    api_bind = raw.get("API_BIND", "127.0.0.1")
    api_port = raw.get("API_PORT", "9876")
    url = "http://%s:%s%s" % (api_bind, api_port, path)

    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        req = Request(url, data=data, headers=headers, method=method)  # noqa: S310
        with urlopen(req, timeout=10) as resp:  # noqa: S310
            result = json.loads(resp.read().decode())
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return result
    except (URLError, OSError, json.JSONDecodeError) as exc:
        logger.error("API call failed: %s %s -- %s", method, path, exc)
        return None
