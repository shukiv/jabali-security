"""Under Attack mode — panic button that activates aggressive defenses."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aiohttp import web

from api.routes.helpers import _err, _ok
from lib.config import load_config, update_conf_key
from lib.constants import CONFIG_FILE, DATA_DIR

logger = logging.getLogger(__name__)

_STATE_FILE = Path(DATA_DIR) / "attack_mode.json"

# Settings applied when Under Attack mode is enabled.
# Keys map to config keys, values are the aggressive settings.
_ATTACK_SETTINGS: dict[str, str] = {
    "PROCESS_KILL_ENABLED": "yes",
    "PROCESS_KILL_THRESHOLD": "50",
    "AUTO_BLOCK_IP": "yes",
    "AUTO_QUARANTINE": "yes",
    "BRUTEFORCE_SSH_THRESHOLD": "3",
    "BRUTEFORCE_SSH_WINDOW": "120",
    "BRUTEFORCE_MAIL_THRESHOLD": "3",
    "BRUTEFORCE_MAIL_WINDOW": "120",
    "BRUTEFORCE_BLOCK_DURATIONS": "3600,86400,0",
}


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/attack-mode", get_attack_mode)
    app.router.add_post("/api/v1/attack-mode/enable", post_enable)
    app.router.add_post("/api/v1/attack-mode/disable", post_disable)


async def get_attack_mode(request: web.Request) -> web.Response:
    active = _is_active()
    return _ok({"active": active, "settings": list(_ATTACK_SETTINGS.keys()) if active else []})


async def post_enable(request: web.Request) -> web.Response:
    if _is_active():
        return _ok({"active": True, "message": "Already in Under Attack mode"})

    # Save current values so we can restore them later
    config = request.app["config"]
    previous: dict[str, str] = {}
    for key in _ATTACK_SETTINGS:
        attr = key.lower()
        val = getattr(config, attr, None)
        if val is None:
            continue
        if isinstance(val, bool):
            previous[key] = "yes" if val else "no"
        elif isinstance(val, list):
            previous[key] = ",".join(str(v) for v in val)
        else:
            previous[key] = str(val)

    # Write state file
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps({"active": True, "previous": previous}), encoding="utf-8")

    # Apply aggressive settings
    for key, value in _ATTACK_SETTINGS.items():
        update_conf_key(CONFIG_FILE, key, value)

    # Reload in-memory config
    new_config = load_config(CONFIG_FILE)
    old_config = request.app["config"]
    for attr in vars(new_config):
        setattr(old_config, attr, getattr(new_config, attr))

    logger.warning("UNDER ATTACK mode ENABLED — aggressive defenses activated")
    return _ok({
        "active": True,
        "settings_applied": list(_ATTACK_SETTINGS.keys()),
        "message": "Under Attack mode enabled. Aggressive defenses activated.",
    })


async def post_disable(request: web.Request) -> web.Response:
    if not _is_active():
        return _ok({"active": False, "message": "Not in Under Attack mode"})

    # Read previous settings
    try:
        state = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        previous = state.get("previous", {})
    except (FileNotFoundError, json.JSONDecodeError):
        previous = {}

    # Restore previous settings
    for key, value in previous.items():
        update_conf_key(CONFIG_FILE, key, value)

    # Remove state file
    _STATE_FILE.unlink(missing_ok=True)

    # Reload in-memory config
    new_config = load_config(CONFIG_FILE)
    old_config = request.app["config"]
    for attr in vars(new_config):
        setattr(old_config, attr, getattr(new_config, attr))

    logger.warning("UNDER ATTACK mode DISABLED — restored normal settings")
    return _ok({
        "active": False,
        "settings_restored": list(previous.keys()),
        "message": "Under Attack mode disabled. Normal settings restored.",
    })


def _is_active() -> bool:
    try:
        state = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        return state.get("active", False)
    except (FileNotFoundError, json.JSONDecodeError):
        return False
