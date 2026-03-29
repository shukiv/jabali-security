"""SSH jail management route handlers."""

from __future__ import annotations

import logging

from aiohttp import web

from api.routes.helpers import _err, _ok
from lib.sshjail.validators import (
    validate_key_id,
    validate_key_name,
    validate_key_type,
    validate_public_key,
    validate_username,
)

logger = logging.getLogger(__name__)


def setup_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/ssh/users", get_ssh_users)
    app.router.add_get("/api/v1/ssh/keys", get_ssh_keys)
    app.router.add_post("/api/v1/ssh/keys", post_ssh_key)
    app.router.add_delete("/api/v1/ssh/keys/{key_id}", delete_ssh_key)
    app.router.add_post("/api/v1/ssh/keys/generate", post_ssh_key_generate)
    app.router.add_get("/api/v1/ssh/shell/status", get_shell_status)
    app.router.add_post("/api/v1/ssh/shell/enable", post_shell_enable)
    app.router.add_post("/api/v1/ssh/shell/disable", post_shell_disable)
    app.router.add_get("/api/v1/ssh/password-auth", get_password_auth)
    app.router.add_post("/api/v1/ssh/password-auth", post_password_auth)
    app.router.add_get("/api/v1/ssh/sshd-settings", get_sshd_settings)
    app.router.add_post("/api/v1/ssh/sshd-settings", post_sshd_settings)


async def get_ssh_users(request: web.Request) -> web.Response:
    """List all hosting users (UID >= 1000) with shell status."""
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    import pwd
    users = []
    for pw in pwd.getpwall():
        if pw.pw_uid < 1000 or pw.pw_uid >= 65534:
            continue
        if not pw.pw_dir.startswith("/home/"):
            continue
        try:
            status = await sshjail.shell_status(pw.pw_name)
            key_count = len(await sshjail.list_keys(pw.pw_name))
            users.append({
                "username": pw.pw_name,
                "shell": status.shell,
                "shell_enabled": status.shell_enabled,
                "sftp_only": status.sftp_only,
                "key_count": key_count,
            })
        except Exception:
            users.append({
                "username": pw.pw_name,
                "shell": pw.pw_shell,
                "shell_enabled": pw.pw_shell != "/usr/sbin/nologin",
                "sftp_only": pw.pw_shell == "/usr/sbin/nologin",
                "key_count": 0,
            })
    return _ok(users)


async def get_ssh_keys(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        username = validate_username(request.query.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    try:
        keys = await sshjail.list_keys(username)
    except Exception:
        logger.exception("Failed to list SSH keys for %s", username)
        return _err("Failed to list SSH keys", 500)

    return _ok([k.model_dump() for k in keys])


async def post_ssh_key(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    try:
        username = validate_username(body.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    try:
        name = validate_key_name(body.get("name", ""))
    except ValueError as exc:
        return _err(str(exc))

    try:
        public_key = validate_public_key(body.get("public_key", ""))
    except ValueError as exc:
        return _err(str(exc))

    logger.info("SSH add key: user=%s name=%s", username, name)
    try:
        key = await sshjail.add_key(username, name, public_key)
    except Exception:
        logger.exception("Failed to add SSH key for %s", username)
        return _err("Failed to add SSH key", 500)

    return _ok(key.model_dump())


async def delete_ssh_key(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        key_id = validate_key_id(request.match_info["key_id"])
    except ValueError as exc:
        return _err(str(exc))

    try:
        username = validate_username(request.query.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    logger.info("SSH delete key: user=%s key_id=%s", username, key_id)
    try:
        success = await sshjail.delete_key(username, key_id)
    except Exception:
        logger.exception("Failed to delete SSH key %s for %s", key_id, username)
        return _err("Failed to delete SSH key", 500)

    if not success:
        return _err("SSH key not found", 404)

    return _ok({"deleted": True, "key_id": key_id})


async def post_ssh_key_generate(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    try:
        name = validate_key_name(body.get("name", ""))
    except ValueError as exc:
        return _err(str(exc))

    try:
        key_type = validate_key_type(body.get("type", ""))
    except ValueError as exc:
        return _err(str(exc))

    passphrase = body.get("passphrase", "")
    if not isinstance(passphrase, str):
        return _err("Passphrase must be a string")

    logger.info("SSH generate key: name=%s type=%s", name, key_type)
    try:
        result = await sshjail.generate_key(name, key_type, passphrase)
    except Exception:
        logger.exception("Failed to generate SSH key")
        return _err("Failed to generate SSH key", 500)

    return _ok(result.model_dump())


async def get_shell_status(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        username = validate_username(request.query.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    try:
        status = await sshjail.shell_status(username)
    except Exception:
        logger.exception("Failed to get shell status for %s", username)
        return _err("Failed to get shell status", 500)

    return _ok(status.model_dump())


async def post_shell_enable(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    try:
        username = validate_username(body.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    config = request.app.get("config")
    if config and not config.ssh_shell_access_enabled:
        return _err("Shell access management is disabled by administrator", 403)

    logger.info("SSH shell enable: user=%s", username)
    try:
        success = await sshjail.enable_shell(username)
    except Exception:
        logger.exception("Failed to enable shell for %s", username)
        return _err("Failed to enable shell", 500)

    if not success:
        logger.warning("SSH shell enable failed for %s", username)
        return _err("Failed to enable shell", 500)

    return _ok({"enabled": True, "username": username})


async def post_shell_disable(request: web.Request) -> web.Response:
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    try:
        username = validate_username(body.get("username", ""))
    except ValueError as exc:
        return _err(str(exc))

    config = request.app.get("config")
    if config and not config.ssh_shell_access_enabled:
        return _err("Shell access management is disabled by administrator", 403)

    logger.info("SSH shell disable: user=%s", username)
    try:
        success = await sshjail.disable_shell(username)
    except Exception:
        logger.exception("Failed to disable shell for %s", username)
        return _err("Failed to disable shell", 500)

    if not success:
        logger.warning("SSH shell disable failed for %s", username)
        return _err("Failed to disable shell", 500)

    return _ok({"disabled": True, "username": username})


async def get_password_auth(request: web.Request) -> web.Response:
    """Legacy endpoint -- returns password_auth from sshd settings."""
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        settings = await sshjail.get_sshd_settings()
    except Exception:
        logger.exception("Failed to read SSH password auth status")
        return _err("Failed to read SSH password auth status", 500)

    return _ok({"enabled": settings["password_auth"]})


async def post_password_auth(request: web.Request) -> web.Response:
    """Legacy endpoint -- updates only password_auth in sshd settings."""
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return _err("'enabled' must be a boolean (true/false)")

    logger.info("SSH password auth: setting to %s", "enabled" if enabled else "disabled")
    try:
        success = await sshjail.set_sshd_settings({"password_auth": enabled})
    except Exception:
        logger.exception("Failed to set SSH password auth")
        return _err("Failed to update SSH password authentication", 500)

    if not success:
        return _err("Failed to update SSH password authentication (sshd config test or reload failed)", 500)

    return _ok({"enabled": enabled})


async def get_sshd_settings(request: web.Request) -> web.Response:
    """Get sshd_config settings: password_auth, pubkey_auth, port."""
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        settings = await sshjail.get_sshd_settings()
    except Exception:
        logger.exception("Failed to read sshd settings")
        return _err("Failed to read sshd settings", 500)

    return _ok(settings)


async def post_sshd_settings(request: web.Request) -> web.Response:
    """Update sshd_config settings. Accepts: password_auth, pubkey_auth, port."""
    sshjail = request.app.get("sshjail")
    if not sshjail:
        return _err("SSH jail management not enabled", 404)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    # Validate inputs
    updates: dict = {}
    if "password_auth" in body:
        if not isinstance(body["password_auth"], bool):
            return _err("'password_auth' must be a boolean")
        updates["password_auth"] = body["password_auth"]

    if "pubkey_auth" in body:
        if not isinstance(body["pubkey_auth"], bool):
            return _err("'pubkey_auth' must be a boolean")
        updates["pubkey_auth"] = body["pubkey_auth"]

    if "port" in body:
        if not isinstance(body["port"], int) or body["port"] < 1 or body["port"] > 65535:
            return _err("'port' must be an integer between 1 and 65535")
        updates["port"] = body["port"]

    if not updates:
        return _err("No valid settings provided. Accepted: password_auth, pubkey_auth, port")

    logger.info("Updating sshd settings: %s", updates)
    try:
        success = await sshjail.set_sshd_settings(updates)
    except Exception:
        logger.exception("Failed to update sshd settings")
        return _err("Failed to update sshd settings", 500)

    if not success:
        return _err("Failed to update sshd settings (config test or reload failed)", 500)

    # Return current state after update
    try:
        current = await sshjail.get_sshd_settings()
    except Exception:
        current = updates

    return _ok(current)
