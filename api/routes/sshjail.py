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
    app.router.add_get("/api/v1/ssh/keys", get_ssh_keys)
    app.router.add_post("/api/v1/ssh/keys", post_ssh_key)
    app.router.add_delete("/api/v1/ssh/keys/{key_id}", delete_ssh_key)
    app.router.add_post("/api/v1/ssh/keys/generate", post_ssh_key_generate)
    app.router.add_get("/api/v1/ssh/shell/status", get_shell_status)
    app.router.add_post("/api/v1/ssh/shell/enable", post_shell_enable)
    app.router.add_post("/api/v1/ssh/shell/disable", post_shell_disable)


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
        status = await sshjail.get_shell_status(username)
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

    logger.info("SSH shell enable: user=%s", username)
    try:
        success, message = await sshjail.enable_shell(username)
    except Exception:
        logger.exception("Failed to enable shell for %s", username)
        return _err("Failed to enable shell", 500)

    if not success:
        logger.warning("SSH shell enable failed for %s: %s", username, message)
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

    logger.info("SSH shell disable: user=%s", username)
    try:
        success, message = await sshjail.disable_shell(username)
    except Exception:
        logger.exception("Failed to disable shell for %s", username)
        return _err("Failed to disable shell", 500)

    if not success:
        logger.warning("SSH shell disable failed for %s: %s", username, message)
        return _err("Failed to disable shell", 500)

    return _ok({"disabled": True, "username": username})
