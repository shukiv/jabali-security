"""REST API route handlers for jabali-security."""

from __future__ import annotations

import ipaddress
import logging
import re
import resource
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from lib.config import DEFAULTS, update_conf_key
from lib.constants import CONFIG_FILE, VERSION
from lib.models import FileEvent
from lib.system_tools import run_freshclam
from lib.tenant import resolve_user

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


# -- Response helpers --------------------------------------------------------

def _ok(data) -> web.Response:
    return web.json_response({"success": True, "data": data, "error": None})


def _err(msg: str, status: int = 400) -> web.Response:
    return web.json_response(
        {"success": False, "data": None, "error": msg}, status=status,
    )


# -- Route registration ------------------------------------------------------

def setup_routes(app: web.Application) -> None:
    """Register all API routes."""
    app.router.add_get("/api/v1/health", get_health)
    app.router.add_get("/api/v1/status", get_status)

    app.router.add_get("/api/v1/incidents", get_incidents)
    app.router.add_get("/api/v1/incidents/{id}", get_incident)
    app.router.add_post("/api/v1/incidents/{id}/resolve", post_resolve_incident)

    app.router.add_post("/api/v1/scan", post_scan)

    app.router.add_get("/api/v1/quarantine", get_quarantine)
    app.router.add_post("/api/v1/quarantine/{id}/restore", post_quarantine_restore)
    app.router.add_delete("/api/v1/quarantine/{id}", delete_quarantine)

    app.router.add_get("/api/v1/users", get_users)
    app.router.add_get("/api/v1/users/{username}", get_user)

    app.router.add_post("/api/v1/block", post_block)
    app.router.add_delete("/api/v1/block/{ip}", delete_block)
    app.router.add_get("/api/v1/blocklist", get_blocklist)

    app.router.add_get("/api/v1/config", get_config)
    app.router.add_patch("/api/v1/config", patch_config)

    app.router.add_get("/api/v1/rules", get_rules)
    app.router.add_post("/api/v1/rules/reload", post_rules_reload)


# -- Health / Status ---------------------------------------------------------

async def get_health(request: web.Request) -> web.Response:
    return _ok({"status": "ok"})


async def get_status(request: web.Request) -> web.Response:
    daemon = request.app["daemon"]
    incidents = request.app["incidents"]
    quarantine = request.app["quarantine"]

    mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KB to MB on Linux

    uptime = 0.0
    if daemon and daemon._start_time:
        uptime = (datetime.now(timezone.utc) - daemon._start_time).total_seconds()

    return _ok({
        "running": True,
        "version": VERSION,
        "uptime_seconds": round(uptime, 1),
        "incidents_24h": await incidents.count_recent(24),
        "quarantined_count": await quarantine.count(),
        "watched_dirs": daemon._watcher.watch_count if daemon and daemon._watcher else 0,
        "scan_queue_size": 0,
        "workers": request.app["config"].workers,
        "memory_mb": round(mem_mb, 1),
    })


# -- Incidents ---------------------------------------------------------------

async def get_incidents(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]

    # Parse and validate query parameters
    try:
        limit = int(request.query.get("limit", "50"))
    except (ValueError, TypeError):
        return _err("'limit' must be an integer")
    if limit < 1 or limit > 1000:
        return _err("'limit' must be between 1 and 1000")

    username = request.query.get("user") or None
    severity = request.query.get("severity") or None
    since = request.query.get("since") or None

    if severity and severity not in _VALID_SEVERITIES:
        return _err("'severity' must be one of: %s" % ", ".join(_VALID_SEVERITIES))

    results = await incidents.list_incidents(
        limit=limit, username=username, severity=severity, since=since,
    )
    return _ok([_incident_dict(inc) for inc in results])


async def get_incident(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    incident_id = request.match_info["id"]

    incident = await incidents.get(incident_id)
    if not incident:
        return _err("Incident not found", 404)

    return _ok(_incident_dict(incident))


async def post_resolve_incident(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    incident_id = request.match_info["id"]

    try:
        body = await request.json()
    except Exception:
        body = {}
    notes = str(body.get("notes", ""))

    resolved = await incidents.resolve(incident_id, notes)
    if not resolved:
        return _err("Incident not found", 404)

    return _ok({"resolved": True, "id": incident_id})


def _incident_dict(incident) -> dict:
    """Convert Incident model to JSON-safe dict."""
    return {
        "id": incident.id,
        "path": incident.file_event.path,
        "username": incident.username,
        "event_type": incident.file_event.event_type,
        "total_score": incident.total_score,
        "severity": incident.severity,
        "action_taken": incident.action_taken,
        "findings": [f.model_dump() for f in incident.findings],
        "timestamp": incident.timestamp.isoformat(),
        "resolved": incident.resolved,
        "notes": incident.notes,
    }


# -- On-demand scan ----------------------------------------------------------

async def post_scan(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    path = body.get("path")
    if not path or not isinstance(path, str):
        return _err("'path' is required")

    p = Path(path)

    # Reject symlinks before any file access
    if p.is_symlink():
        return _err("Symlinks not allowed")

    if not p.is_file():
        return _err("File not found: %s" % path, 404)

    content = p.read_bytes()

    scanner = request.app["scanner"]
    findings = await scanner.scan(path, content)

    scoring = request.app["scoring"]
    event = FileEvent(
        event_type="scan",
        path=path,
        username=resolve_user(path),
        size=len(content),
    )
    score = scoring.evaluate(event, findings)

    return _ok({
        "path": path,
        "findings": [f.model_dump() for f in findings],
        "score": score.total,
        "action": score.action,
        "severity": scoring.severity_from_score(score.total),
    })


# -- Quarantine --------------------------------------------------------------

async def get_quarantine(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    username = request.query.get("user") or None

    records = await incidents.list_quarantine(username)
    return _ok([_quarantine_dict(r) for r in records])


async def post_quarantine_restore(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    quarantine = request.app["quarantine"]
    record_id = request.match_info["id"]

    # Find the record in the database
    records = await incidents.list_quarantine()
    record = None
    for r in records:
        if r.id == record_id:
            record = r
            break

    if not record:
        return _err("Quarantine record not found", 404)

    restored = await quarantine.restore_file(record)
    if not restored:
        return _err("Failed to restore file", 500)

    await incidents.mark_quarantine_restored(record_id)
    return _ok({"restored": True, "id": record_id, "path": record.original_path})


async def delete_quarantine(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    quarantine = request.app["quarantine"]
    record_id = request.match_info["id"]

    # Find the record in the database
    records = await incidents.list_quarantine()
    record = None
    for r in records:
        if r.id == record_id:
            record = r
            break

    if not record:
        return _err("Quarantine record not found", 404)

    deleted = await quarantine.delete_quarantined(record)
    if not deleted:
        return _err("Failed to delete quarantined file", 500)

    await incidents.mark_quarantine_deleted(record_id)
    return _ok({"deleted": True, "id": record_id})


def _quarantine_dict(record) -> dict:
    """Convert QuarantineRecord to JSON-safe dict."""
    return {
        "id": record.id,
        "original_path": record.original_path,
        "quarantine_path": record.quarantine_path,
        "username": record.username,
        "timestamp": record.timestamp.isoformat(),
        "reason": record.reason,
        "incident_id": record.incident_id,
        "sha256": record.sha256,
        "restored": record.restored,
        "deleted": record.deleted,
    }


# -- Users -------------------------------------------------------------------

async def get_users(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    async with db.execute(
        "SELECT username, COUNT(*) AS count, MAX(total_score) AS max_score "
        "FROM incidents WHERE username IS NOT NULL GROUP BY username "
        "ORDER BY count DESC"
    ) as cursor:
        users = []
        async for row in cursor:
            users.append({
                "username": row[0],
                "incident_count": row[1],
                "max_score": row[2],
            })
    return _ok(users)


async def get_user(request: web.Request) -> web.Response:
    incidents_store = request.app["incidents"]
    username = request.match_info["username"]

    # Validate username: alphanumeric + underscore + hyphen + dot only
    if not re.match(r"^[a-zA-Z0-9._-]+$", username):
        return _err("Invalid username format")

    user_incidents = await incidents_store.list_incidents(limit=100, username=username)
    quarantine_records = await incidents_store.list_quarantine(username=username)

    return _ok({
        "username": username,
        "incidents": [_incident_dict(inc) for inc in user_incidents],
        "quarantine": [_quarantine_dict(r) for r in quarantine_records],
        "incident_count": len(user_incidents),
        "quarantine_count": len(quarantine_records),
    })


# -- IP blocking -------------------------------------------------------------

def _validate_ip(ip_str: str) -> bool:
    """Validate an IP address (IPv4 or IPv6) using the standard library."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


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
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    await db.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at, blocked_by) "
        "VALUES (?, ?, ?, ?, ?)",
        (ip, reason, now.isoformat(), expires_at, "api"),
    )
    await db.commit()

    return _ok({
        "blocked": True,
        "ip": ip,
        "reason": reason,
        "expires_at": expires_at,
    })


async def delete_block(request: web.Request) -> web.Response:
    ip = request.match_info["ip"]

    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    incidents = request.app["incidents"]
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    cursor = await db.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    await db.commit()

    if cursor.rowcount == 0:
        return _err("IP not found in blocklist", 404)

    return _ok({"unblocked": True, "ip": ip})


async def get_blocklist(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    blocked = []
    async with db.execute(
        "SELECT ip, reason, blocked_at, expires_at, blocked_by FROM blocked_ips ORDER BY blocked_at DESC"
    ) as cursor:
        async for row in cursor:
            blocked.append({
                "ip": row[0],
                "reason": row[1],
                "blocked_at": row[2],
                "expires_at": row[3],
                "blocked_by": row[4],
            })
    return _ok(blocked)


# -- Config ------------------------------------------------------------------

async def get_config(request: web.Request) -> web.Response:
    config = request.app["config"]
    data = {}
    for key in DEFAULTS:
        attr = key.lower()
        value = getattr(config, attr, None)
        if value is None:
            continue
        # Redact sensitive values
        if key == "API_KEY":
            data[key] = "set" if config.api_key else "unset"
        elif isinstance(value, list):
            data[key] = ",".join(value)
        elif isinstance(value, bool):
            data[key] = "yes" if value else "no"
        else:
            data[key] = str(value)
    return _ok(data)


async def patch_config(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    # Validate all keys before applying any changes
    invalid_keys = [k for k in body if k not in DEFAULTS]
    if invalid_keys:
        return _err("Unknown config keys: %s" % ", ".join(invalid_keys))

    updated = {}
    for key, value in body.items():
        str_value = str(value)
        update_conf_key(CONFIG_FILE, key, str_value)
        updated[key] = str_value

    # Redact API_KEY in response
    if "API_KEY" in updated:
        updated["API_KEY"] = "set" if updated["API_KEY"] else "unset"

    return _ok({"updated": updated, "note": "Restart daemon to apply runtime changes"})


# -- Rules -------------------------------------------------------------------

async def get_rules(request: web.Request) -> web.Response:
    config = request.app["config"]
    scanner = request.app["scanner"]

    rules_dir = Path(config.yara_rules_dir)
    yara_files = []
    if rules_dir.is_dir():
        for rule_file in sorted(rules_dir.glob("*.yar")):
            yara_files.append({
                "name": rule_file.name,
                "size": rule_file.stat().st_size,
            })

    clamav_available = False
    for name in scanner.scanner_names:
        if name == "clamav":
            clamav_available = True
            break

    return _ok({
        "yara_rules": yara_files,
        "yara_rules_dir": str(rules_dir),
        "yara_enabled": config.yara_enabled,
        "clamav_enabled": clamav_available,
        "scanners": scanner.scanner_names,
    })


async def post_rules_reload(request: web.Request) -> web.Response:
    config = request.app["config"]
    scanner = request.app["scanner"]

    # Reload YARA rules
    scanner.reload_rules()
    result = {"yara_reloaded": True}

    # Optionally run freshclam
    if config.freshclam_on_update:
        success, output = await run_freshclam()
        result["freshclam_success"] = success
        result["freshclam_output"] = output.strip() if output else ""
    else:
        result["freshclam_success"] = None
        result["freshclam_output"] = "freshclam_on_update is disabled"

    return _ok(result)
