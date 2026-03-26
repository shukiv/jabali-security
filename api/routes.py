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

    app.router.add_get("/api/v1/bruteforce/stats", get_bruteforce_stats)
    app.router.add_get("/api/v1/bruteforce/blocked", get_bruteforce_blocked)
    app.router.add_post("/api/v1/bruteforce/whitelist", post_bruteforce_whitelist)
    app.router.add_delete("/api/v1/bruteforce/whitelist/{ip}", delete_bruteforce_whitelist)

    app.router.add_get("/api/v1/waf/events", get_waf_events)
    app.router.add_get("/api/v1/waf/rules", get_waf_rules)
    app.router.add_post("/api/v1/waf/rules/{rule_id}/disable", post_waf_rule_disable)
    app.router.add_post("/api/v1/waf/rules/{rule_id}/enable", post_waf_rule_enable)
    app.router.add_get("/api/v1/waf/stats", get_waf_stats)
    app.router.add_post("/api/v1/waf/crs/update", post_waf_crs_update)

    app.router.add_get("/api/v1/proactive/status", get_proactive_status)
    app.router.add_get("/api/v1/proactive/php/pools", get_proactive_php_pools)
    app.router.add_post("/api/v1/proactive/php/harden", post_proactive_php_harden)
    app.router.add_post("/api/v1/proactive/php/unharden", post_proactive_php_unharden)
    app.router.add_get("/api/v1/proactive/kills", get_proactive_kills)

    app.router.add_get("/api/v1/cleanup/records", get_cleanup_records)
    app.router.add_post("/api/v1/cleanup/file", post_cleanup_file)
    app.router.add_post("/api/v1/scan/full", post_scan_full)
    app.router.add_get("/api/v1/scan/scheduled", get_scan_scheduled)

    app.router.add_get("/api/v1/threat-intel/feeds", get_threat_intel_feeds)
    app.router.add_post("/api/v1/threat-intel/update", post_threat_intel_update)
    app.router.add_get("/api/v1/threat-intel/check/ip/{ip}", get_threat_intel_check_ip)
    app.router.add_get("/api/v1/threat-intel/check/hash/{hash}", get_threat_intel_check_hash)

    app.router.add_get("/api/v1/webshield/status", get_webshield_status)
    app.router.add_post("/api/v1/webshield/install", post_webshield_install)
    app.router.add_post("/api/v1/webshield/uninstall", post_webshield_uninstall)
    app.router.add_get("/api/v1/webshield/rules", get_webshield_rules)
    app.router.add_post("/api/v1/webshield/update-blocklist", post_webshield_update_blocklist)


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


# -- Brute-force protection --------------------------------------------------

async def get_bruteforce_stats(request: web.Request) -> web.Response:
    detector = request.app.get("bruteforce_detector")
    if not detector:
        return _err("Brute-force protection not enabled", 404)
    return _ok({
        "tracked_ips": detector.tracked_ips,
        "blocked_count": detector.blocked_count,
    })


async def get_bruteforce_blocked(request: web.Request) -> web.Response:
    firewall = request.app.get("firewall")
    if not firewall:
        return _err("Firewall not available", 404)
    ips = await firewall.list_blocked()
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


# -- WAF (ModSecurity) -------------------------------------------------------

async def get_waf_events(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    try:
        limit = int(request.query.get("limit", "50"))
    except (ValueError, TypeError):
        return _err("'limit' must be an integer")
    if limit < 1 or limit > 1000:
        return _err("'limit' must be between 1 and 1000")

    conditions: list[str] = []
    params: list[str | int] = []

    ip_filter = request.query.get("ip")
    if ip_filter:
        if not _validate_ip(ip_filter):
            return _err("Invalid IP address format")
        conditions.append("client_ip = ?")
        params.append(ip_filter)

    rule_filter = request.query.get("rule_id")
    if rule_filter:
        try:
            rule_id_val = int(rule_filter)
        except (ValueError, TypeError):
            return _err("'rule_id' must be an integer")
        conditions.append("rule_id = ?")
        params.append(rule_id_val)

    since = request.query.get("since")
    if since:
        conditions.append("created_at >= ?")
        params.append(since)

    where = " AND ".join(conditions)
    query = "SELECT id, client_ip, uri, method, rule_id, rule_msg, severity, action, hostname, username, matched_data, created_at FROM waf_events"
    if where:
        query += " WHERE " + where
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    events = []
    async with db.execute(query, params) as cursor:
        async for row in cursor:
            events.append({
                "id": row[0],
                "client_ip": row[1],
                "uri": row[2],
                "method": row[3],
                "rule_id": row[4],
                "rule_msg": row[5],
                "severity": row[6],
                "action": row[7],
                "hostname": row[8],
                "username": row[9],
                "matched_data": row[10],
                "created_at": row[11],
            })
    return _ok(events)


async def get_waf_rules(request: web.Request) -> web.Response:
    waf_rules = request.app.get("waf_rules")
    if not waf_rules:
        return _err("WAF not enabled", 404)

    rule_files = await waf_rules.list_rules()
    disabled = waf_rules.list_disabled()

    return _ok({
        "rule_files": rule_files,
        "disabled_rules": disabled,
        "web_server": waf_rules.web_server,
    })


async def post_waf_rule_disable(request: web.Request) -> web.Response:
    waf_rules = request.app.get("waf_rules")
    if not waf_rules:
        return _err("WAF not enabled", 404)

    try:
        rule_id = int(request.match_info["rule_id"])
    except (ValueError, TypeError):
        return _err("rule_id must be an integer")
    if rule_id < 1 or rule_id > 9999999:
        return _err("rule_id out of valid range")

    reloaded = await waf_rules.disable_rule(rule_id)
    return _ok({
        "disabled": True,
        "rule_id": rule_id,
        "web_server_reloaded": reloaded,
    })


async def post_waf_rule_enable(request: web.Request) -> web.Response:
    waf_rules = request.app.get("waf_rules")
    if not waf_rules:
        return _err("WAF not enabled", 404)

    try:
        rule_id = int(request.match_info["rule_id"])
    except (ValueError, TypeError):
        return _err("rule_id must be an integer")
    if rule_id < 1 or rule_id > 9999999:
        return _err("rule_id out of valid range")

    reloaded = await waf_rules.enable_rule(rule_id)
    return _ok({
        "enabled": True,
        "rule_id": rule_id,
        "web_server_reloaded": reloaded,
    })


async def get_waf_stats(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    db = incidents._db
    if db is None:
        return _err("Database not available", 500)

    # Total events in last 24 hours
    async with db.execute(
        "SELECT COUNT(*) FROM waf_events WHERE created_at >= datetime('now', '-24 hours')"
    ) as cursor:
        row = await cursor.fetchone()
        total_24h = row[0] if row else 0

    # Blocked events in last 24 hours
    async with db.execute(
        "SELECT COUNT(*) FROM waf_events WHERE created_at >= datetime('now', '-24 hours') AND action = 'deny'"
    ) as cursor:
        row = await cursor.fetchone()
        blocked_24h = row[0] if row else 0

    # Top IPs
    top_ips = []
    async with db.execute(
        "SELECT client_ip, COUNT(*) AS cnt FROM waf_events "
        "WHERE created_at >= datetime('now', '-24 hours') "
        "GROUP BY client_ip ORDER BY cnt DESC LIMIT 10"
    ) as cursor:
        async for row in cursor:
            top_ips.append({"ip": row[0], "count": row[1]})

    # Top rules
    top_rules = []
    async with db.execute(
        "SELECT rule_id, rule_msg, COUNT(*) AS cnt FROM waf_events "
        "WHERE created_at >= datetime('now', '-24 hours') AND rule_id > 0 "
        "GROUP BY rule_id ORDER BY cnt DESC LIMIT 10"
    ) as cursor:
        async for row in cursor:
            top_rules.append({"rule_id": row[0], "rule_msg": row[1], "count": row[2]})

    # Top URIs
    top_uris = []
    async with db.execute(
        "SELECT uri, COUNT(*) AS cnt FROM waf_events "
        "WHERE created_at >= datetime('now', '-24 hours') "
        "GROUP BY uri ORDER BY cnt DESC LIMIT 10"
    ) as cursor:
        async for row in cursor:
            top_uris.append({"uri": row[0], "count": row[1]})

    return _ok({
        "total_events_24h": total_24h,
        "blocked_24h": blocked_24h,
        "top_ips": top_ips,
        "top_rules": top_rules,
        "top_uris": top_uris,
    })


async def post_waf_crs_update(request: web.Request) -> web.Response:
    config = request.app["config"]

    from lib.waf.crs_updater import CRSUpdater
    updater = CRSUpdater(rules_dir=config.waf_rules_dir)
    result = await updater.update()

    if not result.get("success"):
        return _err(result.get("error", "CRS update failed"), 500)

    return _ok(result)


# -- Proactive Defense -------------------------------------------------------

async def get_proactive_status(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")
    hardener = request.app.get("php_hardener")

    return _ok({
        "process_kill_enabled": killer.enabled if killer else False,
        "process_kill_count": killer.kill_count if killer else 0,
        "php_hardening_enabled": hardener is not None and hardener.enabled,
    })


async def get_proactive_php_pools(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    pools = await hardener.scan_pools()
    return _ok([p.model_dump() for p in pools])


async def post_proactive_php_harden(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    harden_all = body.get("all", False)
    conf_path = body.get("conf_path")

    if harden_all:
        pools = await hardener.scan_pools()
        count = 0
        for pool in pools:
            if not pool.hardened:
                if await hardener.harden_pool(pool.socket_path):
                    count += 1
        return _ok({"hardened_count": count})

    if not conf_path or not isinstance(conf_path, str):
        return _err("'conf_path' is required (or set 'all': true)")

    # Validate conf_path is a real PHP-FPM pool config path
    if not conf_path.endswith(".conf"):
        return _err("conf_path must be a .conf file")

    success = await hardener.harden_pool(conf_path)
    if not success:
        return _err("Failed to harden pool at %s" % conf_path, 500)

    return _ok({"hardened": True, "conf_path": conf_path})


async def post_proactive_php_unharden(request: web.Request) -> web.Response:
    hardener = request.app.get("php_hardener")
    if hardener is None:
        from lib.proactive.php_hardener import PHPHardener
        hardener = PHPHardener(enabled=False)

    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    if not isinstance(body, dict):
        return _err("Request body must be a JSON object")

    conf_path = body.get("conf_path")
    if not conf_path or not isinstance(conf_path, str):
        return _err("'conf_path' is required")

    if not conf_path.endswith(".conf"):
        return _err("conf_path must be a .conf file")

    success = await hardener.unharden_pool(conf_path)
    if not success:
        return _err("Failed to unharden pool at %s (no hardening block found)" % conf_path, 404)

    return _ok({"unhardened": True, "conf_path": conf_path})


async def get_proactive_kills(request: web.Request) -> web.Response:
    killer = request.app.get("proactive_killer")
    if not killer:
        return _ok([])

    records = killer.recent_kills
    return _ok([r.model_dump(mode="json") for r in records])


# -- Cleanup -----------------------------------------------------------------

async def get_cleanup_records(request: web.Request) -> web.Response:
    incidents = request.app["incidents"]
    records = await incidents.list_cleanups(limit=50)
    return _ok(records)


async def post_cleanup_file(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return _err("Invalid JSON body")

    path = body.get("path")
    if not path or not isinstance(path, str):
        return _err("'path' is required")

    p = Path(path)
    if p.is_symlink():
        return _err("Symlinks not allowed")
    if not p.is_file():
        return _err("File not found", 404)

    cleanup = request.app.get("cleanup")
    if not cleanup:
        return _err("Cleanup engine not available", 503)

    result = await cleanup.clean_file(path)
    # Save to DB
    await request.app["incidents"].save_cleanup(result)
    return _ok(result.model_dump())


# -- Scheduled Scan ----------------------------------------------------------

async def post_scan_full(request: web.Request) -> web.Response:
    scheduler = request.app.get("scheduler")
    if not scheduler:
        return _err("Scan scheduler not available", 503)

    import asyncio
    asyncio.create_task(scheduler.run_now())
    return _ok({"started": True, "status": scheduler.status})


async def get_scan_scheduled(request: web.Request) -> web.Response:
    scheduler = request.app.get("scheduler")
    if not scheduler:
        return _ok({"enabled": False})
    return _ok(scheduler.status)


# -- Threat Intelligence -----------------------------------------------------

_VALID_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


async def get_threat_intel_feeds(request: web.Request) -> web.Response:
    feed_mgr = request.app.get("threat_intel")
    if not feed_mgr:
        return _err("Threat intelligence not enabled", 404)

    feeds = []
    for fs in feed_mgr.feed_statuses:
        feeds.append({
            "name": fs.name,
            "source_url": fs.source_url,
            "last_update": fs.last_update.isoformat() if fs.last_update else None,
            "entry_count": fs.entry_count,
            "enabled": fs.enabled,
            "feed_type": fs.feed_type,
        })
    return _ok(feeds)


async def post_threat_intel_update(request: web.Request) -> web.Response:
    feed_mgr = request.app.get("threat_intel")
    if not feed_mgr:
        return _err("Threat intelligence not enabled", 404)

    results = await feed_mgr.update_all()
    success = sum(1 for v in results.values() if v)
    return _ok({
        "updated": results,
        "success_count": success,
        "total_count": len(results),
    })


async def get_threat_intel_check_ip(request: web.Request) -> web.Response:
    feed_mgr = request.app.get("threat_intel")
    if not feed_mgr:
        return _err("Threat intelligence not enabled", 404)

    ip = request.match_info["ip"]
    if not _validate_ip(ip):
        return _err("Invalid IP address format")

    result = feed_mgr.check_ip(ip)
    return _ok(result.model_dump())


async def get_threat_intel_check_hash(request: web.Request) -> web.Response:
    feed_mgr = request.app.get("threat_intel")
    if not feed_mgr:
        return _err("Threat intelligence not enabled", 404)

    hash_val = request.match_info["hash"]
    if not _VALID_SHA256_RE.match(hash_val):
        return _err("Invalid SHA-256 hash format (expected 64 hex characters)")

    # Check local first, then optionally remote
    remote = request.query.get("remote", "").lower() in ("1", "true", "yes")
    if remote:
        result = await feed_mgr.check_hash_remote(hash_val)
    else:
        result = feed_mgr.check_hash(hash_val)

    return _ok(result.model_dump())


# -- WebShield ---------------------------------------------------------------

async def get_webshield_status(request: web.Request) -> web.Response:
    webshield = request.app.get("webshield")
    if not webshield:
        return _err("WebShield not enabled", 404)

    status = webshield.get_status()
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
