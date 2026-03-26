# REST API Reference

Base URL: `http://127.0.0.1:9876/api/v1/`

## Authentication

All endpoints (except `/health`) require an API key via the `X-API-Key` header.

```bash
curl -H "X-API-Key: YOUR_KEY" http://127.0.0.1:9876/api/v1/status
```

The API key is auto-generated on install and stored in the config file.

## Response Format

All responses follow this envelope:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

On error:

```json
{
  "success": false,
  "data": null,
  "error": "Description of the error"
}
```

HTTP status codes: `200` success, `400` bad request, `404` not found, `500` internal error.

---

## Health / Status

### GET /health

Health check endpoint. No authentication required.

**Response:**
```json
{ "status": "ok" }
```

### GET /status

Daemon status and runtime statistics.

**Response:**
```json
{
  "running": true,
  "version": "0.1.0",
  "uptime_seconds": 3661.2,
  "incidents_24h": 12,
  "quarantined_count": 3,
  "watched_dirs": 48,
  "scan_queue_size": 0,
  "workers": 2,
  "memory_mb": 42.5
}
```

---

## Incidents

### GET /incidents

List security incidents.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 50 | Max results (1-1000) |
| `user` | string | -- | Filter by username |
| `severity` | string | -- | Filter: `low`, `medium`, `high`, `critical` |
| `since` | string | -- | ISO timestamp lower bound |

**Response:**
```json
[
  {
    "id": "a1b2c3d4e5f6g7h8",
    "path": "/home/user1/public_html/wp-content/uploads/shell.php",
    "username": "user1",
    "event_type": "create",
    "total_score": 85,
    "severity": "high",
    "action_taken": "quarantine",
    "findings": [
      {
        "scanner": "heuristic",
        "rule": "php_obfuscated_call",
        "score": 50,
        "description": "Obfuscated function call pattern detected"
      }
    ],
    "timestamp": "2026-03-27T10:30:00+00:00",
    "resolved": false,
    "notes": ""
  }
]
```

### GET /incidents/{id}

Get a single incident by ID.

**Response:** Same structure as a single item in the list above.

### POST /incidents/{id}/resolve

Mark an incident as resolved.

**Body:**
```json
{ "notes": "False positive, whitelisted" }
```

**Response:**
```json
{ "resolved": true, "id": "a1b2c3d4e5f6g7h8" }
```

---

## Scanning

### POST /scan

Scan a single file on demand.

**Body:**
```json
{
  "path": "/home/user1/public_html/index.php",
  "recursive": false
}
```

**Response:**
```json
{
  "path": "/home/user1/public_html/index.php",
  "findings": [],
  "score": 0,
  "action": "ignore",
  "severity": "low"
}
```

### POST /scan/full

Trigger a full scheduled scan immediately.

**Response:**
```json
{ "started": true }
```

### GET /scan/scheduled

Get scheduled scan status.

**Response:**
```json
{
  "enabled": true,
  "interval_hours": 24,
  "paths": ["/home/*/public_html"],
  "last_run": "2026-03-26T02:00:00+00:00",
  "next_run": "2026-03-27T02:00:00+00:00"
}
```

### POST /scan/database

Scan a MySQL database for injected payloads.

**Body:**
```json
{
  "database": "wp_user1",
  "user": "root",
  "host": "localhost",
  "cms_type": "wordpress",
  "table_prefix": "wp_"
}
```

**Response:**
```json
{
  "database": "wp_user1",
  "findings_count": 2,
  "findings": [
    {
      "table": "wp_posts",
      "column": "post_content",
      "row_id": "142",
      "pattern": "js_inject",
      "description": "Injected JavaScript found"
    }
  ]
}
```

### POST /scan/rapid

Fast parallel directory scan with mtime cache.

**Body:**
```json
{ "path": "/home/user1/public_html" }
```

**Response:**
```json
{
  "directory": "/home/user1/public_html",
  "files_scanned": 1240,
  "files_skipped": 890,
  "threats_found": 2,
  "results": [
    { "path": "/home/user1/public_html/shell.php", "score": 85, "action": "quarantine" }
  ]
}
```

---

## Quarantine

### GET /quarantine

List quarantined files.

| Parameter | Type | Description |
|---|---|---|
| `user` | string | Filter by username |

**Response:**
```json
[
  {
    "id": "f1e2d3c4b5a69788",
    "original_path": "/home/user1/public_html/shell.php",
    "quarantine_path": "/var/security/quarantine/user1/f1e2d3c4b5a69788",
    "username": "user1",
    "timestamp": "2026-03-27T10:30:00+00:00",
    "reason": "Score 85 exceeded quarantine threshold",
    "incident_id": "a1b2c3d4e5f6g7h8",
    "sha256": "e3b0c44298fc...",
    "restored": false,
    "deleted": false
  }
]
```

### POST /quarantine/{id}/restore

Restore a quarantined file to its original location.

**Response:**
```json
{ "restored": true, "id": "f1e2d3c4b5a69788", "path": "/home/user1/public_html/shell.php" }
```

### DELETE /quarantine/{id}

Permanently delete a quarantined file.

**Response:**
```json
{ "deleted": true, "id": "f1e2d3c4b5a69788" }
```

---

## Users

### GET /users

List users with incident counts.

**Response:**
```json
[
  { "username": "user1", "incident_count": 5, "max_score": 85 }
]
```

### GET /users/{username}

Get full risk profile for a user.

**Response:**
```json
{
  "username": "user1",
  "incidents": [ ... ],
  "quarantine": [ ... ],
  "incident_count": 5,
  "quarantine_count": 1
}
```

---

## IP Blocking

### POST /block

Block an IP address.

**Body:**
```json
{
  "ip": "192.168.1.100",
  "reason": "manual block",
  "duration": 3600
}
```

| Field | Type | Description |
|---|---|---|
| `ip` | string | IPv4 or IPv6 address (required) |
| `reason` | string | Block reason |
| `duration` | int | Seconds (0 = permanent) |

**Response:**
```json
{
  "blocked": true,
  "ip": "192.168.1.100",
  "reason": "manual block",
  "expires_at": "2026-03-27T11:30:00+00:00",
  "firewall": true
}
```

### DELETE /block/{ip}

Unblock an IP address.

**Response:**
```json
{ "unblocked": true, "ip": "192.168.1.100" }
```

### GET /blocklist

List all blocked IPs.

**Response:**
```json
[
  {
    "ip": "192.168.1.100",
    "reason": "bruteforce",
    "blocked_at": "2026-03-27T10:30:00+00:00",
    "expires_at": "2026-03-27T11:30:00+00:00",
    "blocked_by": "auto"
  }
]
```

---

## Configuration

### GET /config

Get current configuration. `API_KEY` is redacted to "set"/"unset".

**Response:**
```json
{
  "LOG_LEVEL": "info",
  "WORKERS": "2",
  "API_KEY": "set",
  "YARA_ENABLED": "yes"
}
```

### PATCH /config

Update configuration keys. Persists to config file. Restart daemon for runtime changes.

**Body:**
```json
{ "LOG_LEVEL": "debug", "WORKERS": "4" }
```

**Response:**
```json
{
  "updated": { "LOG_LEVEL": "debug", "WORKERS": "4" },
  "note": "Restart daemon to apply runtime changes"
}
```

---

## Rules

### GET /rules

List loaded detection rules.

**Response:**
```json
{
  "yara_rules": [
    { "name": "webshells.yar", "size": 4096 },
    { "name": "exploits.yar", "size": 2048 }
  ],
  "yara_rules_dir": "/usr/local/jabali-security/rules",
  "yara_enabled": true,
  "clamav_enabled": true,
  "scanners": ["heuristic", "entropy", "yara", "clamav"]
}
```

### POST /rules/reload

Reload YARA rules and optionally run freshclam.

**Response:**
```json
{
  "yara_reloaded": true,
  "freshclam_success": true,
  "freshclam_output": "ClamAV update process started..."
}
```

---

## Brute-Force Protection

### GET /bruteforce/stats

**Response:**
```json
{ "tracked_ips": 42, "blocked_count": 3 }
```

### GET /bruteforce/blocked

**Response:**
```json
{ "blocked_ips": ["192.168.1.100", "10.0.0.50"], "count": 2 }
```

### POST /bruteforce/whitelist

Add IP to brute-force whitelist.

**Body:**
```json
{ "ip": "192.168.1.1" }
```

**Response:**
```json
{ "whitelisted": true, "ip": "192.168.1.1" }
```

### DELETE /bruteforce/whitelist/{ip}

Remove IP from whitelist.

**Response:**
```json
{ "removed": true, "ip": "192.168.1.1" }
```

---

## WAF (ModSecurity)

### GET /waf/events

List WAF events.

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (1-1000, default 50) |
| `ip` | string | Filter by client IP |
| `rule_id` | int | Filter by ModSecurity rule ID |
| `since` | string | ISO timestamp lower bound |

**Response:**
```json
[
  {
    "id": "abc123",
    "client_ip": "203.0.113.50",
    "uri": "/wp-login.php",
    "method": "POST",
    "rule_id": 942100,
    "rule_msg": "SQL Injection Attack Detected",
    "severity": "CRITICAL",
    "action": "deny",
    "hostname": "example.com",
    "username": "user1",
    "matched_data": "1=1",
    "created_at": "2026-03-27T10:30:00+00:00"
  }
]
```

### GET /waf/rules

List CRS rule files and disabled rules.

**Response:**
```json
{
  "web_server": "nginx",
  "rule_files": [
    { "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "size": 45000 }
  ],
  "disabled_rules": [942100, 942200]
}
```

### POST /waf/rules/{rule_id}/disable

Disable a ModSecurity rule.

**Response:**
```json
{ "disabled": true, "rule_id": 942100, "web_server_reloaded": true }
```

### POST /waf/rules/{rule_id}/enable

Enable a previously disabled rule.

**Response:**
```json
{ "enabled": true, "rule_id": 942100, "web_server_reloaded": true }
```

### GET /waf/stats

WAF statistics for the last 24 hours.

**Response:**
```json
{
  "total_events_24h": 156,
  "blocked_24h": 42,
  "top_ips": [
    { "ip": "203.0.113.50", "count": 25 }
  ],
  "top_rules": [
    { "rule_id": 942100, "count": 18, "rule_msg": "SQL Injection Attack Detected" }
  ]
}
```

### POST /waf/crs/update

Update OWASP Core Rule Set.

**Response:**
```json
{ "success": true, "version": "4.0.0", "rules_count": 42 }
```

---

## Proactive Defense

### GET /proactive/status

**Response:**
```json
{
  "process_kill_enabled": true,
  "process_kill_count": 5,
  "php_hardening_enabled": true
}
```

### GET /proactive/php/pools

List PHP-FPM pools and hardening status.

**Response:**
```json
[
  {
    "pool_name": "user1",
    "php_version": "8.3",
    "user": "user1",
    "hardened": true,
    "issues": []
  }
]
```

### POST /proactive/php/harden

Harden PHP-FPM pools.

**Body (all pools):**
```json
{ "all": true }
```

**Body (single pool):**
```json
{ "conf_path": "/etc/php/8.3/fpm/pool.d/user1.conf" }
```

**Response:**
```json
{ "hardened_count": 5 }
```

### POST /proactive/php/unharden

Remove hardening from a pool.

**Body:**
```json
{ "conf_path": "/etc/php/8.3/fpm/pool.d/user1.conf" }
```

### GET /proactive/kills

List recent process kills.

**Response:**
```json
[
  {
    "id": "abc123",
    "pid": 12345,
    "ppid": 1000,
    "username": "user1",
    "score": 85,
    "success": true,
    "reason": "Suspicious process tree"
  }
]
```

---

## Cleanup

### GET /cleanup/records

List recent cleanup operations.

**Response:**
```json
[
  {
    "id": "abc123",
    "path": "/home/user1/public_html/index.php",
    "strategy": "injection_removal",
    "success": true,
    "backup_path": "/var/lib/jabali-security/backups/abc123",
    "username": "user1",
    "created_at": "2026-03-27T10:30:00+00:00"
  }
]
```

### POST /cleanup/file

Clean a specific file.

**Body:**
```json
{ "path": "/home/user1/public_html/index.php" }
```

**Response:**
```json
{
  "success": true,
  "changes_made": ["Removed injected script tag at line 42"],
  "backup_path": "/var/lib/jabali-security/backups/abc123"
}
```

---

## Threat Intelligence

### GET /threat-intel/feeds

List feed statuses.

**Response:**
```json
[
  {
    "name": "spamhaus_drop",
    "feed_type": "ip",
    "entry_count": 1200,
    "last_update": "2026-03-27T06:00:00+00:00"
  }
]
```

### POST /threat-intel/update

Trigger immediate update of all enabled feeds.

**Response:**
```json
{
  "success_count": 4,
  "total_count": 4,
  "updated": {
    "spamhaus_drop": true,
    "spamhaus_edrop": true,
    "blocklist_de_all": true,
    "malwarebazaar_recent": true
  }
}
```

### GET /threat-intel/check/ip/{ip}

Check an IP against threat intelligence feeds.

**Response:**
```json
{
  "ip": "203.0.113.50",
  "is_malicious": true,
  "score": 3,
  "feeds": ["spamhaus_drop", "blocklist_de_all", "tor_exit_nodes"]
}
```

### GET /threat-intel/check/hash/{hash}

Check a SHA-256 hash against threat intelligence feeds.

| Parameter | Type | Description |
|---|---|---|
| `remote` | flag | Add `?remote=1` to also check remote APIs |

**Response:**
```json
{
  "hash": "e3b0c44298fc...",
  "is_malicious": true,
  "score": 2,
  "feeds": ["malwarebazaar_recent"],
  "details": {
    "signature": "Backdoor.PHP.WebShell",
    "file_type": "php"
  }
}
```

---

## WebShield

### GET /webshield/status

**Response:**
```json
{
  "installed": true,
  "nginx_available": true,
  "rate_limiting": true,
  "bot_filtering": true,
  "challenge_enabled": true,
  "blocked_ips_count": 12,
  "config_dir": "/etc/nginx/jabali-security"
}
```

### POST /webshield/install

Install WebShield nginx configuration files.

**Response:**
```json
{
  "success": true,
  "files_written": ["/etc/nginx/jabali-security/rate-limit.conf"],
  "nginx_config_valid": true,
  "note": "Include the config snippets in your nginx server blocks"
}
```

### POST /webshield/uninstall

Remove WebShield nginx configuration files.

**Response:**
```json
{ "files_removed": ["/etc/nginx/jabali-security/rate-limit.conf"] }
```

### GET /webshield/rules

List bot detection rules.

**Response:**
```json
[
  {
    "name": "bad_bot_ua",
    "action": "block",
    "category": "bot",
    "pattern": "MJ12bot|AhrefsBot",
    "enabled": true
  }
]
```

### POST /webshield/update-blocklist

Update the WebShield IP blocklist from threat intelligence data.

---

## Error Codes

| HTTP Code | Meaning |
|---|---|
| 200 | Success |
| 400 | Bad request (invalid parameters, missing fields) |
| 404 | Resource not found (incident, quarantine record, IP, feature not enabled) |
| 500 | Internal server error (database unavailable, scan failure) |
