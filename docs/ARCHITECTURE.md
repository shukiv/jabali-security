# Architecture

Technical architecture of Jabali Security.

## System Overview

```
+------------------------------------------------------------------+
|                        jabali-security daemon                     |
|                                                                   |
|  +-----------+   +------------+   +-----------+   +------------+ |
|  | Watcher   |   | Scan Queue |   | Detection |   | Response   | |
|  | (inotify) +-->| (asyncio)  +-->| Engines   +-->| Engine     | |
|  +-----------+   +------+-----+   +-----------+   +------+-----+ |
|                         |                                 |       |
|  +-----------+   +------+-----+   +-----------+   +------+-----+ |
|  | Process   |   | Scan       |   | Scoring   |   | Incident   | |
|  | Monitor   |   | Workers    |   | Engine    |   | Store (DB) | |
|  +-----------+   +------------+   +-----------+   +------------+ |
|                                                                   |
|  +-----------+   +------------+   +-----------+   +------------+ |
|  | Auth Log  |   | BruteForce |   | Firewall  |   | WAF Rule   | |
|  | Parser    +-->| Detector   +-->| Manager   |   | Manager    | |
|  +-----------+   +------------+   +-----------+   +------------+ |
|                                                                   |
|  +-----------+   +------------+   +-----------+   +------------+ |
|  | Threat    |   | Cleanup    |   | WebShield |   | PHP-FPM    | |
|  | Intel     |   | Engine     |   | Manager   |   | Hardener   | |
|  +-----------+   +------------+   +-----------+   +------------+ |
|                                                                   |
|  +-----------+   +------------+   +-----------+                    |
|  | REST API  |   | Scan       |   | UFW       |                    |
|  | (aiohttp) |   | Scheduler  |   | Manager   |                    |
|  +-----------+   +------------+   +-----------+                    |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|                    Web Dashboard (separate process)                |
|                    Flask + Waitress on :8443                       |
|                    Communicates via REST API                       |
+------------------------------------------------------------------+
```

## Components

### Daemon (`daemon/`)

| File | Purpose |
|---|---|
| `__main__.py` | CLI entry point (click). 30+ commands for all subsystems. |
| `server.py` | `SecurityDaemon` -- async supervisor that starts all subsystems via `asyncio.TaskGroup`. |

The daemon uses a single async event loop. On startup it builds a `ComponentRegistry`, starts the API server (Unix socket at `/run/jabali-security/jabali-security.sock`), file watcher, scan workers, and all enabled optional subsystems as concurrent tasks.

### Component Registry (`lib/registry.py`)

`ComponentRegistry` is a dataclass that constructs and holds every runtime component. It provides:

- `build()` -- async class method that constructs all components based on config
- Context manager (`__aenter__`/`__aexit__`) for lifecycle (DB open/close, watcher stop, cache save)
- `populate_app()` -- injects components into the aiohttp app for route handlers
- `background_tasks()` -- returns the list of async tasks to run in the TaskGroup

Optional components (brute-force, WAF, cleanup, threat intel, WebShield, PHP hardener) are only instantiated when their feature flag is enabled.

### File Watcher (`lib/watcher/`)

- `inotify.py` -- `InotifyWatcher` wraps Linux inotify to watch configured directories recursively
- Watches for CREATE, MODIFY, CLOSE_WRITE, MOVED_TO events
- Handles IN_DELETE_SELF for watched directory deletion (graceful removal from watch list)
- Passes matching file paths through `PreFilter` before queuing
- Default `WATCH_DIRS`: `/home/*/public_html`, `/home/*/domains/*/public_html`, `/home/*/tmp`

### Pre-Filter (`lib/filter.py`)

Fast path-level filtering before scanning:
- Extension allowlist (`.php`, `.js`, `.py`, etc.)
- Max file size check
- Skip directories (`.git`, `node_modules`, `vendor`, etc.)

### Scanners (`lib/scanner/`)

| Scanner | File | Description |
|---|---|---|
| **Heuristic** | `heuristic.py` | 17 regex patterns for high-confidence attack indicators (eval+base64, user input execution, obfuscation chains, reverse shells). WordPress/Joomla false-positive patterns removed; YARA rules cover those. |
| **Entropy** | `entropy.py` | Shannon entropy analysis to detect obfuscated/encoded payloads |
| **YARA-X** | `yara_engine.py` | YARA-X (Rust-based) signature matching using `.yar` rule files |
| **ClamAV** | `clamav.py` | Optional clamd socket scanning, auto-detected |
| **Database** | `database.py` | MySQL table scanning for injected payloads in CMS tables |

All scanners implement `ScannerBase` (in `base.py`) and return `list[Finding]`.

`ScanOrchestrator` runs all enabled scanners concurrently via `asyncio.gather()`.

### Scoring Engine (`lib/scoring.py`)

Aggregates `Finding` scores into a `ThreatScore` with an action decision:

| Score Range | Severity | Action |
|---|---|---|
| 0 - SCORE_LOG | -- | `ignore` |
| SCORE_LOG - SCORE_QUARANTINE | low/medium | `log` |
| SCORE_QUARANTINE - SCORE_SUSPEND | high | `quarantine` |
| >= SCORE_SUSPEND | critical | `suspend` |

Default thresholds: log=40, quarantine=70, suspend=100.

**CMS-aware scoring:** Files in known CMS core directories (wp-admin, wp-includes, administrator, etc.) and known WordPress root files (wp-config.php, wp-login.php, etc.) are treated differently. In these paths, only YARA and ClamAV signature matches are considered real threats; heuristic and entropy findings are capped at the "log" action to avoid false positives from legitimate CMS code.

### Response Engine (`lib/response.py`)

Executes the action determined by scoring:
- **log** -- saves incident to database
- **quarantine** -- moves file to quarantine directory, records metadata
- **suspend** -- (optional) suspends the hosting account

Also triggers cleanup (if enabled and `CLEANUP_AUTO=yes`) before quarantine.

### Incident Store (`lib/incidents.py`)

SQLite database via `aiosqlite` with tables for incidents, quarantine, blocked IPs, WAF events, and cleanup records. All database access is encapsulated behind public async methods (no direct `_db` access from outside the class). Key methods: `save()`, `get()`, `list_incidents()`, `count_recent()`, `resolve()`, `list_quarantine()`, `save_blocked_ip()`, `get_blocked_ips()`, `delete_blocked_ip()`, `save_waf_event()`, `get_waf_events()`, `get_waf_stats()`, `get_user_stats()`, `get_user_detail()`, `find_incident_by_path()`. See [Database Schema](#database-schema).

### Brute-Force Protection (`lib/bruteforce/`)

| File | Purpose |
|---|---|
| `log_parser.py` | Tails auth logs (SSH, Dovecot, Postfix, Exim, Stalwart) for failed login events. Uses `AsyncLogTailer` for rotation-safe tailing. |
| `detector.py` | Sliding window counter per IP per service; triggers block on threshold |
| `firewall.py` | `FirewallManager` -- auto-detects nftables/iptables; block/unblock IPs |
| `models.py` | Data models for auth events and block records |

Progressive blocking: durations escalate per repeat offense (default: 10m, 1h, 1d, permanent).

### WAF Integration (`lib/waf/`)

| File | Purpose |
|---|---|
| `audit_log_parser.py` | Parses ModSecurity audit logs (serial or concurrent format) |
| `rule_manager.py` | Manages OWASP CRS rules: list, disable, enable, update |

### Proactive Defense (`lib/proactive/`)

| File | Purpose |
|---|---|
| `php_hardener.py` | Scans PHP-FPM pool configs, adds `disable_functions` and `open_basedir`. Disabled by default; skips pools that already have disable_functions and open_basedir set (e.g. by hosting panels) |
| `process_killer.py` | Kills suspicious processes above score threshold (respects min UID + whitelist). Uses graceful shutdown: SIGTERM first, waits 5 seconds, then SIGKILL if still alive. |

### Malware Cleanup (`lib/cleanup/`)

| File | Purpose |
|---|---|
| `engine.py` | Orchestrates cleanup: backup, clean, verify |
| `cms_cleaner.py` | CMS-specific integrity checks using official checksums |
| `injection_patterns.py` | Regex patterns for common injection types |
| `scheduler.py` | Scheduled periodic scans |
| `models.py` | Cleanup record data models |

### Threat Intelligence (`lib/threat_intel/`)

- `feed_manager.py` -- downloads and caches IP/hash feeds on a schedule
- Supported feeds: Spamhaus DROP/EDROP, blocklist.de, Tor exit nodes, MalwareBazaar
- IP and hash lookup APIs for real-time checking

### WebShield (`lib/webshield/`)

- `manager.py` -- generates nginx config snippets for rate limiting, JS challenges, and bot UA filtering
- Install generates nginx config snippets that must be included in the nginx `http{}` and `server{}` blocks; nginx must be reloaded manually
- Install/uninstall manages files in the nginx config directory

### UFW Firewall Management (`lib/ufw/`)

| File | Purpose |
|---|---|
| `manager.py` | Wraps the `ufw` CLI via async subprocess for rule CRUD, enable/disable/reload, and app profile listing |
| `validators.py` | Input validation for IPs, ports, protocols, and rule parameters |
| `models.py` | Pydantic data models for UFW rules, status, and app profiles |

Separate from the nftables/iptables-based IP blocking in `lib/bruteforce/firewall.py`. The brute-force firewall manager handles automatic per-IP blocking for intrusion prevention, while the UFW module provides full firewall rule management (port rules, app profiles, direction, logging) exposed via REST API.

Disabled by default (`UFW_ENABLED="no"`). Requires `ufw` to be installed on the system.

### Other Core Modules

| Module | File | Purpose |
|---|---|---|
| AsyncLogTailer | `lib/log_tailer.py` | Reusable async log file tailer with rotation/truncation detection. Used by brute-force log parser. |
| Behavior Tracker | `lib/behavior_tracker.py` | Tracks file lifecycle (CREATE -> MODIFY -> EXECUTE) |
| Process Monitor | `lib/process_monitor.py` | Polls `/proc` for suspicious process trees |
| Quarantine Manager | `lib/quarantine.py` | File move/restore/delete with metadata |
| Tenant Resolution | `lib/tenant.py` | Maps file paths to hosting account usernames |
| Notifications | `lib/notify.py` | Email and webhook alerts |
| Hash Cache | `lib/hash_cache.py` | Persistent hash cache to skip re-scanning known files |
| RapidScan | `lib/rapidscan.py` | Parallel directory scanner with mtime-based caching |
| Config | `lib/config.py` | KEY=VALUE config parser, typed `JabaliConfig` dataclass |
| Constants | `lib/constants.py` | Paths, version, app name |

### REST API (`api/`)

| File | Purpose |
|---|---|
| `app.py` | aiohttp application factory with middleware |
| `middleware.py` | API key authentication, request logging |
| `routes/__init__.py` | Route registration -- imports and calls all domain sub-routers |
| `routes/core.py` | Health check, status |
| `routes/incidents.py` | Incident CRUD |
| `routes/scanning.py` | On-demand, full, scheduled, database, and rapid scan |
| `routes/quarantine.py` | Quarantine list, restore, delete |
| `routes/users.py` | User risk scores and profiles |
| `routes/blocking.py` | IP block/unblock/blocklist |
| `routes/config.py` | Config get/patch |
| `routes/rules.py` | YARA/ClamAV rule management |
| `routes/bruteforce.py` | Brute-force stats, blocked, whitelist |
| `routes/waf.py` | WAF events, rules, stats |
| `routes/proactive.py` | PHP hardening, process kills |
| `routes/cleanup.py` | Cleanup records and operations |
| `routes/threat_intel.py` | Threat intel feeds, IP/hash checks |
| `routes/webshield.py` | WebShield status, install, rules |
| `routes/ufw.py` | UFW firewall status, rules CRUD, enable/disable/reload, app profiles |
| `routes/helpers.py` | Shared response helpers (`_ok`, `_err`) |

### Web Dashboard (`web/`)

| File | Purpose |
|---|---|
| `app.py` | Flask application factory with security headers |
| `routes.py` | Dashboard routes, feature toggle handlers |
| `api_client.py` | HTTP client that talks to the REST API |
| `templates/` | Jinja2 templates (20 pages) |
| `static/` | CSS and JavaScript |

The web dashboard is a separate process (systemd service `jabali-security-web`). It communicates with the daemon exclusively through the REST API via the Unix socket.

### Jabali Panel Plugin (`panel/`)

| File | Purpose |
|---|---|
| `JabaliSecurityPlugin.php` | Filament v5 plugin class |
| `JabaliSecurityClient.php` | HTTP client for daemon API |
| `Pages/Security.php` | Single page with tabs (Overview, Incidents, Quarantine, Blocklist, Firewall, Config) |
| `Widgets/SecurityStatsWidget.php` | Stats overview widget |
| `views/security.blade.php` | Blade view template |

The panel plugin is deployed to `/var/www/jabali/app/JabaliSecurity/` on servers with Jabali Panel. It communicates with the daemon through the same REST API via the Unix socket. See [PARITY.md](PARITY.md) for feature comparison between the two interfaces.

## Data Flow

### File Event Pipeline

```
1. inotify event (CREATE/MODIFY/CLOSE_WRITE/MOVED_TO)
       |
2. PreFilter (extension, size, skip dirs)
       |
3. ScanQueue (async queue)
       |
4. Scan Worker picks up event
       |
5. ScanOrchestrator runs scanners concurrently:
   - HeuristicScanner -> list[Finding]
   - EntropyScanner   -> list[Finding]
   - YaraEngine        -> list[Finding]
   - ClamavScanner     -> list[Finding]
       |
6. ScoringEngine aggregates findings -> ThreatScore
       |
7. BehaviorTracker updates file lifecycle
       |
8. ResponseEngine executes action:
   - ignore: no action
   - log:    save incident to DB
   - quarantine: cleanup (optional) -> move file -> save incident
   - suspend: quarantine + suspend account
       |
9. Notifications (if severity >= threshold)
```

### Brute-Force Pipeline

```
1. AuthLogParser tails log files
       |
2. Regex extracts (service, IP, username, success/fail)
       |
3. BruteForceDetector sliding window check
       |
4. If threshold exceeded:
   - FirewallManager.block_ip() (nftables/iptables)
   - Record in blocked_ips table
   - Progressive duration escalation
```

## Database Schema

SQLite database at `{DATA_DIR}/incidents.db`. Five tables:

### incidents

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | Hex ID |
| path | TEXT | File path |
| username | TEXT | Hosting account |
| event_type | TEXT | Event that triggered detection |
| total_score | INTEGER | Aggregated threat score |
| severity | TEXT | low/medium/high/critical |
| action_taken | TEXT | Action executed |
| findings_json | TEXT | JSON array of findings |
| file_event_json | TEXT | JSON of the original file event |
| created_at | TEXT | ISO timestamp |
| resolved | INTEGER | 0 or 1 |
| notes | TEXT | Resolution notes |

### quarantine

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | Hex ID |
| incident_id | TEXT | Related incident |
| original_path | TEXT | Original file location |
| quarantine_path | TEXT | Path in quarantine dir |
| username | TEXT | Hosting account |
| sha256 | TEXT | File hash |
| reason | TEXT | Why quarantined |
| created_at | TEXT | ISO timestamp |
| restored | INTEGER | 0 or 1 |
| deleted | INTEGER | 0 or 1 |

### blocked_ips

| Column | Type | Description |
|---|---|---|
| ip | TEXT PK | IP address |
| reason | TEXT | Block reason |
| blocked_at | TEXT | ISO timestamp |
| expires_at | TEXT | Expiry (null = permanent) |
| blocked_by | TEXT | Source (auto/api/bruteforce) |

### waf_events

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | Hex ID |
| client_ip | TEXT | Client IP |
| uri | TEXT | Request URI |
| method | TEXT | HTTP method |
| rule_id | INTEGER | ModSecurity rule ID |
| rule_msg | TEXT | Rule message |
| severity | TEXT | Rule severity |
| action | TEXT | Action taken |
| hostname | TEXT | Virtual host |
| username | TEXT | Mapped user |
| matched_data | TEXT | Data that triggered the rule |
| created_at | TEXT | ISO timestamp |

### cleanup_records

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | Hex ID |
| path | TEXT | Cleaned file path |
| strategy | TEXT | Cleanup strategy used |
| success | INTEGER | 0 or 1 |
| backup_path | TEXT | Path to backup |
| changes_json | TEXT | JSON of changes made |
| error | TEXT | Error message if failed |
| username | TEXT | Hosting account |
| created_at | TEXT | ISO timestamp |

## Configuration System

- Format: `KEY="value"`, one per line, `#` comments
- Parser: `lib/config.py` -- regex-based, handles quoted and unquoted values
- Loading: `DEFAULTS` dict merged with parsed config file -> typed `JabaliConfig` dataclass
- Paths: `/etc/jabali-security/jabali-security.conf` (root) or `~/.config/jabali-security/jabali-security.conf` (user)
- Updates: `update_conf_key()` performs atomic writes (temp file + rename) with `0o600` permissions
- Runtime: `PATCH /api/v1/config` updates the file and can push to the running daemon

Full reference: [CONFIGURATION.md](CONFIGURATION.md)

## Security Model

### Linux Capabilities

The systemd service drops root privileges and uses targeted capabilities:

| Capability | Purpose |
|---|---|
| `CAP_DAC_READ_SEARCH` | Read any file for scanning (without write) |
| `CAP_DAC_OVERRIDE` | Delete/move files for quarantine |
| `CAP_FOWNER` | Change permissions on quarantined files |
| `CAP_NET_ADMIN` | Manage nftables/iptables rules for IP blocking |
| `CAP_KILL` | Kill suspicious processes (proactive defense) |

### systemd Hardening

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=no
PrivateTmp=yes
MemoryMax=256M
LimitNOFILE=65536
RuntimeDirectory=jabali-security
```

`ProtectHome=no` is required because the security scanner needs write access to quarantine files in `/home`. Writable paths: `/home`, `/var/security/quarantine`, `/var/lib/jabali-security`, `/var/log/jabali-security`, and `/etc/php`.

### API Authentication

- API listens on Unix socket `/run/jabali-security/jabali-security.sock` (TCP disabled by default)
- `X-API-Key` header required on all API requests (except `/health`)
- Key auto-generated on install (44-char URL-safe token)
- Socket permissions: `0660 root:www-data`
- Config file written with `0o600` permissions

### Input Validation

- All API inputs validated (IP addresses via `ipaddress.ip_address()`, integers range-checked, strings pattern-matched)
- No `shell=True` in subprocess calls -- always list args
- Symlinks rejected before file access in scan endpoints
- Config values sanitized on write (backslash, quote, newline escaping)
- SQL parameterized queries throughout (no string interpolation)

### Web Dashboard Security

- Session cookie: `HttpOnly`, `SameSite=Lax`
- Headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`
- Login via API key
