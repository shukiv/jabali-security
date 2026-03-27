# Configuration Reference

## File Location

| Context | Path |
|---|---|
| Root (production) | `/etc/jabali-security/jabali-security.conf` |
| User (development) | `~/.config/jabali-security/jabali-security.conf` |

## Format

```
# Comments start with #
KEY="value"
```

- One key per line
- Values are quoted (double or single quotes) or unquoted
- Blank lines and `#` comment lines are ignored
- Keys are uppercase with underscores

## Managing Configuration

```bash
# View current config
jabali-security config show

# Set a value (persists to file + pushes to running daemon)
jabali-security config set KEY value

# Validate config
jabali-security config test

# Edit directly
sudo nano /etc/jabali-security/jabali-security.conf
```

See also: `etc/jabali-security.conf.example` for a fully commented template.

---

## Daemon

| Key | Type | Default | Description |
|---|---|---|---|
| `LOG_LEVEL` | string | `info` | Log verbosity: `debug`, `info`, `warning`, `error`, `critical` |
| `LOG_DIR` | path | `/var/log/jabali-security` | Directory for log files (auto-created) |
| `DATA_DIR` | path | `/var/lib/jabali-security` | Persistent data directory (SQLite DB, state files) |
| `QUARANTINE_DIR` | path | `/var/security/quarantine` | Quarantine directory for malicious files |
| `WORKERS` | int | `4` | Number of async scan workers (1-32) |

## API

| Key | Type | Default | Description |
|---|---|---|---|
| `API_BIND` | string | `127.0.0.1` | Bind address for REST API (`127.0.0.1` = localhost only) |
| `API_PORT` | int | `9876` | Port for REST API (1024-65535) |
| `API_KEY` | string | *(auto-generated)* | API authentication key. Auto-generated on install. |

## File Watcher

| Key | Type | Default | Description |
|---|---|---|---|
| `WATCH_DIRS` | csv | `/home/*/public_html,/home/*/domains/*/public_html,/home/*/tmp` | Comma-separated directories/globs to watch recursively |
| `WATCHER_BACKEND` | string | `inotify` | Watcher backend: `inotify` (default) |

> **Note:** `/var/www` was removed from defaults to avoid watching hosting panel application directories.

## Pre-Filter

| Key | Type | Default | Description |
|---|---|---|---|
| `SCAN_EXTENSIONS` | csv | `.php,.phtml,.js,.py,.sh,.cgi,.pl,.asp,.aspx,.jsp` | Comma-separated file extensions to scan |
| `MAX_FILE_SIZE` | int | `2097152` | Maximum file size in bytes (default 2 MB). Min: 1024. |
| `SKIP_DIRS` | csv | `.git,node_modules,vendor,__pycache__,.cache` | Comma-separated directory names to skip |

## Detection

| Key | Type | Default | Description |
|---|---|---|---|
| `HEURISTIC_ENABLED` | bool | `yes` | Enable heuristic analysis (regex pattern matching) |
| `ENTROPY_ENABLED` | bool | `yes` | Enable Shannon entropy analysis |
| `ENTROPY_THRESHOLD` | float | `4.5` | Entropy threshold (0.0-8.0); content above this is flagged |
| `YARA_ENABLED` | bool | `yes` | Enable YARA-X signature scanning |
| `YARA_RULES_DIR` | path | `/usr/local/jabali-security/rules` | Directory containing YARA-X rule files (`.yar`) |

## ClamAV (Optional)

| Key | Type | Default | Description |
|---|---|---|---|
| `CLAMAV_ENABLED` | string | `auto` | `auto` (detect clamd), `yes` (require), `no` (disable) |
| `CLAMAV_SOCKET` | path | `/var/run/clamav/clamd.ctl` | Path to clamd Unix socket |
| `FRESHCLAM_ON_UPDATE` | bool | `yes` | Run freshclam when `jabali-security rules update` is called |

## Scoring

| Key | Type | Default | Description |
|---|---|---|---|
| `SCORE_LOG` | int | `40` | Minimum score to create a log entry. Min: 0. |
| `SCORE_QUARANTINE` | int | `70` | Minimum score to quarantine the file. Min: 0. |
| `SCORE_SUSPEND` | int | `100` | Minimum score to suspend the hosting account. Min: 0. |

Scoring determines the action for each detected threat:

| Score Range | Action |
|---|---|
| Below `SCORE_LOG` | Ignored |
| `SCORE_LOG` to `SCORE_QUARANTINE` | Logged as incident |
| `SCORE_QUARANTINE` to `SCORE_SUSPEND` | File quarantined |
| `SCORE_SUSPEND` and above | Account suspended (if enabled) |

## Process Monitor

| Key | Type | Default | Description |
|---|---|---|---|
| `PROCESS_MONITOR_ENABLED` | bool | `yes` | Enable monitoring of suspicious process trees |
| `PROCESS_POLL_INTERVAL` | int | `2` | Poll interval in seconds for /proc scanning (1-300) |

## Behavior Tracking

| Key | Type | Default | Description |
|---|---|---|---|
| `BEHAVIOR_TRACKING_ENABLED` | bool | `yes` | Enable file lifecycle tracking (CREATE -> MODIFY -> EXECUTE) |
| `BEHAVIOR_TTL` | int | `300` | Time-to-live in seconds for behavior records. Min: 10. |

## Response

| Key | Type | Default | Description |
|---|---|---|---|
| `AUTO_QUARANTINE` | bool | `yes` | Automatically quarantine files exceeding `SCORE_QUARANTINE` |
| `AUTO_SUSPEND` | bool | `no` | Automatically suspend accounts exceeding `SCORE_SUSPEND` |
| `AUTO_BLOCK_IP` | bool | `no` | Automatically block attacker IP addresses |

## Notifications

| Key | Type | Default | Description |
|---|---|---|---|
| `NOTIFY_EMAIL` | string | *(empty)* | Email address for alerts (empty = disabled) |
| `NOTIFY_WEBHOOK` | string | *(empty)* | Webhook URL for alerts (empty = disabled) |
| `NOTIFY_MIN_SEVERITY` | string | `high` | Minimum severity to trigger notifications: `low`, `medium`, `high`, `critical` |

## Brute-Force Protection

| Key | Type | Default | Description |
|---|---|---|---|
| `BRUTEFORCE_ENABLED` | bool | `no` | Enable brute-force detection and automatic IP blocking |
| `BRUTEFORCE_SSH_LOG` | path | `/var/log/auth.log` | SSH authentication log file |
| `BRUTEFORCE_MAIL_LOG` | path | `/var/log/mail.log` | Mail service log file (Dovecot, Postfix, Exim) |
| `BRUTEFORCE_STALWART_LOG` | path | `/var/log/stalwart-mail` | Stalwart mail server log directory |
| `BRUTEFORCE_SSH_THRESHOLD` | int | `5` | Failed SSH attempts before blocking. Min: 1. |
| `BRUTEFORCE_SSH_WINDOW` | int | `300` | SSH sliding window in seconds. Min: 10. |
| `BRUTEFORCE_MAIL_THRESHOLD` | int | `10` | Failed mail attempts before blocking. Min: 1. |
| `BRUTEFORCE_MAIL_WINDOW` | int | `600` | Mail sliding window in seconds. Min: 10. |
| `BRUTEFORCE_BLOCK_DURATIONS` | csv(int) | `600,3600,86400,0` | Progressive block durations in seconds. 0 = permanent. |
| `FIREWALL_BACKEND` | string | `auto` | `auto` (detect nftables/iptables), `nftables`, `iptables`, `none` |
| `BRUTEFORCE_WHITELIST_IPS` | csv | *(empty)* | Comma-separated IPs to never block |

## WAF (ModSecurity)

| Key | Type | Default | Description |
|---|---|---|---|
| `WAF_ENABLED` | bool | `no` | Enable ModSecurity WAF audit log parsing and rule management |
| `WAF_AUDIT_LOG` | path | `/var/log/modsec_audit.log` | ModSecurity audit log file path. Path varies by installation: nginx default is `/var/log/nginx/modsec_audit.log`, Apache default is `/var/log/modsec_audit.log`. |
| `WAF_AUDIT_LOG_TYPE` | string | `serial` | Audit log type: `serial` (single file) or `concurrent` (directory-based) |
| `WAF_RULES_DIR` | path | `/etc/modsecurity/crs` | OWASP Core Rule Set directory |
| `WAF_OVERRIDES_FILE` | path | `/etc/modsecurity/jabali-overrides.conf` | Jabali-managed overrides file for disabling rules |
| `WAF_CRS_AUTO_UPDATE` | bool | `no` | Auto-update OWASP CRS on rules update |
| `WAF_WEB_SERVER` | string | `auto` | Web server to reload: `auto`, `nginx`, `apache` |

## Proactive Defense

| Key | Type | Default | Description |
|---|---|---|---|
| `PROACTIVE_ENABLED` | bool | `no` | Enable proactive defense subsystem (master switch) |
| `PHP_HARDENING_ENABLED` | bool | `no` | Enable PHP-FPM pool hardening. Disabled by default. Hosting panels (Jabali Panel, cPanel) typically manage per-user FPM hardening. Enable only if your environment does not set `disable_functions` and `open_basedir` per pool. |
| `PHP_HARDENING_AUTO` | bool | `no` | Auto-harden new/unhardened pools at startup. When enabled, the hardener skips pools that already have `disable_functions` and `open_basedir` configured. |
| `PROCESS_KILL_ENABLED` | bool | `no` | Enable proactive killing of suspicious processes |
| `PROCESS_KILL_THRESHOLD` | int | `70` | Minimum threat score to kill a process (1-100) |
| `PROCESS_KILL_MIN_UID` | int | `1000` | Minimum UID for killable processes (protects system processes) |
| `PROCESS_KILL_WHITELIST` | csv | `wp-cron.php,artisan,composer` | Command substrings to whitelist from killing |

## Malware Cleanup

| Key | Type | Default | Description |
|---|---|---|---|
| `CLEANUP_ENABLED` | bool | `no` | Enable the cleanup engine (master switch) |
| `CLEANUP_AUTO` | bool | `no` | Automatically attempt cleanup before quarantine |
| `CLEANUP_BACKUP_DIR` | path | `/var/lib/jabali-security/backups` | Directory for file backups before cleanup |
| `CLEANUP_CMS_CHECKSUMS` | bool | `yes` | Use CMS checksums for integrity verification |

## Scheduled Scan

| Key | Type | Default | Description |
|---|---|---|---|
| `SCHEDULED_SCAN_ENABLED` | bool | `no` | Enable periodic full-path scanning |
| `SCHEDULED_SCAN_INTERVAL` | int | `24` | Interval between scans in hours (1-8760) |
| `SCHEDULED_SCAN_PATHS` | csv | `/home/*/public_html` | Paths/globs to scan on schedule |

## Threat Intelligence

| Key | Type | Default | Description |
|---|---|---|---|
| `THREAT_INTEL_ENABLED` | bool | `no` | Enable threat intelligence feeds |
| `THREAT_INTEL_UPDATE_INTERVAL` | int | `6` | Feed update interval in hours (1-168) |
| `THREAT_INTEL_FEEDS` | csv | `spamhaus_drop,spamhaus_edrop,blocklist_de_all,tor_exit_nodes,malwarebazaar_recent` | Enabled feeds |
| `THREAT_INTEL_AUTO_BLOCK` | bool | `no` | Auto-block IPs found in threat intel feeds |
| `THREAT_INTEL_AUTO_BLOCK_THRESHOLD` | int | `3` | Feed matches required before auto-blocking (1-10) |

Available feeds: `spamhaus_drop`, `spamhaus_edrop`, `blocklist_de_all`, `tor_exit_nodes`, `malwarebazaar_recent`

## WebShield

| Key | Type | Default | Description |
|---|---|---|---|
| `WEBSHIELD_ENABLED` | bool | `no` | Enable WebShield nginx integration |
| `WEBSHIELD_RATE_LIMIT` | int | `10` | Requests per second per IP (1-10000) |
| `WEBSHIELD_RATE_BURST` | int | `20` | Burst size above rate before 429 (1-100000) |
| `WEBSHIELD_CHALLENGE_ENABLED` | bool | `yes` | Enable JS challenge page for suspicious bots |
| `WEBSHIELD_BOT_FILTERING` | bool | `yes` | Enable user-agent based bot filtering |
| `WEBSHIELD_NGINX_CONF_DIR` | path | `/etc/nginx/jabali-security` | Directory for generated nginx config snippets |

## UFW Firewall Management

| Key | Type | Default | Description |
|---|---|---|---|
| `UFW_ENABLED` | bool | `no` | Enable UFW firewall management via REST API. Requires `ufw` to be installed. Separate from the nftables/iptables-based brute-force IP blocking. |

## Database Scanner

| Key | Type | Default | Description |
|---|---|---|---|
| `DB_SCANNER_ENABLED` | bool | `no` | Enable MySQL database malware scanning |

## RapidScan

| Key | Type | Default | Description |
|---|---|---|---|
| `RAPIDSCAN_WORKERS` | int | `4` | Number of parallel workers (1-32) |
| `RAPIDSCAN_MTIME_CACHE` | bool | `yes` | Cache file modification times to skip unchanged files |

## Web Dashboard

| Key | Type | Default | Description |
|---|---|---|---|
| `WEB_ENABLED` | bool | `no` | Enable the web dashboard |
| `WEB_BIND` | string | `0.0.0.0` | Bind address (`0.0.0.0` = all interfaces) |
| `WEB_PORT` | int | `8443` | Port for the web dashboard (1024-65535) |

## Retention

| Key | Type | Default | Description |
|---|---|---|---|
| `INCIDENT_RETAIN_DAYS` | int | `90` | Days to retain incident records. Min: 1. |

---

## Common Scenarios

### Minimal setup (file scanning only)

```
LOG_LEVEL="info"
WATCH_DIRS="/home/*/public_html"
HEURISTIC_ENABLED="yes"
ENTROPY_ENABLED="yes"
YARA_ENABLED="yes"
AUTO_QUARANTINE="yes"
```

### Full protection (all features)

```
BRUTEFORCE_ENABLED="yes"
WAF_ENABLED="yes"
PROACTIVE_ENABLED="yes"
PHP_HARDENING_ENABLED="yes"
PHP_HARDENING_AUTO="yes"
PROCESS_KILL_ENABLED="yes"
CLEANUP_ENABLED="yes"
CLEANUP_AUTO="yes"
THREAT_INTEL_ENABLED="yes"
WEBSHIELD_ENABLED="yes"
UFW_ENABLED="yes"
SCHEDULED_SCAN_ENABLED="yes"
WEB_ENABLED="yes"
```

### High-traffic server (tuned thresholds)

```
WORKERS="8"
WEBSHIELD_RATE_LIMIT="50"
WEBSHIELD_RATE_BURST="100"
BRUTEFORCE_SSH_THRESHOLD="10"
BRUTEFORCE_MAIL_THRESHOLD="20"
RAPIDSCAN_WORKERS="8"
```

### Sensitive server (aggressive response)

```
SCORE_LOG="20"
SCORE_QUARANTINE="50"
SCORE_SUSPEND="80"
AUTO_QUARANTINE="yes"
AUTO_BLOCK_IP="yes"
PROCESS_KILL_THRESHOLD="50"
NOTIFY_EMAIL="admin@example.com"
NOTIFY_MIN_SEVERITY="medium"
```
