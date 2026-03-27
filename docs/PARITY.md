# Interface Parity Rules

Jabali Security has two interfaces that must maintain feature parity:

- **Web Dashboard** — standalone Flask app on port 8443 (`web/`)
- **Jabali Panel Plugin** — Filament plugin for the hosting panel (`panel/`)

## Rule

Every feature available in the web dashboard must have an equivalent in the Jabali Panel plugin. If a server admin can do it in the web dashboard, they must be able to do it in the panel.

---

## Feature Matrix

### Pages & Data Views

| Feature | Web Dashboard | Panel Plugin | Status |
|---------|:---:|:---:|--------|
| Dashboard stats (incidents, quarantine, dirs, workers, memory) | Yes | Yes | Parity |
| Daemon status (version, uptime, memory, workers) | Yes | Yes | Parity |
| Incidents list with severity, score, action, timestamp | Yes | Yes | Parity |
| Incident detail view | Yes | No | **Gap** |
| Quarantine list with restore/delete | Yes | Yes | Parity |
| IP Blocklist with block/unblock | Yes | Yes | Parity |
| UFW Firewall rules with add/delete/enable/disable | Yes | Yes | Parity |
| Configuration editor (view/edit all keys) | Yes | Yes | Parity |
| WAF events table + stats | Yes | No | **Gap** |
| WAF rule files + disable/enable rules | Yes | No | **Gap** |
| Brute-Force stats + blocked IPs | Yes | No | **Gap** |
| Brute-Force whitelist management | Yes | No | **Gap** |
| Proactive Defense status | Yes | No | **Gap** |
| PHP-FPM pool hardening status | Yes | No | **Gap** |
| Process kills log | Yes | No | **Gap** |
| WebShield status + bot rules | Yes | No | **Gap** |
| WebShield install/uninstall | Yes | No | **Gap** |
| Cleanup records | Yes | No | **Gap** |
| Threat Intelligence feeds + update | Yes | No | **Gap** |
| Threat Intel IP/hash check | Yes | No | **Gap** |
| YARA/ClamAV rules list | Yes | No | **Gap** |
| Scan page (path input + results) | Yes | Partial | **Gap** (header action only) |
| Users list with incident counts | Yes | No | **Gap** |
| User detail (incidents + quarantine) | Yes | No | **Gap** |

### Module Toggles (Enable/Disable)

| Toggle | Web Dashboard | Panel Plugin | Status |
|--------|:---:|:---:|--------|
| Heuristic Scanner | Yes | No | **Gap** |
| Entropy Scanner | Yes | No | **Gap** |
| YARA-X Rules | Yes | No | **Gap** |
| Process Monitor | Yes | No | **Gap** |
| Behavior Tracking | Yes | No | **Gap** |
| Auto Quarantine | Yes | No | **Gap** |
| WAF (ModSecurity) | Yes | No | **Gap** |
| Brute-Force Protection | Yes | No | **Gap** |
| Proactive Defense | Yes | No | **Gap** |
| Process Killer | Yes | No | **Gap** |
| PHP Hardening | Yes | No | **Gap** |
| WebShield | Yes | No | **Gap** |
| Threat Intelligence | Yes | No | **Gap** |
| Auto Cleanup | Yes | No | **Gap** |
| UFW Firewall | Yes | No | **Gap** |
| Scheduled Scans | Yes | No | **Gap** |
| Auto Suspend | Yes | No | **Gap** |

### Actions

| Action | Web Dashboard | Panel Plugin | Status |
|--------|:---:|:---:|--------|
| Resolve incident (with notes) | Yes | Yes | Parity |
| Restore quarantined file | Yes | Yes | Parity |
| Delete quarantined file | Yes | Yes | Parity |
| Block IP (with reason/duration) | Yes | Yes | Parity |
| Unblock IP | Yes | Yes | Parity |
| Add UFW rule | Yes | Yes | Parity |
| Delete UFW rule | Yes | Yes | Parity |
| Enable/Disable UFW | Yes | Yes | Parity |
| Reload UFW | Yes | No | **Gap** |
| Run on-demand scan | Yes | Yes | Parity |
| Reload YARA rules + freshclam | Yes | Yes | Parity |
| Update threat intel feeds | Yes | No | **Gap** |
| Install/uninstall WebShield | Yes | No | **Gap** |
| Harden/unharden PHP pool | Yes | No | **Gap** |
| WAF rule enable/disable | Yes | No | **Gap** |
| Update OWASP CRS | Yes | No | **Gap** |
| Reset all stats | Yes | No | **Gap** |

---

## Gap Priority

### P1 — Must Have

These are core security management features:

- **Module toggles** — Enable/disable protection features from the panel
- **WAF tab** — View events, stats, manage rules
- **Brute-Force tab** — View stats, blocked IPs, manage whitelist
- **Scan results** — Show detailed findings after scan (not just header action)

### P2 — Should Have

Important for full security management:

- **Proactive tab** — PHP pool status, process kills log
- **WebShield tab** — Status, bot rules, install/uninstall
- **Threat Intel tab** — Feed status, IP/hash check, update trigger
- **Users tab** — User list with risk scores, per-user detail view

### P3 — Nice to Have

Supplementary features:

- **Cleanup tab** — Cleanup records
- **Rules tab** — YARA/ClamAV rules list
- **Incident detail view** — Full incident breakdown
- **Reset all stats** — Maintenance action

---

## Implementation Notes

- Panel plugin uses **Filament Tabs** — new features = new tabs on the Security page
- All data comes from the **REST API** (`127.0.0.1:9876`) — no direct database access
- API client: `panel/JabaliSecurityClient.php` wraps all HTTP calls
- After updating panel plugin code, **restart `jabali-panel` service** (FrankenPHP caches PHP in worker mode)
- Module toggles require writing to `/etc/jabali-security/jabali-security.conf` and restarting the daemon
- The web dashboard serves as the **reference implementation** — when adding a feature to the panel, match the web dashboard's behavior

---

## When Adding New Features

1. Add the feature to the **web dashboard** first (Flask templates + routes)
2. Add the corresponding **API endpoint** if needed
3. Add the feature to the **panel plugin** (Filament tab/action)
4. Update this **parity matrix** to reflect the new feature
5. Update `docs/API.md` if new endpoints were added
