# Jabali Security — Translation Strings

All translatable strings used by the Jabali Security panel plugin. These should be added to the panel's `lang/*.json` files (ar, en, es, fr, he, pt, ru, tr).

Translations are managed by the panel team. This document is the reference for which strings the security plugin uses.

## How it works

The plugin uses Laravel's `__()` helper with English keys. Laravel looks up the key in `lang/{locale}.json` and falls back to the key itself if no translation exists.

## Strings

### Labels & Navigation

| Key | Context |
|-----|---------|
| Security | Page title and navigation |
| Overview | Tab label |
| Defense | Tab label |
| Malware Scanner | Tab label |
| Intelligence | Tab label |
| Settings | Tab label |
| Firewall | Sub-tab |
| WAF | Sub-tab |
| IP Protection | Sub-tab |
| Proactive | Sub-tab |
| WebShield | Sub-tab |
| GeoIP | Sub-tab |
| SSH Jail | Sub-tab |
| Rules | Sub-tab |
| Users | Sub-tab / column |
| Scan | Sub-tab |
| Cleanup | Sub-tab |
| Quarantine | Sub-tab label |

### GeoIP Module

| Key | Context |
|-----|---------|
| Block Country | Button label |
| Update GeoIP DB | Button label |
| MaxMind Configuration | Section heading |
| MaxMind License Key | Field label |
| Default Action | Field label |
| Block (403) | Select option |
| Challenge (JS) | Select option |
| Challenge (JS page) | Select option |
| Log only | Select option |
| Country Codes | Field label |
| Comma-separated ISO codes (e.g., CN,RU,KP) | Helper text |
| Code | Column header |
| Country | Column header |
| Action | Column header |
| Country Rules | Status card label |
| Database | Status card label |
| Missing | Status value |
| No country rules | Empty state heading |
| Block or allow traffic by country using MaxMind GeoIP database | Empty state description |
| Block or allow traffic by country using MaxMind GeoLite2 database. | Tab description |
| Countries blocked: :codes | Notification (`:codes` = comma-separated list) |
| Country removed: :cc | Notification (`:cc` = country code) |
| GeoIP database updated | Notification |
| GeoIP update failed | Notification |
| GeoIP settings saved | Notification |
| Failed to save settings | Notification |
| Enter license key | Placeholder |
| Download the latest MaxMind GeoLite2-Country database. Requires a license key configured below. | Modal description |
| Sign up free at maxmind.com/en/geolite2/signup, then generate a license key under Account → Manage License Keys. | Section description |
| Save | Button label |

### Status Cards & Stats

| Key | Context |
|-----|---------|
| On | Status value |
| Off | Status value |
| Online | Status value |
| Offline | Status value |
| Daemon | Status card |
| Incidents | Status card |
| Blocked | Status card |
| Watching | Status card |
| CrowdSec | Status card |
| Connected | Status value |
| Disconnected | Status value |
| Decisions | Status card |
| Blocked IPs | Status card |
| LAPI | Status card |
| Installed | Status card |
| Rate Limiting | Status card |
| Bot Filtering | Status card |
| Bots Blocked | Status card |
| Rate Limited | Status card |
| Events (24h) | Status card |
| Blocked (24h) | Status card |
| Processes Killed | Status card |
| Process Killer | Status card |
| Tracked IPs | Status card |
| ClamAV | Status card |
| YARA | Status card |
| Entries | Status card |
| Last Update | Status card |
| Threat Intel | Status card |

### Actions & Buttons

| Key | Context |
|-----|---------|
| Enable | Button |
| Disable | Button |
| Remove | Button |
| Delete | Button |
| Restore | Button |
| Resolve | Button |
| Unblock | Button |
| Unban | Button |
| Block | Button |
| Allow | Button |
| Deny | Button |
| Reject | Button |
| Change | Button |
| Check IP | Button |
| Clean File | Button |
| Add IP | Button |
| Add Rule | Button |
| Block IP | Button |
| Whitelist | Button/tab |
| Enable Firewall | Button |
| Disable Firewall | Button |
| Enable Shell | Button |
| Disable Shell | Button |
| Disable Rule | Button |
| Disable Attack Mode | Button |
| Scan All Users | Button |
| Scan Selected | Button |
| Delete Selected | Button |
| Delete Selected Rules | Button |
| Remove Selected | Button |
| Resolve Selected | Button |
| Restore Selected | Button |
| Unblock Selected | Button |
| Save & Restart | Button |
| Basic Mode | Toggle button |
| Expert Mode | Toggle button |
| I Am Under Attack! | Button |

### Under Attack Mode

| Key | Context |
|-----|---------|
| Under Attack Mode | Feature name |
| UNDER ATTACK MODE ACTIVE | Banner text |
| Aggressive defenses activated | Notification |
| Normal settings restored | Notification |
| Advanced Protection | Section |
| Protection Modules | Section |

### Table Columns

| Key | Context |
|-----|---------|
| Name | Column |
| Pattern | Column |
| Category | Column |
| Enabled | Column |
| IP Address | Column |
| Source | Column |
| Reason | Column |
| Duration | Column |
| Expires | Column |
| Blocked By | Column |
| Severity | Column |
| Score | Column |
| Max Score | Column |
| File Path | Column |
| Original Path | Column |
| Size | Column |
| Time | Column |
| User | Column |
| Username | Column |
| Message | Column |
| Method | Column |
| URI | Column |
| Client IP | Column |
| Rule ID | Column |
| Rule Name | Column |
| Scenario | Column |
| Strategy | Column |
| From | Column |
| To | Column |
| From IP | Column |
| Direction | Column |
| Number | Column |
| Port | Column |
| Protocol | Column |
| Permission | Column |
| Comment | Column |
| Type | Column |
| Notes | Column |
| IP Version | Column |
| Active | Column/badge |
| Expired | Column/badge |
| Permanent | Column/badge/value |
| Resolved | Column/badge |
| Quarantined | Column/badge |
| Failed | Column/badge |
| Limit | Column |
| SSH Keys | Column/tab |
| SSH Port | Card label |
| SSH Shell Default | Card label |
| Password Auth | Card label |

### Notifications

| Key | Context |
|-----|---------|
| :feature :action | Module toggle (`:feature` = name, `:action` = enabled/disabled) |
| enabled | Action value |
| disabled | Action value |
| IP blocked: :ip | Notification |
| IP unblocked: :ip | Notification |
| IP whitelisted: :ip | Notification |
| Removed :ip from whitelist | Notification |
| CrowdSec ban removed: :ip | Notification |
| Firewall enabled | Notification |
| Firewall disabled | Notification |
| WebShield enabled | Notification |
| WebShield disabled | Notification |
| Incident resolved | Notification |
| File cleaned | Notification |
| File deleted | Notification |
| File restored | Notification |
| Rule added | Notification |
| Rule deleted | Notification |
| Rule disabled | Notification |
| Daemon restarted | Notification |
| Settings saved | Notification |
| settings applied | Notification body |
| Failed to save config | Notification |
| Threat detected | Notification |
| Shell enabled for :user | Notification |
| Shell disabled for :user | Notification |
| Password auth enabled | Notification |
| Password auth disabled | Notification |
| SSH port changed to :port | Notification |
| Scan complete — :users users | Notification |
| Scan failed for :user | Notification |
| Scanning :user... | Notification |
| Scanning :n/:total — :user | Notification |
| :files files scanned, :threats threats found | Notification body |
| :user — :files files, :threats threats | Notification body |
| :count IPs unblocked | Notification |
| :count IPs removed from whitelist | Notification |
| :count files deleted | Notification |
| :count files restored | Notification |
| :count incidents resolved | Notification |
| :count rules deleted | Notification |
| :count shells enabled | Notification |
| :count shells disabled | Notification |
| IP Check Result | Notification title |

### Severity Levels

| Key | Context |
|-----|---------|
| Critical | Severity badge |
| High | Severity badge |
| Medium | Severity badge |
| Low | Severity badge |

### Boolean Values

| Key | Context |
|-----|---------|
| Yes | Display value |
| No | Display value |

### Miscellaneous

| Key | Context |
|-----|---------|
| Configuration | Section heading |
| Duration (seconds) | Field label |
| Any | Select option |
| Powered by Jabali Security | Footer |
| permanent | Duration value |
| UFW Firewall | Module name |

## Adding new strings

When adding new `__('...')` calls to the security plugin, update this document and notify the panel team to add translations.
