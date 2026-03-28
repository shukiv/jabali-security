<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Pages;

use App\JabaliSecurity\JabaliSecurityClient;
use App\JabaliSecurity\Widgets\BlocklistTable;
use App\JabaliSecurity\Widgets\BruteforceBlockedTable;
use App\JabaliSecurity\Widgets\CleanupRecordsTable;
use App\JabaliSecurity\Widgets\FirewallRulesTable;
use App\JabaliSecurity\Widgets\IncidentsTable;
use App\JabaliSecurity\Widgets\PhpPoolsTable;
use App\JabaliSecurity\Widgets\QuarantineTable;
use App\JabaliSecurity\Widgets\ThreatFeedsTable;
use App\JabaliSecurity\Widgets\UsersTable;
use App\JabaliSecurity\Widgets\WafEventsTable;
use App\JabaliSecurity\Widgets\WebshieldRulesTable;
use App\JabaliSecurity\Widgets\YaraRulesTable;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Schemas\Components\Actions as SchemaActions;
use Filament\Schemas\Components\EmbeddedTable;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Text;
use Filament\Schemas\Components\Tabs;
use Filament\Schemas\Components\Tabs\Tab;
use Filament\Schemas\Schema;
use Filament\Support\Enums\FontWeight;
use Filament\Support\Enums\TextSize;
use Illuminate\Contracts\Support\Htmlable;
use Livewire\Attributes\Url;

class Security extends Page implements HasActions, HasForms
{
    use InteractsWithActions;
    use InteractsWithForms;

    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-shield-check';

    protected static ?int $navigationSort = 5;

    protected static ?string $slug = 'security';

    protected string $view = 'jabali-security::security';

    #[Url(as: 'tab')]
    public string $activeTab = 'overview';

    #[Url(as: 'threats')]
    public string $threatsTab = 'incidents';

    #[Url(as: 'defense')]
    public string $defenseTab = 'firewall';

    #[Url(as: 'intelligence')]
    public string $intelligenceTab = 'rules';

    public array $configData = [];

    public function mount(): void
    {
        $this->loadConfigData();
    }

    protected function loadConfigData(): void
    {
        $config = $this->client()->get('/config') ?? [];
        foreach (static::$configCategories as $keys) {
            foreach ($keys as $key) {
                $val = $config[$key] ?? '';
                if (in_array($key, static::$booleanKeys)) {
                    $this->configData['config_'.$key] = in_array($val, ['yes', 'true', '1']);
                } else {
                    $this->configData['config_'.$key] = $val;
                }
            }
        }
    }

    public function getTitle(): string|Htmlable
    {
        return __('Security');
    }

    public static function getNavigationLabel(): string
    {
        return __('Security');
    }

    protected function client(): JabaliSecurityClient
    {
        return new JabaliSecurityClient;
    }

    // ── Header Actions ───────────────────────────────────────────────

    protected function getHeaderActions(): array
    {
        return [
            Action::make('scan')
                ->label(__('Run Scan'))
                ->icon('heroicon-o-magnifying-glass')
                ->color('danger')
                ->form([
                    TextInput::make('path')
                        ->label(__('Path'))
                        ->placeholder('/home/user/public_html')
                        ->required(),
                ])
                ->action(function (array $data): void {
                    $result = $this->client()->post('/scan', ['path' => $data['path']]);
                    if ($result) {
                        Notification::make()
                            ->title(__('Scan Complete'))
                            ->body(__('Score: :score', ['score' => $result['score'] ?? 0]))
                            ->color(($result['score'] ?? 0) > 0 ? 'warning' : 'success')
                            ->send();
                    } else {
                        Notification::make()->title(__('Scan failed'))->danger()->send();
                    }
                }),

            Action::make('saveAndRestart')
                ->label(__('Save & Restart'))
                ->icon('heroicon-o-check')
                ->color('success')
                ->action('saveAndRestart'),

            Action::make('updateRules')
                ->label(__('Update Rules'))
                ->icon('heroicon-o-arrow-path')
                ->color('danger')
                ->requiresConfirmation()
                ->action(function (): void {
                    $result = $this->client()->post('/rules/reload');
                    if ($result && ($result['yara_reloaded'] ?? false)) {
                        Notification::make()->title(__('Rules reloaded'))->success()->send();
                    } else {
                        Notification::make()->title(__('Reload failed'))->danger()->send();
                    }
                }),
        ];
    }

    // ── Forms ────────────────────────────────────────────────────────

    protected function getForms(): array
    {
        return ['securitySchema'];
    }

    public function securitySchema(Schema $schema): Schema
    {
        return $schema->components([
            Tabs::make(__('Security'))
                ->contained()
                ->livewireProperty('activeTab')
                ->tabs([
                    'overview' => Tab::make(__('Overview'))
                        ->icon('heroicon-o-home')
                        ->schema(array_merge(
                            $this->overviewStats(),
                            $this->overviewTab(),
                        )),
                    'threats' => Tab::make(__('Threats'))
                        ->icon('heroicon-o-exclamation-triangle')
                        ->schema([
                            Tabs::make(__('Threats'))
                                ->contained(false)
                                ->livewireProperty('threatsTab')
                                ->tabs([
                                    'incidents' => Tab::make(__('Incidents'))
                                        ->schema([EmbeddedTable::make(IncidentsTable::class)]),
                                    'quarantine' => Tab::make(__('Quarantine'))
                                        ->schema([EmbeddedTable::make(QuarantineTable::class)]),
                                    'cleanup' => Tab::make(__('Cleanup'))
                                        ->schema([EmbeddedTable::make(CleanupRecordsTable::class)]),
                                ]),
                        ]),
                    'defense' => Tab::make(__('Defense'))
                        ->icon('heroicon-o-shield-check')
                        ->schema([
                            Tabs::make(__('Defense'))
                                ->contained(false)
                                ->livewireProperty('defenseTab')
                                ->tabs([
                                    'firewall' => Tab::make(__('Firewall'))
                                        ->schema($this->firewallTab()),
                                    'blocklist' => Tab::make(__('Blocklist'))
                                        ->schema([EmbeddedTable::make(BlocklistTable::class)]),
                                    'waf' => Tab::make(__('WAF'))
                                        ->schema(array_merge($this->wafStats(), [EmbeddedTable::make(WafEventsTable::class)])),
                                    'bruteforce' => Tab::make(__('Brute-Force'))
                                        ->schema(array_merge($this->bruteforceStats(), [EmbeddedTable::make(BruteforceBlockedTable::class)])),
                                    'proactive' => Tab::make(__('Proactive'))
                                        ->schema(array_merge($this->proactiveStats(), [EmbeddedTable::make(PhpPoolsTable::class)])),
                                    'webshield' => Tab::make(__('WebShield'))
                                        ->schema(array_merge($this->webshieldStats(), [EmbeddedTable::make(WebshieldRulesTable::class)])),
                                ]),
                        ]),
                    'intelligence' => Tab::make(__('Intelligence'))
                        ->icon('heroicon-o-light-bulb')
                        ->schema([
                            Tabs::make(__('Intelligence'))
                                ->contained(false)
                                ->livewireProperty('intelligenceTab')
                                ->tabs([
                                    'rules' => Tab::make(__('Rules'))
                                        ->schema(array_merge($this->rulesStats(), [EmbeddedTable::make(YaraRulesTable::class)])),
                                    'threatintel' => Tab::make(__('Threat Intel'))
                                        ->schema([EmbeddedTable::make(ThreatFeedsTable::class)]),
                                    'users' => Tab::make(__('Users'))
                                        ->schema([EmbeddedTable::make(UsersTable::class)]),
                                ]),
                        ]),
                    'settings' => Tab::make(__('Settings'))
                        ->icon('heroicon-o-cog-6-tooth')
                        ->schema($this->configTab()),
                ]),
        ]);
    }

    // ── Stat Cards (schema-based, compact) ─────────────────────────

    private function statCard(string $label, string $value, string $desc, string $color = 'gray'): Section
    {
        return Section::make()->compact()->schema([
            Text::make(__($label))->size(TextSize::ExtraSmall)->weight(FontWeight::Medium)->color('gray'),
            Text::make($value)->size(TextSize::Large)->weight(FontWeight::Bold)->color($color),
            Text::make(__($desc))->size(TextSize::ExtraSmall)->color('gray'),
        ]);
    }

    protected function overviewStats(): array
    {
        $s = $this->client()->get('/status');
        if (! $s) {
            return [$this->statCard('Daemon', __('Offline'), __('Not responding'), 'danger')];
        }

        return [
            Grid::make(5)->dense()->schema([
                $this->statCard('Incidents', (string) ($s['incidents_24h'] ?? 0), 'Last 24 hours',
                    ($s['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success'),
                $this->statCard('Quarantine', (string) ($s['quarantined_count'] ?? 0), 'Files isolated',
                    ($s['quarantined_count'] ?? 0) > 0 ? 'warning' : 'success'),
                $this->statCard('Watching', (string) ($s['watched_dirs'] ?? 0), 'Folders monitored', 'info'),
                $this->statCard('Memory', round($s['memory_mb'] ?? 0, 1).' MB', ($s['workers'] ?? 0).' workers', 'gray'),
                $this->statCard('Daemon', ($s['running'] ?? false) ? __('Online') : __('Offline'),
                    ($s['running'] ?? false) ? 'All systems go' : 'Service down',
                    ($s['running'] ?? false) ? 'success' : 'danger'),
            ]),
        ];
    }

    protected function wafStats(): array
    {
        $s = $this->client()->get('/waf/stats') ?? [];
        return [
            Grid::make(2)->dense()->schema([
                $this->statCard('Events (24h)', (string) ($s['total_events_24h'] ?? 0), '',
                    ($s['total_events_24h'] ?? 0) > 0 ? 'warning' : 'success'),
                $this->statCard('Blocked (24h)', (string) ($s['blocked_24h'] ?? 0), '',
                    ($s['blocked_24h'] ?? 0) > 0 ? 'danger' : 'success'),
            ]),
        ];
    }

    protected function bruteforceStats(): array
    {
        $s = $this->client()->get('/bruteforce/stats') ?? [];
        return [
            Grid::make(2)->dense()->schema([
                $this->statCard('Tracked IPs', (string) ($s['tracked_ips'] ?? 0), '', 'info'),
                $this->statCard('Blocked', (string) ($s['blocked_count'] ?? 0), '',
                    ($s['blocked_count'] ?? 0) > 0 ? 'danger' : 'success'),
            ]),
        ];
    }

    protected function proactiveStats(): array
    {
        $s = $this->client()->get('/proactive/status') ?? [];
        return [
            Grid::make(3)->dense()->schema([
                $this->statCard('Process Killer', ($s['process_kill_enabled'] ?? false) ? __('Active') : __('Disabled'), '',
                    ($s['process_kill_enabled'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Processes Killed', (string) ($s['process_kill_count'] ?? 0), '',
                    ($s['process_kill_count'] ?? 0) > 0 ? 'warning' : 'success'),
                $this->statCard('PHP Hardening', ($s['php_hardening_enabled'] ?? false) ? __('Active') : __('Disabled'), '',
                    ($s['php_hardening_enabled'] ?? false) ? 'success' : 'gray'),
            ]),
        ];
    }

    protected function webshieldStats(): array
    {
        $s = $this->client()->get('/webshield/status') ?? [];
        return [
            Grid::make(4)->dense()->schema([
                $this->statCard('Installed', ($s['installed'] ?? false) ? __('Yes') : __('No'), '',
                    ($s['installed'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Rate Limiting', ($s['rate_limiting'] ?? false) ? __('On') : __('Off'), '',
                    ($s['rate_limiting'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Bot Filtering', ($s['bot_filtering'] ?? false) ? __('On') : __('Off'), '',
                    ($s['bot_filtering'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Blocked IPs', (string) ($s['blocked_ips_count'] ?? 0), '',
                    ($s['blocked_ips_count'] ?? 0) > 0 ? 'danger' : 'success'),
            ]),
        ];
    }

    protected function rulesStats(): array
    {
        $r = $this->client()->get('/rules') ?? [];
        return [
            Grid::make(4)->dense()->schema([
                $this->statCard('YARA', ($r['yara_enabled'] ?? false) ? __('Enabled') : __('Disabled'), '',
                    ($r['yara_enabled'] ?? false) ? 'success' : 'gray'),
                $this->statCard('ClamAV', ($r['clamav_enabled'] ?? false) ? __('Enabled') : __('Disabled'), '',
                    ($r['clamav_enabled'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Scanners', implode(', ', $r['scanners'] ?? []), '', 'info'),
                $this->statCard('Rules Dir', $r['yara_rules_dir'] ?? '?', '', 'gray'),
            ]),
        ];
    }

    // ── Overview Tab ─────────────────────────────────────────────────

    protected function overviewTab(): array
    {
        $config = $this->client()->get('/config') ?? [];
        $modules = static::getModuleToggles();
        $schema = [];

        // Protection Modules
        $coreSchema = [];
        foreach ($modules['core'] as $key => $mod) {
            $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']);
            $coreSchema[] = Section::make(__($mod['label']))
                ->description(__($mod['desc']))
                ->aside()
                ->compact()
                ->schema([
                    SchemaActions::make([
                        Action::make('toggle_'.$key)
                            ->label($enabled ? __('Enabled') : __('Disabled'))
                            ->color($enabled ? 'success' : 'gray')
                            ->size('xs')
                            ->action(fn () => $this->toggleModule($key)),
                    ]),
                ]);
        }
        $schema[] = Section::make(__('Protection Modules'))->schema($coreSchema);

        // Advanced Protection
        $advSchema = [];
        foreach ($modules['advanced'] as $key => $mod) {
            $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']);
            $advSchema[] = Section::make(__($mod['label']))
                ->description(__($mod['desc']))
                ->aside()
                ->compact()
                ->schema([
                    SchemaActions::make([
                        Action::make('toggle_'.$key)
                            ->label($enabled ? __('Enabled') : __('Disabled'))
                            ->color($enabled ? 'success' : 'gray')
                            ->size('xs')
                            ->action(fn () => $this->toggleModule($key)),
                    ]),
                ]);
        }
        $schema[] = Section::make(__('Advanced Protection'))->schema($advSchema);

        return $schema;
    }

    // ── Firewall Tab ─────────────────────────────────────────────────

    protected function firewallTab(): array
    {
        $fw = $this->client()->get('/firewall/ufw/status') ?? ['available' => false];
        $active = $fw['active'] ?? false;

        return [
            Section::make(__('UFW Status'))
                ->schema([
                    SchemaActions::make([
                        Action::make('fw_toggle')
                            ->label($active ? __('Disable Firewall') : __('Enable Firewall'))
                            ->color($active ? 'danger' : 'success')
                            ->size('sm')
                            ->requiresConfirmation()
                            ->action(function () use ($active) {
                                $active
                                    ? $this->client()->post('/firewall/ufw/disable')
                                    : $this->client()->post('/firewall/ufw/enable');
                                $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'firewall']));
                            }),
                    ]),
                ]),
            EmbeddedTable::make(FirewallRulesTable::class),
        ];
    }

    // ── Config Tab ───────────────────────────────────────────────────

    protected function configTab(): array
    {
        $tabs = [];

        foreach (static::$configCategories as $category => $keys) {
            $fields = [];
            foreach ($keys as $key) {
                $help = static::$configHelp[$key] ?? '';
                if (in_array($key, static::$booleanKeys)) {
                    $fields[] = Toggle::make('configData.config_'.$key)
                        ->label($key)
                        ->helperText($help)
                        ->live();
                } elseif (isset(static::$selectKeys[$key])) {
                    $opts = array_combine(static::$selectKeys[$key], static::$selectKeys[$key]);
                    $fields[] = Select::make('configData.config_'.$key)
                        ->label($key)
                        ->options($opts)
                        ->helperText($help)
                        ->live();
                } else {
                    $fields[] = TextInput::make('configData.config_'.$key)
                        ->label($key)
                        ->helperText($help)
                        ->lazy();
                }
            }

            $tabs[$category] = Tab::make(__($category))->schema($fields);
        }

        return [
            Tabs::make(__('Configuration'))
                ->contained()
                ->tabs($tabs),
        ];
    }

    // ── Module Toggles ───────────────────────────────────────────────

    public function toggleModule(string $key): void
    {
        $config = $this->client()->get('/config') ?? [];
        $current = $config[$key] ?? 'no';
        $newValue = in_array($current, ['yes', 'true', '1']) ? 'no' : 'yes';

        $result = $this->client()->patch('/config', [$key => $newValue]);
        if ($result) {
            $label = str_replace('_', ' ', str_replace('_ENABLED', '', $key));
            Notification::make()
                ->title(__(':feature :action', [
                    'feature' => $label,
                    'action' => $newValue === 'yes' ? __('enabled') : __('disabled'),
                ]))
                ->color($newValue === 'yes' ? 'success' : 'warning')
                ->send();
        } else {
            Notification::make()->title(__('Failed to update config'))->danger()->send();
        }

        $this->redirect(static::getUrl(['tab' => 'overview']));
    }

    public function updateConfigValue(string $key, string $value): void
    {
        $this->client()->patch('/config', [$key => $value]);
    }

    public function saveAndRestart(): void
    {
        // Collect all form values
        $payload = [];
        foreach (static::$configCategories as $keys) {
            foreach ($keys as $key) {
                $formKey = 'config_'.$key;
                if (array_key_exists($formKey, $this->configData)) {
                    $val = $this->configData[$formKey];
                    if (in_array($key, static::$booleanKeys)) {
                        $val = $val ? 'yes' : 'no';
                    }
                    $payload[$key] = (string) $val;
                }
            }
        }

        // Save via API
        if (! empty($payload)) {
            $this->client()->patch('/config', $payload);
        }

        // Restart daemon
        \Illuminate\Support\Facades\Process::run('/usr/bin/systemctl restart jabali-security');

        Notification::make()
            ->title(__('Settings saved'))
            ->body(count($payload).' settings applied, daemon restarting...')
            ->success()
            ->send();
    }

    // ── Firewall Actions ─────────────────────────────────────────────

    public function enableFirewall(): void
    {
        $this->client()->post('/firewall/ufw/enable');
        Notification::make()->title(__('Firewall enabled'))->success()->send();
    }

    public function disableFirewall(): void
    {
        $this->client()->post('/firewall/ufw/disable');
        Notification::make()->title(__('Firewall disabled'))->success()->send();
    }

    public static array $configHelp = [
        'LOG_LEVEL' => 'Logging verbosity: debug shows everything, error shows only errors',
        'LOG_DIR' => 'Directory for daemon log files',
        'DATA_DIR' => 'Directory for SQLite database and cached data',
        'QUARANTINE_DIR' => 'Where quarantined malicious files are moved to',
        'WORKERS' => 'Number of parallel scan workers (1-32)',
        'API_BIND' => 'TCP bind address for API fallback. Empty = socket only (recommended)',
        'API_PORT' => 'TCP port when API_BIND is set',
        'API_KEY' => 'Authentication key for API access. Auto-generated on install',
        'API_SOCKET' => 'Unix socket path for secure local API communication',
        'WEB_ENABLED' => 'Enable the standalone web dashboard (port 8443)',
        'WEB_BIND' => 'Web dashboard bind address',
        'WEB_PORT' => 'Web dashboard port',
        'WATCH_DIRS' => 'Comma-separated directory globs to monitor for file changes',
        'SCAN_EXTENSIONS' => 'File extensions to scan (comma-separated)',
        'MAX_FILE_SIZE' => 'Maximum file size to scan in bytes (default 2MB)',
        'SKIP_DIRS' => 'Directory names to skip during scanning',
        'HEURISTIC_ENABLED' => 'Enable regex-based pattern matching for malicious code',
        'ENTROPY_ENABLED' => 'Enable Shannon entropy analysis for encoded payloads',
        'ENTROPY_THRESHOLD' => 'Entropy score threshold (0.0-8.0, default 4.5)',
        'YARA_ENABLED' => 'Enable YARA-X signature-based scanning',
        'YARA_RULES_DIR' => 'Directory containing .yar rule files',
        'CLAMAV_ENABLED' => 'ClamAV scanning: auto (detect), yes (require), no (disable)',
        'CLAMAV_SOCKET' => 'Path to clamd Unix socket',
        'FRESHCLAM_ON_UPDATE' => 'Run freshclam when reloading rules',
        'SCORE_LOG' => 'Minimum score to log an incident',
        'SCORE_QUARANTINE' => 'Minimum score to auto-quarantine a file',
        'SCORE_SUSPEND' => 'Minimum score to auto-suspend a hosting account',
        'PROCESS_MONITOR_ENABLED' => 'Monitor running processes for suspicious activity',
        'PROCESS_POLL_INTERVAL' => 'Seconds between process scans',
        'BEHAVIOR_TRACKING_ENABLED' => 'Track file creation patterns for behavioral analysis',
        'BEHAVIOR_TTL' => 'Seconds to keep behavioral tracking data',
        'AUTO_QUARANTINE' => 'Automatically quarantine files exceeding score threshold',
        'AUTO_SUSPEND' => 'Automatically suspend accounts exceeding score threshold',
        'AUTO_BLOCK_IP' => 'Automatically block IP addresses associated with attacks',
        'WAF_ENABLED' => 'Enable ModSecurity WAF event monitoring',
        'WAF_AUDIT_LOG' => 'Path to ModSecurity audit log file',
        'WAF_AUDIT_LOG_TYPE' => 'Audit log format: serial (single file) or concurrent',
        'WAF_RULES_DIR' => 'Directory containing OWASP CRS rule files',
        'WAF_OVERRIDES_FILE' => 'File for custom ModSecurity rule overrides',
        'WAF_CRS_AUTO_UPDATE' => 'Automatically update OWASP Core Rule Set',
        'WAF_WEB_SERVER' => 'Web server type: auto, nginx, or apache',
        'BRUTEFORCE_ENABLED' => 'Enable brute-force detection on auth logs',
        'BRUTEFORCE_SSH_LOG' => 'Path to SSH auth log (auth.log)',
        'BRUTEFORCE_MAIL_LOG' => 'Path to mail auth log (mail.log)',
        'BRUTEFORCE_STALWART_LOG' => 'Directory for Stalwart mail server logs',
        'BRUTEFORCE_SSH_THRESHOLD' => 'Failed SSH attempts before blocking',
        'BRUTEFORCE_SSH_WINDOW' => 'Time window in seconds for SSH threshold',
        'BRUTEFORCE_MAIL_THRESHOLD' => 'Failed mail login attempts before blocking',
        'BRUTEFORCE_MAIL_WINDOW' => 'Time window in seconds for mail threshold',
        'BRUTEFORCE_BLOCK_DURATIONS' => 'Progressive block durations in seconds (comma-separated, 0=permanent)',
        'FIREWALL_BACKEND' => 'IP blocking backend: auto, nftables, iptables, or none',
        'BRUTEFORCE_WHITELIST_IPS' => 'IPs that are never blocked (comma-separated)',
        'UFW_ENABLED' => 'Enable UFW firewall rule management via the API',
        'PROACTIVE_ENABLED' => 'Master switch for proactive defense features',
        'PHP_HARDENING_ENABLED' => 'Harden PHP-FPM pools with disable_functions and open_basedir',
        'PHP_HARDENING_AUTO' => 'Automatically harden new PHP-FPM pools',
        'PROCESS_KILL_ENABLED' => 'Kill suspicious processes (reverse shells, crypto miners)',
        'PROCESS_KILL_THRESHOLD' => 'Suspicion score threshold to kill a process (1-100)',
        'PROCESS_KILL_MIN_UID' => 'Minimum UID to consider for process killing',
        'PROCESS_KILL_WHITELIST' => 'Process names to never kill (comma-separated)',
        'CLEANUP_ENABLED' => 'Enable malware cleanup engine',
        'CLEANUP_AUTO' => 'Automatically clean detected malware',
        'CLEANUP_BACKUP_DIR' => 'Directory for cleanup backups before modification',
        'CLEANUP_CMS_CHECKSUMS' => 'Verify CMS file integrity using official checksums',
        'SCHEDULED_SCAN_ENABLED' => 'Enable periodic full-directory scanning',
        'SCHEDULED_SCAN_INTERVAL' => 'Hours between scheduled scans (1-8760)',
        'SCHEDULED_SCAN_PATHS' => 'Paths to scan on schedule (comma-separated globs)',
        'THREAT_INTEL_ENABLED' => 'Enable threat intelligence feed downloads',
        'THREAT_INTEL_UPDATE_INTERVAL' => 'Hours between feed updates (1-168)',
        'THREAT_INTEL_FEEDS' => 'Enabled feed names (comma-separated)',
        'THREAT_INTEL_AUTO_BLOCK' => 'Automatically block IPs found in threat feeds',
        'THREAT_INTEL_AUTO_BLOCK_THRESHOLD' => 'Number of feeds an IP must appear in before auto-blocking',
        'WEBSHIELD_ENABLED' => 'Enable nginx-level bot filtering and rate limiting',
        'WEBSHIELD_RATE_LIMIT' => 'Requests per second before rate limiting kicks in',
        'WEBSHIELD_RATE_BURST' => 'Maximum burst of requests allowed',
        'WEBSHIELD_CHALLENGE_ENABLED' => 'Serve JS challenge pages to suspicious clients',
        'WEBSHIELD_BOT_FILTERING' => 'Block known malicious user agents',
        'WEBSHIELD_NGINX_CONF_DIR' => 'Directory for WebShield nginx config snippets',
        'DB_SCANNER_ENABLED' => 'Enable database injection scanning',
        'RAPIDSCAN_WORKERS' => 'Parallel workers for rapid directory scans',
        'RAPIDSCAN_MTIME_CACHE' => 'Cache file modification times to skip unchanged files',
        'NOTIFY_EMAIL' => 'Email address for high-severity notifications',
        'NOTIFY_WEBHOOK' => 'Webhook URL for incident notifications',
        'NOTIFY_MIN_SEVERITY' => 'Minimum severity to trigger notifications',
        'INCIDENT_RETAIN_DAYS' => 'Days to keep incident records before cleanup',
    ];

    // ── Static Data ──────────────────────────────────────────────────

    public static function getModuleToggles(): array
    {
        return [
            'core' => [
                'HEURISTIC_ENABLED' => ['label' => 'Heuristic Scanner', 'desc' => 'Regex pattern matching for malicious code'],
                'ENTROPY_ENABLED' => ['label' => 'Entropy Scanner', 'desc' => 'Detects encoded/obfuscated payloads'],
                'YARA_ENABLED' => ['label' => 'YARA-X Rules', 'desc' => 'Signature-based scanning'],
                'PROCESS_MONITOR_ENABLED' => ['label' => 'Process Monitor', 'desc' => 'Monitors suspicious processes'],
                'BEHAVIOR_TRACKING_ENABLED' => ['label' => 'Behavior Tracking', 'desc' => 'Tracks file lifecycle patterns'],
                'AUTO_QUARANTINE' => ['label' => 'Auto Quarantine', 'desc' => 'Quarantine files above score threshold'],
            ],
            'advanced' => [
                'WAF_ENABLED' => ['label' => 'WAF (ModSecurity)', 'desc' => 'Web application firewall with OWASP CRS'],
                'BRUTEFORCE_ENABLED' => ['label' => 'Brute-Force Protection', 'desc' => 'Blocks IPs after failed logins'],
                'PROACTIVE_ENABLED' => ['label' => 'Proactive Defense', 'desc' => 'Master switch for PHP hardening and process killer'],
                'PROCESS_KILL_ENABLED' => ['label' => 'Process Killer', 'desc' => 'Kills reverse shells and miners'],
                'PHP_HARDENING_ENABLED' => ['label' => 'PHP Hardening', 'desc' => 'disable_functions and open_basedir per pool'],
                'WEBSHIELD_ENABLED' => ['label' => 'WebShield', 'desc' => 'Nginx bot filtering and rate limiting'],
                'THREAT_INTEL_ENABLED' => ['label' => 'Threat Intelligence', 'desc' => 'IP reputation and malware hash feeds'],
                'CLEANUP_ENABLED' => ['label' => 'Auto Cleanup', 'desc' => 'Removes injected code from files'],
                'UFW_ENABLED' => ['label' => 'UFW Firewall', 'desc' => 'Manage system firewall rules'],
                'SCHEDULED_SCAN_ENABLED' => ['label' => 'Scheduled Scans', 'desc' => 'Periodic full-path scanning'],
                'AUTO_SUSPEND' => ['label' => 'Auto Suspend', 'desc' => 'Suspends accounts above score threshold'],
            ],
        ];
    }

    public static array $booleanKeys = [
        'HEURISTIC_ENABLED', 'ENTROPY_ENABLED', 'YARA_ENABLED', 'PROCESS_MONITOR_ENABLED',
        'BEHAVIOR_TRACKING_ENABLED', 'AUTO_QUARANTINE', 'AUTO_SUSPEND', 'AUTO_BLOCK_IP',
        'WAF_ENABLED', 'WAF_CRS_AUTO_UPDATE', 'BRUTEFORCE_ENABLED', 'PROACTIVE_ENABLED',
        'PHP_HARDENING_ENABLED', 'PHP_HARDENING_AUTO', 'PROCESS_KILL_ENABLED',
        'CLEANUP_ENABLED', 'CLEANUP_AUTO', 'CLEANUP_CMS_CHECKSUMS',
        'SCHEDULED_SCAN_ENABLED', 'THREAT_INTEL_ENABLED', 'THREAT_INTEL_AUTO_BLOCK',
        'WEBSHIELD_ENABLED', 'WEBSHIELD_CHALLENGE_ENABLED', 'WEBSHIELD_BOT_FILTERING',
        'WEB_ENABLED', 'DB_SCANNER_ENABLED', 'RAPIDSCAN_MTIME_CACHE', 'FRESHCLAM_ON_UPDATE',
        'UFW_ENABLED',
    ];

    public static array $selectKeys = [
        'LOG_LEVEL' => ['debug', 'info', 'warning', 'error', 'critical'],
        'CLAMAV_ENABLED' => ['auto', 'yes', 'no'],
        'FIREWALL_BACKEND' => ['auto', 'nftables', 'iptables', 'none'],
        'WAF_AUDIT_LOG_TYPE' => ['serial', 'concurrent'],
        'WAF_WEB_SERVER' => ['auto', 'nginx', 'apache'],
        'NOTIFY_MIN_SEVERITY' => ['low', 'medium', 'high', 'critical'],
    ];

    public static array $configCategories = [
        'Daemon' => ['LOG_LEVEL', 'LOG_DIR', 'DATA_DIR', 'QUARANTINE_DIR', 'WORKERS'],
        'File Watcher' => ['WATCH_DIRS'],
        'Pre-Filter' => ['SCAN_EXTENSIONS', 'MAX_FILE_SIZE', 'SKIP_DIRS'],
        'Detection' => ['HEURISTIC_ENABLED', 'ENTROPY_ENABLED', 'ENTROPY_THRESHOLD', 'YARA_ENABLED', 'YARA_RULES_DIR'],
        'ClamAV' => ['CLAMAV_ENABLED', 'CLAMAV_SOCKET', 'FRESHCLAM_ON_UPDATE'],
        'Scoring' => ['SCORE_LOG', 'SCORE_QUARANTINE', 'SCORE_SUSPEND'],
        'Process Monitor' => ['PROCESS_MONITOR_ENABLED', 'PROCESS_POLL_INTERVAL'],
        'Behavior' => ['BEHAVIOR_TRACKING_ENABLED', 'BEHAVIOR_TTL'],
        'Response' => ['AUTO_QUARANTINE', 'AUTO_SUSPEND', 'AUTO_BLOCK_IP'],
        'WAF' => ['WAF_ENABLED', 'WAF_AUDIT_LOG', 'WAF_AUDIT_LOG_TYPE', 'WAF_RULES_DIR', 'WAF_OVERRIDES_FILE', 'WAF_CRS_AUTO_UPDATE', 'WAF_WEB_SERVER'],
        'Brute-Force' => ['BRUTEFORCE_ENABLED', 'BRUTEFORCE_SSH_LOG', 'BRUTEFORCE_MAIL_LOG', 'BRUTEFORCE_STALWART_LOG', 'BRUTEFORCE_SSH_THRESHOLD', 'BRUTEFORCE_SSH_WINDOW', 'BRUTEFORCE_MAIL_THRESHOLD', 'BRUTEFORCE_MAIL_WINDOW', 'BRUTEFORCE_BLOCK_DURATIONS', 'FIREWALL_BACKEND', 'BRUTEFORCE_WHITELIST_IPS'],
        'UFW' => ['UFW_ENABLED'],
        'Proactive' => ['PROACTIVE_ENABLED', 'PHP_HARDENING_ENABLED', 'PHP_HARDENING_AUTO', 'PROCESS_KILL_ENABLED', 'PROCESS_KILL_THRESHOLD', 'PROCESS_KILL_MIN_UID', 'PROCESS_KILL_WHITELIST'],
        'Cleanup' => ['CLEANUP_ENABLED', 'CLEANUP_AUTO', 'CLEANUP_BACKUP_DIR', 'CLEANUP_CMS_CHECKSUMS'],
        'Scheduled Scan' => ['SCHEDULED_SCAN_ENABLED', 'SCHEDULED_SCAN_INTERVAL', 'SCHEDULED_SCAN_PATHS'],
        'Threat Intel' => ['THREAT_INTEL_ENABLED', 'THREAT_INTEL_UPDATE_INTERVAL', 'THREAT_INTEL_FEEDS', 'THREAT_INTEL_AUTO_BLOCK', 'THREAT_INTEL_AUTO_BLOCK_THRESHOLD'],
        'WebShield' => ['WEBSHIELD_ENABLED', 'WEBSHIELD_RATE_LIMIT', 'WEBSHIELD_RATE_BURST', 'WEBSHIELD_CHALLENGE_ENABLED', 'WEBSHIELD_BOT_FILTERING', 'WEBSHIELD_NGINX_CONF_DIR'],
        'Performance' => ['DB_SCANNER_ENABLED', 'RAPIDSCAN_WORKERS', 'RAPIDSCAN_MTIME_CACHE'],
        'Notifications' => ['NOTIFY_EMAIL', 'NOTIFY_WEBHOOK', 'NOTIFY_MIN_SEVERITY'],
        'Retention' => ['INCIDENT_RETAIN_DAYS'],
    ];
}
