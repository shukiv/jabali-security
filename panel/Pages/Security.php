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
use App\JabaliSecurity\Widgets\BruteforceStatsWidget;
use App\JabaliSecurity\Widgets\ProactiveStatsWidget;
use App\JabaliSecurity\Widgets\RulesStatsWidget;
use App\JabaliSecurity\Widgets\SecurityStatsWidget;
use App\JabaliSecurity\Widgets\WafStatsWidget;
use App\JabaliSecurity\Widgets\WebshieldStatsWidget;
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
use Filament\Schemas\Components\Livewire;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Tabs;
use Filament\Schemas\Components\Tabs\Tab;
use Filament\Schemas\Schema;
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
                            [Livewire::make(SecurityStatsWidget::class)],
                            $this->overviewTab(),
                        )),
                    'incidents' => Tab::make(__('Incidents'))
                        ->icon('heroicon-o-exclamation-triangle')
                        ->schema([EmbeddedTable::make(IncidentsTable::class)]),
                    'quarantine' => Tab::make(__('Quarantine'))
                        ->icon('heroicon-o-lock-closed')
                        ->schema([EmbeddedTable::make(QuarantineTable::class)]),
                    'blocklist' => Tab::make(__('Blocklist'))
                        ->icon('heroicon-o-no-symbol')
                        ->schema([EmbeddedTable::make(BlocklistTable::class)]),
                    'waf' => Tab::make(__('WAF'))
                        ->icon('heroicon-o-shield-exclamation')
                        ->schema([Livewire::make(WafStatsWidget::class), EmbeddedTable::make(WafEventsTable::class)]),
                    'firewall' => Tab::make(__('Firewall'))
                        ->icon('heroicon-o-fire')
                        ->schema($this->firewallTab()),
                    'bruteforce' => Tab::make(__('Brute-Force'))
                        ->icon('heroicon-o-key')
                        ->schema([Livewire::make(BruteforceStatsWidget::class), EmbeddedTable::make(BruteforceBlockedTable::class)]),
                    'proactive' => Tab::make(__('Proactive'))
                        ->icon('heroicon-o-bolt')
                        ->schema([Livewire::make(ProactiveStatsWidget::class), EmbeddedTable::make(PhpPoolsTable::class)]),
                    'webshield' => Tab::make(__('WebShield'))
                        ->icon('heroicon-o-globe-alt')
                        ->schema([Livewire::make(WebshieldStatsWidget::class), EmbeddedTable::make(WebshieldRulesTable::class)]),
                    'threatintel' => Tab::make(__('Threat Intel'))
                        ->icon('heroicon-o-globe-americas')
                        ->schema([EmbeddedTable::make(ThreatFeedsTable::class)]),
                    'users' => Tab::make(__('Users'))
                        ->icon('heroicon-o-users')
                        ->schema([EmbeddedTable::make(UsersTable::class)]),
                    'cleanup' => Tab::make(__('Cleanup'))
                        ->icon('heroicon-o-sparkles')
                        ->schema([EmbeddedTable::make(CleanupRecordsTable::class)]),
                    'rules' => Tab::make(__('Rules'))
                        ->icon('heroicon-o-document-text')
                        ->schema([Livewire::make(RulesStatsWidget::class), EmbeddedTable::make(YaraRulesTable::class)]),
                    'config' => Tab::make(__('Configuration'))
                        ->icon('heroicon-o-cog-6-tooth')
                        ->schema($this->configTab()),
                ]),
        ]);
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
                                $this->redirect(static::getUrl(['tab' => 'firewall']));
                            }),
                    ]),
                ]),
            EmbeddedTable::make(FirewallRulesTable::class),
        ];
    }

    // ── Config Tab ───────────────────────────────────────────────────

    protected function configTab(): array
    {
        $config = $this->client()->get('/config') ?? [];
        $tabs = [];

        foreach (static::$configCategories as $category => $keys) {
            $fields = [];
            foreach ($keys as $key) {
                $val = $config[$key] ?? '';

                if (in_array($key, static::$booleanKeys)) {
                    $fields[] = Toggle::make('config_'.$key)
                        ->label($key)
                        ->default(in_array($val, ['yes', 'true', '1']))
                        ->live()
                        ->afterStateUpdated(fn ($state) => $this->updateConfigValue($key, $state ? 'yes' : 'no'));
                } elseif (isset(static::$selectKeys[$key])) {
                    $opts = array_combine(static::$selectKeys[$key], static::$selectKeys[$key]);
                    $fields[] = Select::make('config_'.$key)
                        ->label($key)
                        ->options($opts)
                        ->default($val)
                        ->live()
                        ->afterStateUpdated(fn ($state) => $this->updateConfigValue($key, $state ?? ''));
                } else {
                    $fields[] = TextInput::make('config_'.$key)
                        ->label($key)
                        ->default($val);
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
        $result = $this->client()->patch('/config', [$key => $value]);
        Notification::make()
            ->title($result ? __('Config updated') : __('Update failed'))
            ->body($result ? __('Restart daemon to apply changes') : '')
            ->color($result ? 'success' : 'danger')
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
        'API' => ['API_BIND', 'API_PORT', 'API_KEY'],
        'Web Dashboard' => ['WEB_ENABLED', 'WEB_BIND', 'WEB_PORT'],
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
