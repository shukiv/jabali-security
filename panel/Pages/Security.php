<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Pages;

use App\JabaliSecurity\JabaliSecurityClient;
use App\JabaliSecurity\Widgets\BlocklistTable;
use App\JabaliSecurity\Widgets\BruteforceBlockedTable;
use App\JabaliSecurity\Widgets\CleanupRecordsTable;
use App\JabaliSecurity\Widgets\FirewallRulesTable;
use App\JabaliSecurity\Widgets\IncidentsTable;
use App\JabaliSecurity\Widgets\QuarantineTable;
use App\JabaliSecurity\Widgets\ScanUsersTable;
use App\JabaliSecurity\Widgets\SshKeysTable;
use App\JabaliSecurity\Widgets\ThreatFeedsTable;
use App\JabaliSecurity\Widgets\UsersTable;
use App\JabaliSecurity\Widgets\WafEventsTable;
use App\JabaliSecurity\Widgets\WebshieldRulesTable;
use App\JabaliSecurity\Widgets\WhitelistTable;
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

    public static function canAccess(): bool
    {
        return auth()->user()?->isAdmin() ?? false;
    }

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

    public array $moduleStates = [];

    public bool $expertMode = false;

    public function mount(): void
    {
        $config = $this->client()->get('/config') ?? [];
        $this->loadConfigData($config);
        $this->loadModuleStates($config);
    }

    protected function loadModuleStates(array $config): void
    {
        foreach (static::getModuleToggles() as $group) {
            foreach ($group as $key => $mod) {
                $this->moduleStates[$key] = in_array($config[$key] ?? 'no', ['yes', 'true', '1']);
            }
        }
        // SSH Jail is not in module toggles but needs state tracking
        $this->moduleStates['SSHJAIL_ENABLED'] = in_array($config['SSHJAIL_ENABLED'] ?? 'no', ['yes', 'true', '1']);
    }

    /** Keys allowed through moduleStates Livewire binding. */
    private static function allowedModuleKeys(): array
    {
        $keys = ['SSHJAIL_ENABLED'];
        foreach (static::getModuleToggles() as $group) {
            foreach ($group as $key => $mod) {
                $keys[] = $key;
            }
        }
        return $keys;
    }

    public function updatedModuleStates($value, string $key): void
    {
        if (! in_array($key, static::allowedModuleKeys(), true)) {
            return;
        }

        $newValue = $value ? 'yes' : 'no';
        $this->client()->patch('/config', [$key => $newValue]);

        $label = str_replace('_', ' ', str_replace('_ENABLED', '', $key));
        Notification::make()
            ->title(__(':feature :action', [
                'feature' => $label,
                'action' => $value ? __('enabled') : __('disabled'),
            ]))
            ->color($value ? 'success' : 'warning')
            ->send();
    }

    protected function loadConfigData(array $config): void
    {
        $data = [];
        foreach (static::$configCategories as $keys) {
            foreach ($keys as $key) {
                $val = $config[$key] ?? '';
                if (in_array($key, static::$booleanKeys)) {
                    $data['config_'.$key] = in_array($val, ['yes', 'true', '1']);
                } else {
                    $data['config_'.$key] = $val;
                }
            }
        }
        $this->configData = $data;
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
        return JabaliSecurityClient::getInstance();
    }

    // ── Header Actions ───────────────────────────────────────────────

    protected function getHeaderActions(): array
    {
        return [];
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
                                        ->schema([
                                            Text::make(__('Security events detected by the scanning engines (heuristic, entropy, YARA-X, ClamAV). Each scanner assigns a score to its findings, which are aggregated into a total threat score. Scoring thresholds determine the action: below 40 = ignored, 40-70 = logged as incident (low/medium), 70-100 = file quarantined (high), 100+ = account suspended (critical). These thresholds are configurable in Settings. You can review details and resolve incidents here.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(IncidentsTable::class),
                                        ]),
                                    'quarantine' => Tab::make(__('Quarantine'))
                                        ->schema([
                                            Text::make(__('Files that exceeded the quarantine score threshold have been moved here for safe isolation. You can restore false positives or permanently delete confirmed threats.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(QuarantineTable::class),
                                        ]),
                                    'cleanup' => Tab::make(__('Cleanup'))
                                        ->schema([
                                            Text::make(__('Records of automated and manual malware cleanup operations. Shows which files were cleaned, what injection patterns were removed, and where backups are stored.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(CleanupRecordsTable::class),
                                        ]),
                                ]),
                        ]),
                    'scan' => Tab::make(__('Scan'))
                        ->icon('heroicon-o-magnifying-glass')
                        ->schema([
                            Text::make(__('Scan user directories for malware, webshells, and suspicious files. Uses heuristic, entropy, and YARA-X engines. ClamAV is used when enabled.'))
                                ->size(TextSize::Small)
                                ->color('gray'),
                            EmbeddedTable::make(ScanUsersTable::class),
                        ]),
                    'defense' => Tab::make(__('Defense'))
                        ->icon('heroicon-o-shield-check')
                        ->schema([
                            Tabs::make(__('Defense'))
                                ->contained(false)
                                ->livewireProperty('defenseTab')
                                ->tabs([
                                    'firewall' => Tab::make(__('Firewall'))
                                        ->schema(array_merge(
                                            [Text::make(__('Manage UFW (Uncomplicated Firewall) rules to control inbound and outbound traffic. Add port rules, IP-based allow/deny rules, and manage application profiles.'))->size(TextSize::Small)->color('gray')],
                                            $this->firewallTab(),
                                        )),
                                    'blocklist' => Tab::make(__('Blocklist'))
                                        ->schema([
                                            Text::make(__('IP addresses blocked by manual action, brute-force detection, or threat intelligence feeds. You can manually block or unblock IPs with optional expiry times.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(BlocklistTable::class),
                                        ]),
                                    'waf' => Tab::make(__('WAF'))
                                        ->schema(array_merge(
                                            [Text::make(__('Web Application Firewall events from ModSecurity with OWASP Core Rule Set. Shows blocked attacks (SQLi, XSS, path traversal) and lets you manage CRS rules.'))->size(TextSize::Small)->color('gray')],
                                            $this->wafStats(),
                                            [EmbeddedTable::make(WafEventsTable::class)],
                                        )),
                                    'bruteforce' => Tab::make(__('Brute-Force'))
                                        ->schema(array_merge(
                                            [Text::make(__('Monitors SSH and mail service logs for repeated failed login attempts. IPs exceeding the threshold are automatically blocked with progressive ban durations.'))->size(TextSize::Small)->color('gray')],
                                            $this->bruteforceStats(),
                                            [
                                                Tabs::make(__('Brute-Force Lists'))
                                                    ->contained(false)
                                                    ->tabs([
                                                        'blocked' => Tab::make(__('Blocklist'))
                                                            ->icon('heroicon-o-no-symbol')
                                                            ->schema([EmbeddedTable::make(BruteforceBlockedTable::class)]),
                                                        'whitelist' => Tab::make(__('Whitelist'))
                                                            ->icon('heroicon-o-shield-check')
                                                            ->schema([EmbeddedTable::make(WhitelistTable::class)]),
                                                    ]),
                                            ],
                                        )),
                                    'crowdsec' => Tab::make(__('CrowdSec'))
                                        ->schema(array_merge(
                                            [Text::make(__('Community threat intelligence powered by 200,000+ installations. CrowdSec detects attacks from server logs and shares signals globally. Known attackers get faster blocks.'))
                                                ->size(TextSize::Small)
                                                ->color('gray')],
                                            $this->crowdsecStats(),
                                        )),
                                    'proactive' => Tab::make(__('Proactive'))
                                        ->schema(array_merge(
                                            [Text::make(__('Suspicious process killer: detects and terminates reverse shells, crypto miners, and other malicious processes.'))->size(TextSize::Small)->color('gray')],
                                            $this->proactiveStats(),
                                        )),
                                    'webshield' => Tab::make(__('WebShield'))
                                        ->schema(array_merge(
                                            [Text::make(__('Nginx-level protection: rate limiting, bot user-agent filtering, and JavaScript challenge pages for suspicious clients. Requires nginx include after install.'))->size(TextSize::Small)->color('gray')],
                                            $this->webshieldStats(),
                                            [EmbeddedTable::make(WebshieldRulesTable::class)],
                                        )),
                                    'ssh' => Tab::make(__('SSH Jail'))
                                        ->schema(array_merge(
                                            [
                                                Text::make(__('SSH/SFTP access management with chroot jailshell. Users get SFTP-only access by default. Shell access provides a jailed environment with wp-cli and basic commands.'))
                                                    ->size(TextSize::Small)
                                                    ->color('gray'),
                                            ],
                                            $this->sshdSettingsStats(),
                                            [EmbeddedTable::make(SshKeysTable::class)],
                                        )),
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
                                        ->schema(array_merge(
                                            [Text::make(__('Detection engine status and YARA-X rule files used for signature-based malware scanning. Shows active scanners (heuristic, entropy, YARA, ClamAV) and rule file details.'))->size(TextSize::Small)->color('gray')],
                                            $this->rulesStats(),
                                            [EmbeddedTable::make(YaraRulesTable::class)],
                                        )),
                                    'threatintel' => Tab::make(__('Threat Intel'))
                                        ->schema([
                                            Text::make(__('Threat intelligence feeds providing IP reputation and malware hash databases. Feeds update automatically and can be used to auto-block known malicious IPs.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(ThreatFeedsTable::class),
                                        ]),
                                    'users' => Tab::make(__('Users'))
                                        ->schema([
                                            Text::make(__('Per-user risk profiles showing incident counts and threat scores. Helps identify compromised hosting accounts that need attention.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(UsersTable::class),
                                        ]),
                                ]),
                        ]),
                    'settings' => Tab::make(__('Settings'))
                        ->icon('heroicon-o-cog-6-tooth')
                        ->schema(array_merge(
                            [Text::make(__('Daemon configuration for all security modules. Changes are saved to /etc/jabali-security/jabali-security.conf. Click Save & Restart to apply.'))->size(TextSize::Small)->color('gray')],
                            $this->configTab(),
                        )),
                ]),
        ]);
    }

    // ── Stat Cards (schema-based, compact) ─────────────────────────


    public function getOverviewStatsDataProperty(): array
    {
        $s = $this->client()->get('/status');
        if (! $s) {
            return [['value' => __('Offline'), 'label' => __('Daemon'), 'icon' => 'heroicon-o-server', 'color' => 'danger']];
        }

        $cs = $this->client()->get('/crowdsec/status');
        $csConnected = $cs['connected'] ?? false;
        $csDecisions = $cs['active_decisions'] ?? 0;

        return [
            ['value' => (string) ($s['incidents_24h'] ?? 0), 'label' => __('Incidents'), 'icon' => 'heroicon-o-exclamation-triangle', 'color' => ($s['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success'],
            ['value' => (string) ($s['attacks_blocked_24h'] ?? 0), 'label' => __('Blocked'), 'icon' => 'heroicon-o-shield-check', 'color' => ($s['attacks_blocked_24h'] ?? 0) > 0 ? 'warning' : 'success'],
            ['value' => (string) ($s['quarantined_count'] ?? 0), 'label' => __('Quarantine'), 'icon' => 'heroicon-o-lock-closed', 'color' => ($s['quarantined_count'] ?? 0) > 0 ? 'warning' : 'success'],
            ['value' => (string) ($s['watched_dirs'] ?? 0), 'label' => __('Watching'), 'icon' => 'heroicon-o-eye', 'color' => 'info'],
            ['value' => $csConnected ? (string) $csDecisions : __('Off'), 'label' => __('CrowdSec'), 'icon' => 'heroicon-o-globe-alt', 'color' => $csConnected ? 'success' : 'gray'],
            ['value' => ($s['running'] ?? false) ? __('Online') : __('Offline'), 'label' => __('Daemon'), 'icon' => 'heroicon-o-server', 'color' => ($s['running'] ?? false) ? 'success' : 'danger'],
        ];
    }

    protected function overviewStats(): array
    {
        $data = $this->getOverviewStatsDataProperty();
        return [Grid::make(3)->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }



    private function getWafStatsData(): array
    {
        $s = $this->client()->get('/waf/stats') ?? [];
        return [
            ['value' => (string) ($s['total_events_24h'] ?? 0), 'label' => __('Events (24h)'), 'icon' => 'heroicon-o-bolt', 'color' => ($s['total_events_24h'] ?? 0) > 0 ? 'warning' : 'success'],
            ['value' => (string) ($s['blocked_24h'] ?? 0), 'label' => __('Blocked (24h)'), 'icon' => 'heroicon-o-no-symbol', 'color' => ($s['blocked_24h'] ?? 0) > 0 ? 'danger' : 'success'],
        ];
    }

    private function getCrowdsecStatsData(): array
    {
        $s = $this->client()->get('/crowdsec/status') ?? [];
        $connected = $s['connected'] ?? false;
        return [
            ['value' => $connected ? __('Connected') : __('Disconnected'), 'label' => __('LAPI'), 'icon' => 'heroicon-o-globe-alt', 'color' => $connected ? 'success' : 'gray'],
            ['value' => (string) ($s['active_decisions'] ?? 0), 'label' => __('Decisions'), 'icon' => 'heroicon-o-shield-check', 'color' => ($s['active_decisions'] ?? 0) > 0 ? 'warning' : 'success'],
            ['value' => (string) ($s['blocked_ips'] ?? 0), 'label' => __('Blocked IPs'), 'icon' => 'heroicon-o-no-symbol', 'color' => ($s['blocked_ips'] ?? 0) > 0 ? 'danger' : 'success'],
        ];
    }

    private function getBruteforceStatsData(): array
    {
        $s = $this->client()->get('/bruteforce/stats') ?? [];
        return [
            ['value' => (string) ($s['tracked_ips'] ?? 0), 'label' => __('Tracked IPs'), 'icon' => 'heroicon-o-signal', 'color' => 'info'],
            ['value' => (string) ($s['blocked_count'] ?? 0), 'label' => __('Blocked'), 'icon' => 'heroicon-o-no-symbol', 'color' => ($s['blocked_count'] ?? 0) > 0 ? 'danger' : 'success'],
        ];
    }

    private function getProactiveStatsData(): array
    {
        $s = $this->client()->get('/proactive/status') ?? [];
        return [
            ['value' => ($s['process_kill_enabled'] ?? false) ? __('Active') : __('Disabled'), 'label' => __('Process Killer'), 'icon' => 'heroicon-o-fire', 'color' => ($s['process_kill_enabled'] ?? false) ? 'success' : 'gray'],
            ['value' => (string) ($s['process_kill_count'] ?? 0), 'label' => __('Processes Killed'), 'icon' => 'heroicon-o-x-circle', 'color' => ($s['process_kill_count'] ?? 0) > 0 ? 'warning' : 'success'],
        ];
    }

    private function getWebshieldStatsData(): array
    {
        $s = $this->client()->get('/webshield/status') ?? [];
        return [
            ['value' => ($s['installed'] ?? false) ? __('Yes') : __('No'), 'label' => __('Installed'), 'icon' => 'heroicon-o-check-circle', 'color' => ($s['installed'] ?? false) ? 'success' : 'danger'],
            ['value' => ($s['rate_limiting'] ?? false) ? __('On') : __('Off'), 'label' => __('Rate Limiting'), 'icon' => 'heroicon-o-clock', 'color' => ($s['rate_limiting'] ?? false) ? 'success' : 'danger'],
            ['value' => ($s['bot_filtering'] ?? false) ? __('On') : __('Off'), 'label' => __('Bot Filtering'), 'icon' => 'heroicon-o-funnel', 'color' => ($s['bot_filtering'] ?? false) ? 'success' : 'danger'],
            ['value' => (string) ($s['blocked_ips_count'] ?? 0), 'label' => __('Blocked IPs'), 'icon' => 'heroicon-o-no-symbol', 'color' => ($s['blocked_ips_count'] ?? 0) > 0 ? 'danger' : 'success'],
            ['value' => (string) ($s['bot_blocked_24h'] ?? 0), 'label' => __('Bots Blocked'), 'icon' => 'heroicon-o-bug-ant', 'color' => ($s['bot_blocked_24h'] ?? 0) > 0 ? 'warning' : 'success'],
            ['value' => (string) ($s['rate_limited_24h'] ?? 0), 'label' => __('Rate Limited'), 'icon' => 'heroicon-o-clock', 'color' => ($s['rate_limited_24h'] ?? 0) > 0 ? 'warning' : 'success'],
        ];
    }

    private function getRulesStatsData(): array
    {
        $r = $this->client()->get('/rules') ?? [];
        return [
            ['value' => ($r['yara_enabled'] ?? false) ? __('Enabled') : __('Disabled'), 'label' => __('YARA'), 'icon' => 'heroicon-o-document-magnifying-glass', 'color' => ($r['yara_enabled'] ?? false) ? 'success' : 'gray'],
            ['value' => ($r['clamav_enabled'] ?? false) ? __('Enabled') : __('Disabled'), 'label' => __('ClamAV'), 'icon' => 'heroicon-o-shield-check', 'color' => ($r['clamav_enabled'] ?? false) ? 'success' : 'gray'],
            ['value' => implode(', ', $r['scanners'] ?? []), 'label' => __('Scanners'), 'icon' => 'heroicon-o-magnifying-glass', 'color' => 'info'],
        ];
    }

    protected function wafStats(): array
    {
        $data = $this->getWafStatsData();
        return [Grid::make(count($data))->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    protected function crowdsecStats(): array
    {
        $data = $this->getCrowdsecStatsData();
        return [Grid::make(count($data))->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    protected function bruteforceStats(): array
    {
        $data = $this->getBruteforceStatsData();
        return [Grid::make(count($data))->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    protected function proactiveStats(): array
    {
        $data = $this->getProactiveStatsData();
        return [Grid::make(count($data))->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    protected function webshieldStats(): array
    {
        $data = $this->getWebshieldStatsData();
        return [Grid::make(3)->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    protected function rulesStats(): array
    {
        $data = $this->getRulesStatsData();
        return [Grid::make(count($data))->dense()->schema(array_map(fn ($s) => $this->dashboardCard($s), $data))];
    }

    private function dashboardCard(array $stat): Section
    {
        return Section::make($stat['label'] . ': ' . $stat['value'])
            ->icon($stat['icon'])
            ->iconColor($stat['color'])
            ->schema([]);
    }

    protected function sshdSettingsStats(): array
    {
        $s = $this->client()->get('/ssh/sshd-settings') ?? [];
        $passAuth = $s['password_auth'] ?? true;
        $port = (int) ($s['port'] ?? 22);

        $jailEnabled = in_array($this->moduleStates['SSHJAIL_ENABLED'] ?? false, [true, 'yes', '1', 1]);

        $config = $this->client()->get('/config') ?? [];
        $shellDefault = in_array($config['SSH_SHELL_ACCESS_ENABLED'] ?? 'no', ['yes', 'true', '1']);

        return [
            Grid::make(3)->dense()->schema([
                Section::make(new \Illuminate\Support\HtmlString(
                    __('SSH Shell Default') . ': <span style="color:' . ($shellDefault ? '#22c55e' : '#ef4444') . '">' . ($shellDefault ? __('Enabled') : __('Disabled')) . '</span>'
                ))
                    ->compact()
                    ->headerActions([
                        Action::make('toggleShellDefault')
                            ->label($shellDefault ? __('Disable') : __('Enable'))
                            ->color($shellDefault ? 'gray' : 'success')
                            ->size('xs')
                            ->action('toggleShellDefault'),
                    ])
                    ->schema([]),
                Section::make(new \Illuminate\Support\HtmlString(
                    __('Password Auth') . ': <span style="color:' . ($passAuth ? '#22c55e' : '#ef4444') . '">' . ($passAuth ? __('Enabled') : __('Disabled')) . '</span>'
                ))
                    ->compact()
                    ->headerActions([
                        Action::make('toggleSshPasswordAuth')
                            ->label($passAuth ? __('Disable') : __('Enable'))
                            ->color($passAuth ? 'gray' : 'success')
                            ->size('xs')
                            ->requiresConfirmation()
                            ->modalDescription($passAuth
                                ? __('Users will only be able to log in with SSH keys.')
                                : __('Users will be able to log in with passwords.'))
                            ->action($passAuth ? 'disableSshPasswordAuth' : 'enableSshPasswordAuth'),
                    ])
                    ->schema([]),
                Section::make(new \Illuminate\Support\HtmlString(
                    __('SSH Port') . ': <span style="color:#eab308">' . $port . '</span>'
                ))
                    ->compact()
                    ->headerActions([
                        Action::make('changeSshPort')
                            ->label(__('Change'))
                            ->color('gray')
                            ->size('xs')
                            ->form([
                                TextInput::make('port')
                                    ->label(__('SSH Port'))
                                    ->numeric()
                                    ->default($port)
                                    ->minValue(1)
                                    ->maxValue(65535)
                                    ->required(),
                            ])
                            ->requiresConfirmation()
                            ->action('changeSshPortAction'),
                    ])
                    ->schema([]),
            ]),
        ];
    }


    // ── Overview Tab ─────────────────────────────────────────────────

    protected function overviewTab(): array
    {
        $modules = static::getModuleToggles();

        $coreToggles = [];
        foreach ($modules['core'] as $key => $mod) {
            $coreToggles[] = Toggle::make('moduleStates.'.$key)
                ->label(__($mod['label']))
                ->helperText(__($mod['desc']))
                ->live();
        }

        $advToggles = [];
        foreach ($modules['advanced'] as $key => $mod) {
            $advToggles[] = Toggle::make('moduleStates.'.$key)
                ->label(__($mod['label']))
                ->helperText(__($mod['desc']))
                ->live();
        }

        $attackMode = $this->client()->get('/attack-mode') ?? ['active' => false];
        $underAttack = $attackMode['active'] ?? false;

        return [
            Section::make($underAttack ? __('UNDER ATTACK MODE ACTIVE') : __('Under Attack Mode'))
                ->description($underAttack
                    ? __('Active defenses: process killer (threshold 50), auto-block IPs, brute-force limit 3 attempts/120s, WAF blocking, WebShield rate limiting (10 req/s), progressive bans (1h→24h→permanent).')
                    : __('Panic button for active attacks. Enables: process killer, auto-block IPs, WAF blocking, WebShield rate limiting, aggressive brute-force thresholds, and progressive IP bans.'))
                ->icon($underAttack ? 'heroicon-o-fire' : 'heroicon-o-shield-exclamation')
                ->iconColor($underAttack ? 'danger' : 'gray')
                ->headerActions([
                    Action::make('toggleAttackMode')
                        ->label($underAttack ? __('Disable Attack Mode') : __('I Am Under Attack!'))
                        ->icon($underAttack ? 'heroicon-o-shield-check' : 'heroicon-o-fire')
                        ->color($underAttack ? 'gray' : 'danger')
                        ->size('lg')
                        ->requiresConfirmation()
                        ->modalHeading($underAttack ? __('Disable Under Attack Mode?') : __('Enable Under Attack Mode?'))
                        ->modalDescription($underAttack
                            ? __('This will restore your previous defense settings.')
                            : __('This will activate aggressive defenses: process killer (threshold 50), auto-block IPs, brute-force threshold lowered to 3 attempts.'))
                        ->action($underAttack ? 'disableAttackMode' : 'enableAttackMode'),
                ])
                ->compact(),
            Section::make(__('Protection Modules'))->schema([Grid::make(3)->schema($coreToggles)])->compact(),
            Section::make(__('Advanced Protection'))->schema([Grid::make(3)->schema($advToggles)])->compact(),
        ];
    }

    // ── Firewall Tab ─────────────────────────────────────────────────

    protected function firewallTab(): array
    {
        $fw = $this->client()->get('/firewall/ufw/status') ?? ['available' => false];
        $active = $fw['active'] ?? false;

        return [
            Section::make(new \Illuminate\Support\HtmlString(
                __('UFW Firewall') . ': <span style="color:' . ($active ? '#22c55e' : '#ef4444') . '">' . ($active ? __('Enabled') : __('Disabled')) . '</span>'
            ))
                ->compact()
                ->headerActions([
                    Action::make('fw_toggle')
                        ->label($active ? __('Disable Firewall') : __('Enable Firewall'))
                        ->color($active ? 'danger' : 'success')
                        ->size('xs')
                        ->requiresConfirmation()
                        ->action($active ? 'disableFirewall' : 'enableFirewall'),
                ])
                ->schema([]),
            EmbeddedTable::make(FirewallRulesTable::class),
        ];
    }

    // ── Config Tab ───────────────────────────────────────────────────

    protected function configTab(): array
    {
        $expert = $this->expertMode;
        $tabs = [];
        $categoriesToShow = $expert ? static::$configCategories : static::$basicCategories;

        $tabDescriptions = [
            'Daemon' => 'Core daemon settings: log verbosity, data directories, quarantine location, and number of parallel scan workers. These affect how the daemon operates at the system level.',
            'Scoring & Response' => 'Threat scoring thresholds that determine what happens when malware is detected. Files scoring above the log threshold are recorded as incidents. Above quarantine threshold, files are automatically isolated. Above suspend threshold, the hosting account can be suspended.',
            'Brute-Force' => 'SSH and mail service brute-force protection. Monitors authentication logs for repeated failed login attempts and automatically blocks attacking IPs with progressive ban durations (10 min → 1 hour → 24 hours → permanent).',
            'WAF' => 'ModSecurity Web Application Firewall with OWASP Core Rule Set. Inspects HTTP requests for SQL injection, XSS, path traversal, and other web attacks. CRS rules auto-update periodically.',
            'Process Killer' => 'Monitors running processes for suspicious activity like reverse shells, crypto miners, and unauthorized scripts. Processes exceeding the threat score threshold are terminated. Only affects non-system processes (UID >= 1000).',
            'Cleanup' => 'Automated malware cleanup engine. Removes injected PHP code from compromised files, restores CMS core files from official checksums, and creates backups before any modifications.',
            'Scheduled Scan' => 'Periodic full-directory scanning that runs automatically on a schedule. Catches dormant malware that may have been missed by real-time file watching. Scans all configured paths at the specified interval.',
            'Threat Intel' => 'Threat intelligence feeds from public sources: Spamhaus DROP/EDROP (known spam networks), blocklist.de (brute-force attackers), and MalwareBazaar (malware hashes). Feeds update every 6 hours automatically.',
            'WebShield' => 'Nginx-level protection layer: rate limiting prevents request flooding, bot filtering blocks known malicious user agents, and JavaScript challenge pages verify that visitors are real browsers, not automated scanners.',
            'Retention' => 'Data retention policy for incident records. Old incidents are automatically cleaned up after the specified number of days to prevent database growth.',
            'File Watcher' => 'Directories monitored for file changes in real-time using inotify. New or modified files matching the scan extensions are automatically scanned for malware.',
            'Pre-Filter' => 'File filtering rules that determine which files are scanned. Only files matching the configured extensions are analyzed. Large files and common non-code directories are skipped for performance.',
            'Detection' => 'Tuning parameters for the detection engines. Entropy threshold controls sensitivity of the Shannon entropy scanner (lower = more sensitive). YARA rules directory contains custom signature files.',
            'ClamAV' => 'ClamAV antivirus integration. When set to "auto", the daemon detects if clamd is running and uses it. ClamAV provides signature-based detection complementing the built-in heuristic and YARA engines.',
            'UFW' => 'UFW (Uncomplicated Firewall) management via the REST API. When enabled, firewall rules can be viewed and managed from the Security panel.',
            'SSH Jail' => 'SSH chroot jail management for hosting users. Users get SFTP-only access by default. Shell access provides a jailed environment with wp-cli and basic commands.',
            'CrowdSec' => 'Community threat intelligence powered by 200,000+ installations worldwide. CrowdSec detects attacks in real-time from server logs and shares signals with the community. Known attackers are blocked faster via reduced brute-force thresholds.',
            'Performance' => 'Performance tuning for database scanning and rapid directory scans. Controls parallel workers and file modification time caching for faster re-scans.',
        ];

        foreach ($categoriesToShow as $category => $keys) {
            $fields = [];
            $desc = $tabDescriptions[$category] ?? '';
            if ($desc) {
                $fields[] = Text::make(__($desc))->size(TextSize::Small)->color('gray');
            }
            foreach ($keys as $key) {
                if (! $expert && in_array($key, static::$expertKeys)) {
                    continue;
                }
                $help = static::$configHelp[$key] ?? '';
                $fieldName = 'configData.config_'.$key;
                if (in_array($key, static::$booleanKeys)) {
                    $fields[] = Toggle::make($fieldName)
                        ->label($key)
                        ->helperText($help);
                } elseif (isset(static::$selectKeys[$key])) {
                    $opts = array_combine(static::$selectKeys[$key], static::$selectKeys[$key]);
                    $fields[] = Select::make($fieldName)
                        ->label($key)
                        ->options($opts)
                        ->helperText($help);
                } else {
                    $fields[] = TextInput::make($fieldName)
                        ->label($key)
                        ->helperText($help);
                }
            }

            if (! empty($fields)) {
                $tabs[$category] = Tab::make(__($category))->schema($fields);
            }
        }

        return [
            Section::make(__('Configuration'))
                ->headerActions([
                    Action::make('toggleExpertMode')
                        ->label($expert ? __('Basic Mode') : __('Expert Mode'))
                        ->icon($expert ? 'heroicon-o-eye-slash' : 'heroicon-o-eye')
                        ->color($expert ? 'warning' : 'gray')
                        ->size('xs')
                        ->action('toggleExpertMode'),
                    Action::make('saveAndRestart')
                        ->label(__('Save & Restart'))
                        ->icon('heroicon-o-check')
                        ->color('success')
                        ->size('xs')
                        ->action('saveAndRestart'),
                ])
                ->schema([
                    Tabs::make(__('config_tabs'))
                        ->contained(false)
                        ->tabs($tabs),
                ]),
        ];
    }


    public function toggleExpertMode(): void
    {
        $this->expertMode = ! $this->expertMode;
    }

    // ── Module Toggles ───────────────────────────────────────────────


    public function saveAndRestart(): void
    {
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

        if (! empty($payload)) {
            $result = $this->client()->patch('/config', $payload);
            if (! $result) {
                Notification::make()->title(__('Failed to save config'))->danger()->send();

                return;
            }
        }

        Notification::make()
            ->title(__('Settings saved'))
            ->body(count($payload).' '.__('settings applied'))
            ->success()
            ->send();
    }

    // ── Attack Mode Actions ────────────────────────────────────────────

    public function enableAttackMode(): void
    {
        $result = $this->client()->post('/attack-mode/enable');
        $actions = $result['actions_taken'] ?? [];
        $body = count($actions) > 0
            ? implode("\n", array_map(fn ($a) => "• {$a}", $actions))
            : __('Aggressive defenses activated');
        $body .= "\n\n" . implode("\n", [
            __('• Process killer threshold lowered to 50'),
            __('• Auto-block IPs on suspicious activity'),
            __('• Brute-force threshold: 3 attempts in 120 seconds'),
            __('• Block durations: 1h → 24h → permanent'),
            __('• WAF blocking enabled per-site'),
            __('• WebShield rate limiting: 10 req/s, burst 5'),
        ]);
        Notification::make()
            ->title($result ? __('Under Attack mode ENABLED') : __('Failed to enable attack mode'))
            ->body($body)
            ->{$result ? 'danger' : 'warning'}()
            ->duration(15000)
            ->send();
        $this->redirect(static::getUrl(['tab' => 'overview']));
    }

    public function disableAttackMode(): void
    {
        $result = $this->client()->post('/attack-mode/disable');
        $actions = implode(', ', $result['actions_taken'] ?? []);
        Notification::make()
            ->title($result ? __('Under Attack mode disabled') : __('Failed to disable attack mode'))
            ->body($actions ?: __('Normal settings restored'))
            ->{$result ? 'success' : 'danger'}()
            ->duration(10000)
            ->send();
        $this->redirect(static::getUrl(['tab' => 'overview']));
    }

    // ── Firewall Actions ─────────────────────────────────────────────

    public function enableFirewall(): void
    {
        $result = $this->client()->post('/firewall/ufw/enable');
        Notification::make()
            ->title($result ? __('Firewall enabled') : __('Failed to enable firewall'))
            ->{($result ? "success" : "danger")}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'firewall']));
    }

    public function disableFirewall(): void
    {
        $result = $this->client()->post('/firewall/ufw/disable');
        Notification::make()
            ->title($result ? __('Firewall disabled') : __('Failed to disable firewall'))
            ->{($result ? "success" : "danger")}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'firewall']));
    }

    // ── SSH Settings Actions ────────────────────────────────────────

    public function toggleSshJail(): void
    {
        $enabled = $this->moduleStates['SSHJAIL_ENABLED'] ?? false;
        $newValue = $enabled ? 'no' : 'yes';
        $this->client()->patch('/config', ['SSHJAIL_ENABLED' => $newValue]);
        // Daemon restart needed to load/unload SSHJailManager
        $this->client()->post('/daemon/restart');
        // Wait for daemon to restart before redirecting
        sleep(3);
        Notification::make()
            ->title($enabled ? __('SSH Jail disabled') : __('SSH Jail enabled'))
            ->body(__('Daemon restarted'))
            ->{$enabled ? 'warning' : 'success'}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'ssh']));
    }

    public function toggleShellDefault(): void
    {
        $config = $this->client()->get('/config') ?? [];
        $current = in_array($config['SSH_SHELL_ACCESS_ENABLED'] ?? 'no', ['yes', 'true', '1']);
        $newValue = $current ? 'no' : 'yes';
        $this->client()->patch('/config', ['SSH_SHELL_ACCESS_ENABLED' => $newValue]);
        Notification::make()
            ->title($current ? __('SSH shell disabled by default for new users') : __('SSH shell enabled by default for new users'))
            ->{$current ? 'warning' : 'success'}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'ssh']));
    }

    public function enableSshPasswordAuth(): void
    {
        $result = $this->client()->post('/ssh/sshd-settings', ['password_auth' => true]);
        Notification::make()
            ->title($result !== null ? __('Password auth enabled') : __('Failed to update setting'))
            ->{($result !== null ? "success" : "danger")}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'ssh']));
    }

    public function disableSshPasswordAuth(): void
    {
        $result = $this->client()->post('/ssh/sshd-settings', ['password_auth' => false]);
        Notification::make()
            ->title($result !== null ? __('Password auth disabled') : __('Failed to update setting'))
            ->{($result !== null ? "success" : "danger")}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'ssh']));
    }



    public function changeSshPortAction(array $data): void
    {
        $result = $this->client()->post('/ssh/sshd-settings', ['port' => (int) $data['port']]);
        Notification::make()
            ->title($result !== null
                ? __('SSH port changed to :port', ['port' => $data['port']])
                : __('Failed to change SSH port'))
            ->{($result !== null ? "success" : "danger")}()
            ->send();
        $this->redirect(static::getUrl(['tab' => 'defense', 'defense' => 'ssh']));
    }

    public static array $configHelp = [
        'LOG_LEVEL' => 'Logging verbosity: debug shows everything, error shows only errors',
        'LOG_DIR' => 'Directory for daemon log files',
        'DATA_DIR' => 'Directory for SQLite database and cached data',
        'QUARANTINE_DIR' => 'Where quarantined malicious files are moved to',
        'WORKERS' => 'Number of parallel scan workers (1-32)',
        'WATCH_DIRS' => 'Comma-separated directory globs to monitor for file changes',
        'SCAN_EXTENSIONS' => 'File extensions to scan (comma-separated)',
        'MAX_FILE_SIZE' => 'Maximum file size to scan in bytes (default 2MB)',
        'SKIP_DIRS' => 'Directory names to skip during scanning',
        'ENTROPY_THRESHOLD' => 'Entropy score threshold (0.0-8.0, default 4.5)',
        'YARA_RULES_DIR' => 'Directory containing .yar rule files',
        'CLAMAV_ENABLED' => 'ClamAV scanning: auto (detect), yes (require), no (disable)',
        'CLAMAV_SOCKET' => 'Path to clamd Unix socket',
        'FRESHCLAM_ON_UPDATE' => 'Run freshclam when reloading rules',
        'SCORE_LOG' => 'Minimum score to log an incident',
        'SCORE_QUARANTINE' => 'Minimum score to auto-quarantine a file',
        'SCORE_SUSPEND' => 'Minimum score to auto-suspend a hosting account',
        'PROCESS_POLL_INTERVAL' => 'Seconds between process scans',
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
        'WAF_NGINX_INCLUDE' => 'Nginx include file for per-site modsecurity on/off toggle',
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
        'NGINX_ACCESS_LOG' => 'Nginx access log path for counting blocked requests',
        'RAPIDSCAN_WORKERS' => 'Parallel workers for rapid directory scans',
        'RAPIDSCAN_MTIME_CACHE' => 'Cache file modification times to skip unchanged files',
        'SSHJAIL_ENABLED' => 'Enable SSH jail management (chroot jailshell with wp-cli)',
        'SSHJAIL_JAIL_DIR' => 'Root directory for the SSH chroot jail',
        'SSH_SHELL_ACCESS_ENABLED' => 'Allow users to enable terminal shell access',
        'CROWDSEC_ENABLED' => 'CrowdSec community threat intelligence: auto (detect), yes, no',
        'CROWDSEC_LAPI_URL' => 'CrowdSec Local API URL (default: http://127.0.0.1:8080)',
        'CROWDSEC_BOUNCER_KEY' => 'Bouncer API key (generated by installer)',
        'CROWDSEC_SYNC_INTERVAL' => 'Decision polling interval in seconds',
    ];

    // ── Static Data ──────────────────────────────────────────────────

    public static function getModuleToggles(): array
    {
        return [
            'core' => [
                'AUTO_QUARANTINE' => ['label' => 'Auto Quarantine', 'desc' => 'Quarantine files above score threshold'],
            ],
            'advanced' => [
                'WAF_ENABLED' => ['label' => 'WAF (ModSecurity)', 'desc' => 'Web application firewall with OWASP CRS'],
                'BRUTEFORCE_ENABLED' => ['label' => 'Brute-Force Protection', 'desc' => 'Blocks IPs after failed logins'],
                'PROCESS_KILL_ENABLED' => ['label' => 'Process Killer', 'desc' => 'Kills reverse shells and miners'],
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
        'AUTO_QUARANTINE', 'AUTO_SUSPEND', 'AUTO_BLOCK_IP',
        'WAF_ENABLED', 'WAF_CRS_AUTO_UPDATE', 'BRUTEFORCE_ENABLED',
        'PROCESS_KILL_ENABLED',
        'CLEANUP_ENABLED', 'CLEANUP_AUTO', 'CLEANUP_CMS_CHECKSUMS',
        'SCHEDULED_SCAN_ENABLED', 'THREAT_INTEL_ENABLED', 'THREAT_INTEL_AUTO_BLOCK',
        'WEBSHIELD_ENABLED', 'WEBSHIELD_CHALLENGE_ENABLED', 'WEBSHIELD_BOT_FILTERING',
        'RAPIDSCAN_MTIME_CACHE', 'FRESHCLAM_ON_UPDATE',
        'UFW_ENABLED', 'SSHJAIL_ENABLED', 'SSH_SHELL_ACCESS_ENABLED',
    ];

    public static array $selectKeys = [
        'LOG_LEVEL' => ['debug', 'info', 'warning', 'error', 'critical'],
        'CLAMAV_ENABLED' => ['auto', 'yes', 'no'],
        'CROWDSEC_ENABLED' => ['auto', 'yes', 'no'],
        'FIREWALL_BACKEND' => ['auto', 'nftables', 'iptables', 'none'],
        'WAF_AUDIT_LOG_TYPE' => ['serial', 'concurrent'],
        'WAF_WEB_SERVER' => ['auto', 'nginx', 'apache'],
    ];

    /** Basic mode: only these categories shown, expert keys hidden within them. */
    public static array $basicCategories = [
        'Daemon' => ['LOG_LEVEL', 'LOG_DIR', 'DATA_DIR', 'QUARANTINE_DIR', 'WORKERS'],
        'Scoring & Response' => ['SCORE_LOG', 'SCORE_QUARANTINE', 'SCORE_SUSPEND', 'AUTO_QUARANTINE', 'AUTO_SUSPEND', 'AUTO_BLOCK_IP'],
        'Brute-Force' => ['BRUTEFORCE_ENABLED', 'BRUTEFORCE_SSH_THRESHOLD', 'BRUTEFORCE_SSH_WINDOW', 'BRUTEFORCE_MAIL_THRESHOLD', 'BRUTEFORCE_MAIL_WINDOW', 'BRUTEFORCE_BLOCK_DURATIONS', 'BRUTEFORCE_WHITELIST_IPS'],
        'WAF' => ['WAF_ENABLED', 'WAF_CRS_AUTO_UPDATE'],
        'Process Killer' => ['PROCESS_KILL_ENABLED', 'PROCESS_KILL_THRESHOLD'],
        'Cleanup' => ['CLEANUP_ENABLED', 'CLEANUP_AUTO'],
        'Scheduled Scan' => ['SCHEDULED_SCAN_ENABLED', 'SCHEDULED_SCAN_INTERVAL', 'SCHEDULED_SCAN_PATHS'],
        'Threat Intel' => ['THREAT_INTEL_ENABLED', 'THREAT_INTEL_AUTO_BLOCK'],
        'WebShield' => ['WEBSHIELD_ENABLED', 'WEBSHIELD_RATE_LIMIT', 'WEBSHIELD_RATE_BURST'],
    ];

    /** Expert mode: all categories with every key. */
    public static array $configCategories = [
        'Daemon' => ['LOG_LEVEL', 'LOG_DIR', 'DATA_DIR', 'QUARANTINE_DIR', 'WORKERS'],
        'File Watcher' => ['WATCH_DIRS'],
        'Pre-Filter' => ['SCAN_EXTENSIONS', 'MAX_FILE_SIZE', 'SKIP_DIRS'],
        'Detection' => ['ENTROPY_THRESHOLD', 'YARA_RULES_DIR', 'PROCESS_POLL_INTERVAL', 'BEHAVIOR_TTL'],
        'ClamAV' => ['CLAMAV_ENABLED', 'CLAMAV_SOCKET', 'FRESHCLAM_ON_UPDATE'],
        'Scoring & Response' => ['SCORE_LOG', 'SCORE_QUARANTINE', 'SCORE_SUSPEND', 'AUTO_QUARANTINE', 'AUTO_SUSPEND', 'AUTO_BLOCK_IP'],
        'WAF' => ['WAF_ENABLED', 'WAF_AUDIT_LOG', 'WAF_AUDIT_LOG_TYPE', 'WAF_RULES_DIR', 'WAF_OVERRIDES_FILE', 'WAF_CRS_AUTO_UPDATE', 'WAF_WEB_SERVER', 'WAF_NGINX_INCLUDE'],
        'Brute-Force' => ['BRUTEFORCE_ENABLED', 'BRUTEFORCE_SSH_LOG', 'BRUTEFORCE_MAIL_LOG', 'BRUTEFORCE_STALWART_LOG', 'BRUTEFORCE_SSH_THRESHOLD', 'BRUTEFORCE_SSH_WINDOW', 'BRUTEFORCE_MAIL_THRESHOLD', 'BRUTEFORCE_MAIL_WINDOW', 'BRUTEFORCE_BLOCK_DURATIONS', 'FIREWALL_BACKEND', 'BRUTEFORCE_WHITELIST_IPS'],
        'UFW' => ['UFW_ENABLED'],
        'SSH Jail' => ['SSHJAIL_ENABLED', 'SSHJAIL_JAIL_DIR', 'SSH_SHELL_ACCESS_ENABLED'],
        'Process Killer' => ['PROCESS_KILL_ENABLED', 'PROCESS_KILL_THRESHOLD', 'PROCESS_KILL_MIN_UID', 'PROCESS_KILL_WHITELIST'],
        'Cleanup' => ['CLEANUP_ENABLED', 'CLEANUP_AUTO', 'CLEANUP_BACKUP_DIR', 'CLEANUP_CMS_CHECKSUMS'],
        'Scheduled Scan' => ['SCHEDULED_SCAN_ENABLED', 'SCHEDULED_SCAN_INTERVAL', 'SCHEDULED_SCAN_PATHS'],
        'Threat Intel' => ['THREAT_INTEL_ENABLED', 'THREAT_INTEL_UPDATE_INTERVAL', 'THREAT_INTEL_FEEDS', 'THREAT_INTEL_AUTO_BLOCK', 'THREAT_INTEL_AUTO_BLOCK_THRESHOLD'],
        'WebShield' => ['WEBSHIELD_ENABLED', 'WEBSHIELD_RATE_LIMIT', 'WEBSHIELD_RATE_BURST', 'WEBSHIELD_CHALLENGE_ENABLED', 'WEBSHIELD_BOT_FILTERING', 'WEBSHIELD_NGINX_CONF_DIR', 'NGINX_ACCESS_LOG'],
        'CrowdSec' => ['CROWDSEC_ENABLED', 'CROWDSEC_LAPI_URL', 'CROWDSEC_BOUNCER_KEY', 'CROWDSEC_SYNC_INTERVAL'],
        'Performance' => ['RAPIDSCAN_WORKERS', 'RAPIDSCAN_MTIME_CACHE'],
    ];

    /** Keys hidden in basic mode (file paths, internal tuning, advanced options). */
    public static array $expertKeys = [
        'LOG_DIR', 'DATA_DIR', 'QUARANTINE_DIR',
        'WATCH_DIRS', 'SCAN_EXTENSIONS', 'MAX_FILE_SIZE', 'SKIP_DIRS',
        'ENTROPY_THRESHOLD', 'YARA_RULES_DIR', 'PROCESS_POLL_INTERVAL', 'BEHAVIOR_TTL',
        'CLAMAV_SOCKET', 'FRESHCLAM_ON_UPDATE',
        'WAF_AUDIT_LOG', 'WAF_AUDIT_LOG_TYPE', 'WAF_RULES_DIR', 'WAF_OVERRIDES_FILE', 'WAF_WEB_SERVER', 'WAF_NGINX_INCLUDE',
        'BRUTEFORCE_SSH_LOG', 'BRUTEFORCE_MAIL_LOG', 'BRUTEFORCE_STALWART_LOG', 'FIREWALL_BACKEND',
        'SSHJAIL_JAIL_DIR',
        'PROCESS_KILL_MIN_UID', 'PROCESS_KILL_WHITELIST',
        'CLEANUP_BACKUP_DIR', 'CLEANUP_CMS_CHECKSUMS',
        'THREAT_INTEL_UPDATE_INTERVAL', 'THREAT_INTEL_FEEDS', 'THREAT_INTEL_AUTO_BLOCK_THRESHOLD',
        'WEBSHIELD_CHALLENGE_ENABLED', 'WEBSHIELD_BOT_FILTERING', 'WEBSHIELD_NGINX_CONF_DIR', 'NGINX_ACCESS_LOG',
        'CROWDSEC_LAPI_URL', 'CROWDSEC_BOUNCER_KEY', 'CROWDSEC_SYNC_INTERVAL',
        'RAPIDSCAN_WORKERS', 'RAPIDSCAN_MTIME_CACHE',
    ];
}
