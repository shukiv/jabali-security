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
use App\JabaliSecurity\Widgets\SshKeysTable;
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
    }

    public function updatedModuleStates($value, string $key): void
    {
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
        return [
            Action::make('scan')
                ->label(__('Run Scan'))
                ->icon('heroicon-o-magnifying-glass')
                ->color('danger')
                ->form([
                    TextInput::make('path')
                        ->label(__('Path'))
                        ->placeholder('/home/user/public_html')
                        ->required()
                        ->rules(['regex:/^\/home\/|^\/var\/www\//'])
                        ->validationMessages(['regex' => __('Path must be under /home/ or /var/www/')]),
                ])
                ->action(function (array $data): void {
                    $result = $this->client()->post('/scan', ['path' => $data['path']]);
                    if ($result) {
                        $score = $result['score'] ?? $result['threats_found'] ?? 0;
                        $filesScanned = $result['files_scanned'] ?? null;
                        $body = $filesScanned
                            ? __('Scanned :files files, :threats threats found', ['files' => $filesScanned, 'threats' => $score])
                            : __('Score: :score', ['score' => $score]);
                        Notification::make()
                            ->title(__('Scan Complete'))
                            ->body($body)
                            ->color($score > 0 ? 'warning' : 'success')
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
                                            [EmbeddedTable::make(BruteforceBlockedTable::class)],
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
                                        ->schema([
                                            Text::make(__('SSH/SFTP access management with chroot jailshell. Users get SFTP-only access by default. Shell access provides a jailed environment with wp-cli and basic commands.'))
                                                ->size(TextSize::Small)
                                                ->color('gray'),
                                            EmbeddedTable::make(SshKeysTable::class),
                                        ]),
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
            Grid::make(6)->dense()->schema([
                $this->statCard('Incidents', (string) ($s['incidents_24h'] ?? 0), 'Last 24 hours',
                    ($s['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success'),
                $this->statCard('Attacks Blocked', (string) ($s['attacks_blocked_24h'] ?? 0), 'Last 24 hours',
                    ($s['attacks_blocked_24h'] ?? 0) > 0 ? 'warning' : 'success'),
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
            Grid::make(2)->dense()->schema([
                $this->statCard('Process Killer', ($s['process_kill_enabled'] ?? false) ? __('Active') : __('Disabled'), '',
                    ($s['process_kill_enabled'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Processes Killed', (string) ($s['process_kill_count'] ?? 0), '',
                    ($s['process_kill_count'] ?? 0) > 0 ? 'warning' : 'success'),
            ]),
        ];
    }

    protected function webshieldStats(): array
    {
        $s = $this->client()->get('/webshield/status') ?? [];
        return [
            Grid::make(6)->dense()->schema([
                $this->statCard('Enabled', ($s['installed'] ?? false) ? __('Yes') : __('No'), '',
                    ($s['installed'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Rate Limiting', ($s['rate_limiting'] ?? false) ? __('On') : __('Off'), '',
                    ($s['rate_limiting'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Bot Filtering', ($s['bot_filtering'] ?? false) ? __('On') : __('Off'), '',
                    ($s['bot_filtering'] ?? false) ? 'success' : 'gray'),
                $this->statCard('Blocked IPs', (string) ($s['blocked_ips_count'] ?? 0), '',
                    ($s['blocked_ips_count'] ?? 0) > 0 ? 'danger' : 'success'),
                $this->statCard('Bots Blocked', (string) ($s['bot_blocked_24h'] ?? 0), 'Last 24 hours',
                    ($s['bot_blocked_24h'] ?? 0) > 0 ? 'warning' : 'success'),
                $this->statCard('Rate Limited', (string) ($s['rate_limited_24h'] ?? 0), 'Last 24 hours',
                    ($s['rate_limited_24h'] ?? 0) > 0 ? 'warning' : 'success'),
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
                    ? __('Aggressive defenses are active: process killer, auto-block IPs, low brute-force thresholds.')
                    : __('Enable if your server is under active attack. Activates process killer, auto-blocks IPs, lowers brute-force thresholds.'))
                ->icon($underAttack ? 'heroicon-o-fire' : 'heroicon-o-shield-exclamation')
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
            Section::make(__('UFW Status'))
                ->schema([
                    SchemaActions::make([
                        Action::make('fw_toggle')
                            ->label($active ? __('Disable Firewall') : __('Enable Firewall'))
                            ->color($active ? 'danger' : 'success')
                            ->size('sm')
                            ->requiresConfirmation()
                            ->action($active ? 'disableFirewall' : 'enableFirewall'),
                    ]),
                ]),
            EmbeddedTable::make(FirewallRulesTable::class),
        ];
    }

    // ── Config Tab ───────────────────────────────────────────────────

    protected function configTab(): array
    {
        $expert = $this->expertMode;
        $tabs = [];
        $categoriesToShow = $expert ? static::$configCategories : static::$basicCategories;

        foreach ($categoriesToShow as $category => $keys) {
            $fields = [];
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
        $actions = implode(', ', $result['actions_taken'] ?? []);
        Notification::make()
            ->title($result ? __('Under Attack mode ENABLED') : __('Failed to enable attack mode'))
            ->body($actions ?: __('Aggressive defenses activated'))
            ->{$result ? 'danger' : 'warning'}()
            ->duration(10000)
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
        'DB_SCANNER_ENABLED' => 'Enable database injection scanning',
        'RAPIDSCAN_WORKERS' => 'Parallel workers for rapid directory scans',
        'RAPIDSCAN_MTIME_CACHE' => 'Cache file modification times to skip unchanged files',
        'NOTIFY_EMAIL' => 'Email address for high-severity notifications',
        'NOTIFY_WEBHOOK' => 'Webhook URL for incident notifications',
        'NOTIFY_MIN_SEVERITY' => 'Minimum severity to trigger notifications',
        'INCIDENT_RETAIN_DAYS' => 'Days to keep incident records before cleanup',
        'SSHJAIL_ENABLED' => 'Enable SSH jail management (chroot jailshell with wp-cli)',
        'SSHJAIL_JAIL_DIR' => 'Root directory for the SSH chroot jail',
        'SSH_SHELL_ACCESS_ENABLED' => 'Allow users to enable terminal shell access',
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
                'SSHJAIL_ENABLED' => ['label' => 'SSH Jail', 'desc' => 'Chroot jailshell with wp-cli for hosting users'],
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
        'DB_SCANNER_ENABLED', 'RAPIDSCAN_MTIME_CACHE', 'FRESHCLAM_ON_UPDATE',
        'UFW_ENABLED', 'SSHJAIL_ENABLED', 'SSH_SHELL_ACCESS_ENABLED',
    ];

    public static array $selectKeys = [
        'LOG_LEVEL' => ['debug', 'info', 'warning', 'error', 'critical'],
        'CLAMAV_ENABLED' => ['auto', 'yes', 'no'],
        'FIREWALL_BACKEND' => ['auto', 'nftables', 'iptables', 'none'],
        'WAF_AUDIT_LOG_TYPE' => ['serial', 'concurrent'],
        'WAF_WEB_SERVER' => ['auto', 'nginx', 'apache'],
        'NOTIFY_MIN_SEVERITY' => ['low', 'medium', 'high', 'critical'],
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
        'Retention' => ['INCIDENT_RETAIN_DAYS'],
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
        'Performance' => ['DB_SCANNER_ENABLED', 'RAPIDSCAN_WORKERS', 'RAPIDSCAN_MTIME_CACHE'],
        'Retention' => ['INCIDENT_RETAIN_DAYS'],
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
        'DB_SCANNER_ENABLED', 'RAPIDSCAN_WORKERS', 'RAPIDSCAN_MTIME_CACHE',
    ];
}
