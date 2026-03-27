<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Pages;

use App\JabaliSecurity\JabaliSecurityClient;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Illuminate\Contracts\Support\Htmlable;
use Livewire\Attributes\Url;

class Security extends Page implements HasActions, HasForms, HasTable
{
    use InteractsWithActions;
    use InteractsWithForms;
    use InteractsWithTable;

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

    public function mount(): void
    {
        $this->activeTab = $this->normalizeTab($this->activeTab);
    }

    public function updatedActiveTab(): void
    {
        $this->activeTab = $this->normalizeTab($this->activeTab);
        $this->resetTable();
    }

    protected function normalizeTab(?string $tab): string
    {
        $tab = $tab ?? 'overview';
        if (str_contains($tab, '::')) {
            $tab = explode('::', $tab)[0];
        }

        $valid = ['overview', 'incidents', 'quarantine', 'blocklist', 'firewall', 'waf', 'bruteforce', 'proactive', 'webshield', 'threatintel', 'users', 'cleanup', 'rules', 'config'];

        return in_array($tab, $valid) ? $tab : 'overview';
    }

    // ── API Client ───────────────────────────────────────────────────

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
                ->form([
                    TextInput::make('path')
                        ->label(__('Path'))
                        ->placeholder('/home/user/public_html')
                        ->required(),
                ])
                ->action(function (array $data): void {
                    $result = $this->client()->post('/scan', ['path' => $data['path']]);
                    if ($result) {
                        $score = $result['score'] ?? 0;
                        $threats = $result['threats_found'] ?? 0;
                        Notification::make()
                            ->title(__('Scan Complete'))
                            ->body(sprintf('Score: %s | Threats: %s', $score, $threats))
                            ->color($score > 0 ? 'warning' : 'success')
                            ->send();
                    } else {
                        Notification::make()->title(__('Scan failed'))->danger()->send();
                    }
                }),

            Action::make('updateRules')
                ->label(__('Update Rules'))
                ->icon('heroicon-o-arrow-path')
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

    // ── Overview Data ────────────────────────────────────────────────

    public function getStatusData(): array
    {
        return $this->client()->get('/status') ?? [];
    }

    // ── Table (dynamic per tab) ──────────────────────────────────────

    public function table(Table $table): Table
    {
        return match ($this->activeTab) {
            'incidents' => $this->incidentsTable($table),
            'quarantine' => $this->quarantineTable($table),
            'blocklist' => $this->blocklistTable($table),
            'firewall' => $this->firewallTable($table),
            'waf' => $this->wafTable($table),
            'bruteforce' => $this->bruteforceTable($table),
            'proactive' => $this->proactiveTable($table),
            'webshield' => $this->webshieldTable($table),
            'threatintel' => $this->threatIntelTable($table),
            'users' => $this->usersTable($table),
            'cleanup' => $this->cleanupTable($table),
            'rules' => $this->rulesTable($table),
            'config' => $this->configTable($table),
            default => $table->columns([])->records(fn () => []),
        };
    }

    // ── Incidents Tab ────────────────────────────────────────────────

    protected function incidentsTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/incidents', ['limit' => 100]) ?? [])
            ->columns([
                TextColumn::make('path')
                    ->label(__('File'))
                    ->limit(50)
                    ->searchable(isIndividual: false),
                TextColumn::make('username')
                    ->label(__('User'))
                    ->searchable(isIndividual: false),
                TextColumn::make('severity')
                    ->label(__('Severity'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'critical' => 'danger',
                        'high' => 'danger',
                        'medium' => 'warning',
                        default => 'info',
                    }),
                TextColumn::make('total_score')
                    ->label(__('Score'))
                    ->alignCenter(),
                TextColumn::make('action_taken')
                    ->label(__('Action'))
                    ->badge()
                    ->color('gray'),
                IconColumn::make('resolved')
                    ->label(__('Resolved'))
                    ->boolean(),
                TextColumn::make('timestamp')
                    ->label(__('Time'))
                    ->since(),
            ])
            ->recordActions([
                Action::make('resolve')
                    ->label(__('Resolve'))
                    ->icon('heroicon-o-check')
                    ->color('success')
                    ->visible(fn (array $record): bool => ! ($record['resolved'] ?? false))
                    ->form([
                        Textarea::make('notes')
                            ->label(__('Notes'))
                            ->placeholder(__('False positive, whitelisted, etc.')),
                    ])
                    ->action(function (array $data, array $record): void {
                        $this->client()->post('/incidents/'.$record['id'].'/resolve', [
                            'notes' => $data['notes'] ?? '',
                        ]);
                        Notification::make()->title(__('Incident resolved'))->success()->send();
                    }),
            ])
            ->emptyStateHeading(__('No incidents'))
            ->emptyStateIcon('heroicon-o-shield-check')
            ->striped()
            ->defaultPaginationPageOption(25);
    }

    // ── Quarantine Tab ───────────────────────────────────────────────

    protected function quarantineTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/quarantine') ?? [])
            ->columns([
                TextColumn::make('original_path')
                    ->label(__('Original Path'))
                    ->limit(50),
                TextColumn::make('username')
                    ->label(__('User')),
                TextColumn::make('reason')
                    ->label(__('Reason'))
                    ->limit(40),
                TextColumn::make('timestamp')
                    ->label(__('Time'))
                    ->since(),
            ])
            ->recordActions([
                Action::make('restore')
                    ->label(__('Restore'))
                    ->icon('heroicon-o-arrow-uturn-left')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/quarantine/'.$record['id'].'/restore');
                        Notification::make()
                            ->title($result ? __('File restored') : __('Restore failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('delete')
                    ->label(__('Delete'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $this->client()->delete('/quarantine/'.$record['id']);
                        Notification::make()->title(__('File deleted'))->success()->send();
                    }),
            ])
            ->emptyStateHeading(__('No quarantined files'))
            ->emptyStateIcon('heroicon-o-lock-closed')
            ->striped();
    }

    // ── Blocklist Tab ────────────────────────────────────────────────

    protected function blocklistTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/blocklist') ?? [])
            ->headerActions([
                Action::make('blockIp')
                    ->label(__('Block IP'))
                    ->icon('heroicon-o-no-symbol')
                    ->form([
                        TextInput::make('ip')
                            ->label(__('IP Address'))
                            ->required()
                            ->ipv4(),
                        TextInput::make('reason')
                            ->label(__('Reason'))
                            ->default('manual'),
                        TextInput::make('duration')
                            ->label(__('Duration (seconds)'))
                            ->numeric()
                            ->placeholder('0 = permanent'),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/block', [
                            'ip' => $data['ip'],
                            'reason' => $data['reason'] ?? 'manual',
                            'duration' => (int) ($data['duration'] ?? 0),
                        ]);
                        Notification::make()
                            ->title($result ? __('IP blocked') : __('Block failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->columns([
                TextColumn::make('ip')
                    ->label(__('IP Address'))
                    ->copyable()
                    ->searchable(isIndividual: false),
                TextColumn::make('reason')
                    ->label(__('Reason')),
                TextColumn::make('blocked_at')
                    ->label(__('Blocked At'))
                    ->since(),
                TextColumn::make('expires_at')
                    ->label(__('Expires'))
                    ->placeholder(__('permanent')),
                TextColumn::make('blocked_by')
                    ->label(__('Source'))
                    ->badge()
                    ->color('gray'),
            ])
            ->recordActions([
                Action::make('unblock')
                    ->label(__('Unblock'))
                    ->icon('heroicon-o-lock-open')
                    ->color('success')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $this->client()->delete('/block/'.$record['ip']);
                        Notification::make()->title(__('IP unblocked'))->success()->send();
                    }),
            ])
            ->emptyStateHeading(__('No blocked IPs'))
            ->emptyStateIcon('heroicon-o-no-symbol')
            ->striped();
    }

    // ── Firewall Tab ─────────────────────────────────────────────────

    protected function firewallTable(Table $table): Table
    {
        return $table
            ->records(fn () => ($this->client()->get('/firewall/ufw/status'))['rules'] ?? [])
            ->headerActions([
                Action::make('addRule')
                    ->label(__('Add Rule'))
                    ->icon('heroicon-o-plus')
                    ->form([
                        Select::make('action')
                            ->label(__('Action'))
                            ->options([
                                'allow' => 'Allow',
                                'deny' => 'Deny',
                                'reject' => 'Reject',
                                'limit' => 'Limit',
                            ])
                            ->required(),
                        TextInput::make('port')
                            ->label(__('Port'))
                            ->placeholder('443'),
                        Select::make('protocol')
                            ->label(__('Protocol'))
                            ->options([
                                '' => 'Any',
                                'tcp' => 'TCP',
                                'udp' => 'UDP',
                            ]),
                        TextInput::make('from_ip')
                            ->label(__('From IP'))
                            ->placeholder(__('optional')),
                        TextInput::make('comment')
                            ->label(__('Comment'))
                            ->placeholder(__('optional')),
                    ])
                    ->action(function (array $data): void {
                        $body = ['action' => $data['action']];
                        if (! empty($data['port'])) {
                            $body['port'] = $data['port'];
                        }
                        if (! empty($data['protocol'])) {
                            $body['protocol'] = $data['protocol'];
                        }
                        if (! empty($data['from_ip'])) {
                            $body['from_ip'] = $data['from_ip'];
                        }
                        if (! empty($data['comment'])) {
                            $body['comment'] = $data['comment'];
                        }
                        $result = $this->client()->post('/firewall/ufw/rules', $body);
                        Notification::make()
                            ->title($result ? __('Rule added') : __('Failed to add rule'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->columns([
                TextColumn::make('number')
                    ->label('#')
                    ->width('50px'),
                TextColumn::make('to')
                    ->label(__('To')),
                TextColumn::make('action')
                    ->label(__('Action'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'ALLOW' => 'success',
                        'DENY' => 'danger',
                        'REJECT' => 'warning',
                        default => 'gray',
                    }),
                TextColumn::make('from_ip')
                    ->label(__('From')),
                TextColumn::make('direction')
                    ->label(__('Dir')),
                IconColumn::make('v6')
                    ->label('IPv6')
                    ->boolean(),
            ])
            ->recordActions([
                Action::make('delete')
                    ->label(__('Delete'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $this->client()->delete('/firewall/ufw/rules/'.$record['number']);
                        Notification::make()->title(__('Rule deleted'))->success()->send();
                    }),
            ])
            ->emptyStateHeading(__('No firewall rules'))
            ->emptyStateIcon('heroicon-o-fire')
            ->striped();
    }

    // ── WAF Tab ──────────────────────────────────────────────────────

    protected function wafTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/waf/events', ['limit' => 100]) ?? [])
            ->headerActions([
                Action::make('updateCrs')
                    ->label(__('Update CRS'))
                    ->icon('heroicon-o-arrow-path')
                    ->requiresConfirmation()
                    ->action(function (): void {
                        $result = $this->client()->post('/waf/crs/update');
                        Notification::make()
                            ->title($result && ($result['success'] ?? false) ? __('CRS updated') : __('CRS update failed'))
                            ->color($result && ($result['success'] ?? false) ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->columns([
                TextColumn::make('client_ip')
                    ->label(__('Client IP'))
                    ->copyable()
                    ->searchable(isIndividual: false),
                TextColumn::make('method')
                    ->label(__('Method'))
                    ->badge()
                    ->color('gray'),
                TextColumn::make('uri')
                    ->label(__('URI'))
                    ->limit(40),
                TextColumn::make('rule_id')
                    ->label(__('Rule ID')),
                TextColumn::make('rule_msg')
                    ->label(__('Message'))
                    ->limit(30),
                TextColumn::make('severity')
                    ->label(__('Severity'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        '2', 'CRITICAL' => 'danger',
                        '3', 'ERROR' => 'danger',
                        '4', 'WARNING' => 'warning',
                        default => 'gray',
                    }),
                TextColumn::make('created_at')
                    ->label(__('Time'))
                    ->since(),
            ])
            ->recordActions([
                Action::make('disableRule')
                    ->label(__('Disable Rule'))
                    ->icon('heroicon-o-x-mark')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->visible(fn (array $record): bool => ! empty($record['rule_id']))
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/waf/rules/'.$record['rule_id'].'/disable');
                        Notification::make()
                            ->title($result ? __('Rule :id disabled', ['id' => $record['rule_id']]) : __('Failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No WAF events'))
            ->emptyStateIcon('heroicon-o-shield-check')
            ->striped()
            ->defaultPaginationPageOption(25);
    }

    public function getWafStats(): array
    {
        return $this->client()->get('/waf/stats') ?? [];
    }

    public function getWafRules(): array
    {
        return $this->client()->get('/waf/rules') ?? [];
    }

    // ── Brute-Force Tab ─────────────────────────────────────────────

    protected function bruteforceTable(Table $table): Table
    {
        return $table
            ->records(fn () => ($this->client()->get('/bruteforce/blocked'))['blocked_ips'] ?? [])
            ->headerActions([
                Action::make('whitelistIp')
                    ->label(__('Whitelist IP'))
                    ->icon('heroicon-o-check-circle')
                    ->form([
                        TextInput::make('ip')
                            ->label(__('IP Address'))
                            ->required()
                            ->ipv4(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/bruteforce/whitelist', ['ip' => $data['ip']]);
                        Notification::make()
                            ->title($result ? __('IP whitelisted') : __('Failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->columns([
                TextColumn::make('ip')
                    ->label(__('IP Address'))
                    ->copyable()
                    ->state(fn ($record): string => is_string($record) ? $record : ($record['ip'] ?? '')),
            ])
            ->emptyStateHeading(__('No blocked IPs'))
            ->emptyStateIcon('heroicon-o-shield-check')
            ->striped();
    }

    public function getBruteforceStats(): array
    {
        return $this->client()->get('/bruteforce/stats') ?? [];
    }

    // ── Proactive Tab ───────────────────────────────────────────────

    protected function proactiveTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/proactive/php/pools') ?? [])
            ->columns([
                TextColumn::make('pool_name')
                    ->label(__('Pool')),
                TextColumn::make('php_version')
                    ->label(__('PHP')),
                TextColumn::make('user')
                    ->label(__('User')),
                IconColumn::make('hardened')
                    ->label(__('Hardened'))
                    ->boolean(),
                TextColumn::make('issues')
                    ->label(__('Issues'))
                    ->state(fn (array $record): string => implode(', ', $record['issues'] ?? []) ?: '-')
                    ->limit(40),
            ])
            ->recordActions([
                Action::make('harden')
                    ->label(__('Harden'))
                    ->icon('heroicon-o-shield-check')
                    ->color('success')
                    ->visible(fn (array $record): bool => ! ($record['hardened'] ?? true))
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/proactive/php/harden', [
                            'conf_path' => $record['socket_path'] ?? '',
                        ]);
                        Notification::make()
                            ->title($result ? __('Pool hardened') : __('Failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('unharden')
                    ->label(__('Unharden'))
                    ->icon('heroicon-o-shield-exclamation')
                    ->color('warning')
                    ->visible(fn (array $record): bool => $record['hardened'] ?? false)
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/proactive/php/unharden', [
                            'conf_path' => $record['socket_path'] ?? '',
                        ]);
                        Notification::make()
                            ->title($result ? __('Hardening removed') : __('Failed'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No PHP-FPM pools found'))
            ->emptyStateIcon('heroicon-o-code-bracket')
            ->striped();
    }

    public function getProactiveStatus(): array
    {
        return $this->client()->get('/proactive/status') ?? [];
    }

    public function getProactiveKills(): array
    {
        return $this->client()->get('/proactive/kills') ?? [];
    }

    // ── WebShield Tab ───────────────────────────────────────────────

    protected function webshieldTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/webshield/rules') ?? [])
            ->headerActions([
                Action::make('installWebshield')
                    ->label(__('Install'))
                    ->icon('heroicon-o-arrow-down-tray')
                    ->color('success')
                    ->requiresConfirmation()
                    ->action(function (): void {
                        $result = $this->client()->post('/webshield/install');
                        Notification::make()
                            ->title($result && ($result['success'] ?? false) ? __('WebShield installed') : __('Install failed'))
                            ->color($result && ($result['success'] ?? false) ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('uninstallWebshield')
                    ->label(__('Uninstall'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (): void {
                        $this->client()->post('/webshield/uninstall');
                        Notification::make()->title(__('WebShield uninstalled'))->success()->send();
                    }),
            ])
            ->columns([
                TextColumn::make('name')
                    ->label(__('Rule')),
                TextColumn::make('pattern')
                    ->label(__('Pattern'))
                    ->limit(40),
                TextColumn::make('action')
                    ->label(__('Action'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'block' => 'danger',
                        'challenge' => 'warning',
                        'allow' => 'success',
                        default => 'gray',
                    }),
                TextColumn::make('category')
                    ->label(__('Category'))
                    ->badge()
                    ->color('gray'),
                IconColumn::make('enabled')
                    ->label(__('Active'))
                    ->boolean(),
            ])
            ->emptyStateHeading(__('No WebShield rules'))
            ->emptyStateIcon('heroicon-o-globe-alt')
            ->striped();
    }

    public function getWebshieldStatus(): array
    {
        return $this->client()->get('/webshield/status') ?? [];
    }

    // ── Threat Intel Tab ────────────────────────────────────────────

    protected function threatIntelTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/threat-intel/feeds') ?? [])
            ->headerActions([
                Action::make('updateFeeds')
                    ->label(__('Update Feeds'))
                    ->icon('heroicon-o-arrow-path')
                    ->action(function (): void {
                        $result = $this->client()->post('/threat-intel/update');
                        $success = $result['success_count'] ?? 0;
                        $total = $result['total_count'] ?? 0;
                        Notification::make()
                            ->title(__(':s/:t feeds updated', ['s' => $success, 't' => $total]))
                            ->color($success > 0 ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('checkIp')
                    ->label(__('Check IP'))
                    ->icon('heroicon-o-magnifying-glass')
                    ->form([
                        TextInput::make('ip')->label(__('IP Address'))->required()->ipv4(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->get('/threat-intel/check/ip/'.$data['ip']);
                        if ($result) {
                            $malicious = $result['is_malicious'] ?? false;
                            $feeds = implode(', ', $result['feeds'] ?? []);
                            Notification::make()
                                ->title($malicious ? __('Malicious: :feeds', ['feeds' => $feeds]) : __('Clean'))
                                ->color($malicious ? 'danger' : 'success')
                                ->persistent()
                                ->send();
                        } else {
                            Notification::make()->title(__('Check failed'))->danger()->send();
                        }
                    }),
            ])
            ->columns([
                TextColumn::make('name')
                    ->label(__('Feed')),
                TextColumn::make('feed_type')
                    ->label(__('Type'))
                    ->badge()
                    ->color('gray'),
                TextColumn::make('entry_count')
                    ->label(__('Entries'))
                    ->alignCenter(),
                TextColumn::make('last_update')
                    ->label(__('Last Update'))
                    ->since(),
                IconColumn::make('enabled')
                    ->label(__('Active'))
                    ->boolean(),
            ])
            ->emptyStateHeading(__('No threat intel feeds'))
            ->emptyStateIcon('heroicon-o-globe-alt')
            ->striped();
    }

    // ── Users Tab ───────────────────────────────────────────────────

    protected function usersTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/users') ?? [])
            ->columns([
                TextColumn::make('username')
                    ->label(__('Username'))
                    ->searchable(isIndividual: false),
                TextColumn::make('incident_count')
                    ->label(__('Incidents'))
                    ->alignCenter(),
                TextColumn::make('max_score')
                    ->label(__('Max Score'))
                    ->alignCenter()
                    ->color(fn ($state): string => ($state ?? 0) >= 70 ? 'danger' : (($state ?? 0) >= 40 ? 'warning' : 'success')),
            ])
            ->recordActions([
                Action::make('viewUser')
                    ->label(__('Details'))
                    ->icon('heroicon-o-eye')
                    ->modalHeading(fn (array $record): string => __('User: :name', ['name' => $record['username'] ?? '']))
                    ->modalContent(function (array $record): \Illuminate\Contracts\View\View {
                        $details = $this->client()->get('/users/'.($record['username'] ?? ''));

                        return view('jabali-security::user-detail', ['user' => $details ?? []]);
                    })
                    ->modalSubmitAction(false),
            ])
            ->emptyStateHeading(__('No users with incidents'))
            ->emptyStateIcon('heroicon-o-users')
            ->striped();
    }

    // ── Cleanup Tab ─────────────────────────────────────────────────

    protected function cleanupTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/cleanup/records') ?? [])
            ->headerActions([
                Action::make('cleanFile')
                    ->label(__('Clean File'))
                    ->icon('heroicon-o-sparkles')
                    ->form([
                        TextInput::make('path')
                            ->label(__('File Path'))
                            ->placeholder('/home/user/public_html/infected.php')
                            ->required(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/cleanup/file', ['path' => $data['path']]);
                        Notification::make()
                            ->title($result && ($result['success'] ?? false) ? __('File cleaned') : __('Cleanup failed'))
                            ->color($result && ($result['success'] ?? false) ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->columns([
                TextColumn::make('path')
                    ->label(__('File'))
                    ->limit(40),
                TextColumn::make('strategy')
                    ->label(__('Strategy'))
                    ->badge()
                    ->color('gray'),
                IconColumn::make('success')
                    ->label(__('Result'))
                    ->boolean(),
                TextColumn::make('username')
                    ->label(__('User')),
                TextColumn::make('created_at')
                    ->label(__('Time'))
                    ->since(),
            ])
            ->emptyStateHeading(__('No cleanup records'))
            ->emptyStateIcon('heroicon-o-sparkles')
            ->striped();
    }

    // ── Rules Tab ───────────────────────────────────────────────────

    protected function rulesTable(Table $table): Table
    {
        return $table
            ->records(function () {
                $rules = $this->client()->get('/rules') ?? [];
                $records = [];
                foreach ($rules['yara_rules'] ?? [] as $r) {
                    $r['type'] = 'yara';
                    $records[] = $r;
                }

                return $records;
            })
            ->columns([
                TextColumn::make('name')
                    ->label(__('Rule File'))
                    ->searchable(isIndividual: false),
                TextColumn::make('size')
                    ->label(__('Size'))
                    ->formatStateUsing(fn ($state): string => number_format($state ?? 0).' bytes')
                    ->alignEnd(),
            ])
            ->emptyStateHeading(__('No YARA rules'))
            ->emptyStateIcon('heroicon-o-document-text')
            ->striped();
    }

    public function getRulesInfo(): array
    {
        return $this->client()->get('/rules') ?? [];
    }

    // ── Config Tab ───────────────────────────────────────────────────

    protected static array $booleanKeys = [
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

    protected static array $selectKeys = [
        'LOG_LEVEL' => ['debug', 'info', 'warning', 'error', 'critical'],
        'CLAMAV_ENABLED' => ['auto', 'yes', 'no'],
        'FIREWALL_BACKEND' => ['auto', 'nftables', 'iptables', 'none'],
        'WAF_AUDIT_LOG_TYPE' => ['serial', 'concurrent'],
        'WAF_WEB_SERVER' => ['auto', 'nginx', 'apache'],
        'WATCHER_BACKEND' => ['inotify', 'fanotify'],
        'NOTIFY_MIN_SEVERITY' => ['low', 'medium', 'high', 'critical'],
    ];

    protected static array $configCategories = [
        'Daemon' => ['LOG_LEVEL', 'LOG_DIR', 'DATA_DIR', 'QUARANTINE_DIR', 'WORKERS'],
        'API' => ['API_BIND', 'API_PORT', 'API_KEY'],
        'Web Dashboard' => ['WEB_ENABLED', 'WEB_BIND', 'WEB_PORT'],
        'File Watcher' => ['WATCH_DIRS', 'WATCHER_BACKEND'],
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

    public string $configCategory = 'Daemon';

    public function getConfigForCategory(): array
    {
        $config = $this->client()->get('/config') ?? [];
        $keys = static::$configCategories[$this->configCategory] ?? [];
        $records = [];
        foreach ($keys as $key) {
            if (isset($config[$key])) {
                $records[] = ['key' => $key, 'value' => $config[$key]];
            }
        }

        return $records;
    }

    protected function configTable(Table $table): Table
    {
        return $table
            ->records(fn () => $this->getConfigForCategory())
            ->columns([
                TextColumn::make('key')
                    ->label(__('Key'))
                    ->searchable(isIndividual: false)
                    ->weight('bold')
                    ->size('sm'),
                TextColumn::make('value')
                    ->label(__('Value'))
                    ->size('sm')
                    ->state(fn () => '')
                    ->formatStateUsing(fn ($record) => ''),
            ])
            ->recordActions([
                Action::make('edit')
                    ->label(__('Edit'))
                    ->icon('heroicon-o-pencil')
                    ->visible(fn (array $record): bool => ! in_array($record['key'], static::$booleanKeys) && ! isset(static::$selectKeys[$record['key']]))
                    ->form(fn (array $record): array => [
                        TextInput::make('value')
                            ->label($record['key'])
                            ->default($record['value']),
                    ])
                    ->action(function (array $data, array $record): void {
                        $this->saveConfigKey($record['key'], $data['value']);
                    }),
            ])
            ->emptyStateHeading(__('Cannot load configuration'))
            ->striped()
            ->defaultPaginationPageOption(50);
    }

    // ── Firewall Actions ─────────────────────────────────────────────

    public function enableFirewall(): void
    {
        $result = $this->client()->post('/firewall/ufw/enable');
        Notification::make()
            ->title($result ? __('Firewall enabled') : __('Failed'))
            ->color($result ? 'success' : 'danger')
            ->send();
    }

    public function disableFirewall(): void
    {
        $result = $this->client()->post('/firewall/ufw/disable');
        Notification::make()
            ->title($result ? __('Firewall disabled') : __('Failed'))
            ->color($result ? 'success' : 'danger')
            ->send();
    }

    public function updateConfigValue(string $key, string $value): void
    {
        $this->saveConfigKey($key, $value);
    }

    protected function saveConfigKey(string $key, string $value): void
    {
        $result = $this->client()->patch('/config', [$key => $value]);
        Notification::make()
            ->title($result ? __('Config updated') : __('Update failed'))
            ->body($result ? __('Restart daemon to apply changes') : '')
            ->color($result ? 'success' : 'danger')
            ->send();
    }

    // ── Module Toggles ───────────────────────────────────────────────

    public function getConfigData(): array
    {
        return $this->client()->get('/config') ?? [];
    }

    public function toggleModule(string $key): void
    {
        $config = $this->getConfigData();
        $current = $config[$key] ?? 'no';
        $newValue = in_array($current, ['yes', 'true', '1']) ? 'no' : 'yes';

        $result = $this->client()->patch('/config', [$key => $newValue]);
        if ($result) {
            Notification::make()
                ->title(__(':feature :action', [
                    'feature' => str_replace('_', ' ', str_replace('_ENABLED', '', $key)),
                    'action' => $newValue === 'yes' ? __('enabled') : __('disabled'),
                ]))
                ->color($newValue === 'yes' ? 'success' : 'warning')
                ->send();
        } else {
            Notification::make()->title(__('Failed to update config'))->danger()->send();
        }
    }

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

    // ── Helper for view ──────────────────────────────────────────────

    public function getFirewallStatus(): array
    {
        return $this->client()->get('/firewall/ufw/status') ?? ['available' => false];
    }
}
