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
use Filament\Tables\Actions\Action as TableAction;
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

    protected static ?int $navigationSort = 50;

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

        $valid = ['overview', 'incidents', 'quarantine', 'blocklist', 'firewall', 'config'];

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
                TableAction::make('resolve')
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
                TableAction::make('restore')
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
                TableAction::make('delete')
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
                TableAction::make('blockIp')
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
                TableAction::make('unblock')
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
                TableAction::make('addRule')
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
                TableAction::make('delete')
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

    // ── Config Tab ───────────────────────────────────────────────────

    protected function configTable(Table $table): Table
    {
        return $table
            ->records(function () {
                $config = $this->client()->get('/config') ?? [];
                $records = [];
                foreach ($config as $key => $value) {
                    $records[] = ['key' => $key, 'value' => $value];
                }

                return $records;
            })
            ->columns([
                TextColumn::make('key')
                    ->label(__('Key'))
                    ->searchable(isIndividual: false)
                    ->weight('bold')
                    ->size('sm'),
                TextColumn::make('value')
                    ->label(__('Value'))
                    ->size('sm'),
            ])
            ->recordActions([
                TableAction::make('edit')
                    ->label(__('Edit'))
                    ->icon('heroicon-o-pencil')
                    ->form([
                        TextInput::make('value')
                            ->label(fn (array $record): string => $record['key'])
                            ->default(fn (array $record): string => $record['value']),
                    ])
                    ->action(function (array $data, array $record): void {
                        $result = $this->client()->patch('/config', [
                            $record['key'] => $data['value'],
                        ]);
                        Notification::make()
                            ->title($result ? __('Config updated') : __('Update failed'))
                            ->body($result ? __('Restart daemon to apply changes') : '')
                            ->color($result ? 'success' : 'danger')
                            ->send();
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

    // ── Helper for view ──────────────────────────────────────────────

    public function getFirewallStatus(): array
    {
        return $this->client()->get('/firewall/ufw/status') ?? ['available' => false];
    }
}
