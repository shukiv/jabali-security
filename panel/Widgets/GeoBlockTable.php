<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\Placeholder;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Livewire\Component;

class GeoBlockTable extends Component implements HasActions, HasSchemas, HasTable
{
    use InteractsWithActions;
    use InteractsWithSchemas;
    use InteractsWithTable;

    protected function client(): JabaliSecurityClient
    {
        return JabaliSecurityClient::getInstance();
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(function () {
                $data = $this->client()->get('/webshield/geo-rules');
                return $data['rules'] ?? [];
            })
            ->columns([
                TextColumn::make('country_code')
                    ->label(__('Code'))
                    ->searchable(),
                TextColumn::make('country_name')
                    ->label(__('Country'))
                    ->searchable(),
                TextColumn::make('action')
                    ->label(__('Action'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'block' => 'danger',
                        'challenge' => 'warning',
                        'allow' => 'success',
                        'log' => 'info',
                        default => 'gray',
                    }),
            ])
            ->actions([
                Action::make('remove')
                    ->label(__('Remove'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function ($record): void {
                        $cc = $record['country_code'] ?? '';
                        if (! $cc) {
                            return;
                        }
                        $this->client()->delete('/webshield/geo-rules/' . urlencode($cc));
                        Notification::make()
                            ->title(__('Country removed: :cc', ['cc' => $cc]))
                            ->success()
                            ->send();
                        $this->redirect(url('/jabali-admin/security?tab=defense&defense=webshield'), navigate: true);
                    }),
            ])
            ->headerActions([
                Action::make('add_country')
                    ->label(__('Block Country'))
                    ->icon('heroicon-o-globe-alt')
                    ->form([
                        TextInput::make('country_codes')
                            ->label(__('Country Codes'))
                            ->helperText(__('Comma-separated ISO codes (e.g., CN,RU,KP)'))
                            ->required(),
                        Select::make('action')
                            ->label(__('Action'))
                            ->options([
                                'block' => __('Block (403)'),
                                'challenge' => __('Challenge (JS page)'),
                                'log' => __('Log only'),
                            ])
                            ->default('block'),
                    ])
                    ->action(function (array $data): void {
                        $codes = array_map('trim', explode(',', strtoupper($data['country_codes'] ?? '')));
                        $codes = array_filter($codes);
                        if (empty($codes)) {
                            return;
                        }

                        // Get existing blocked countries and merge
                        $existing = $this->client()->get('/webshield/geo-rules');
                        $existingCodes = array_column($existing['rules'] ?? [], 'country_code');
                        $merged = array_unique(array_merge($existingCodes, $codes));

                        $this->client()->post('/webshield/geo-rules', [
                            'countries' => array_values($merged),
                            'action' => $data['action'] ?? 'block',
                            'mode' => 'blocklist',
                        ]);

                        Notification::make()
                            ->title(__('Countries blocked: :codes', ['codes' => implode(', ', $codes)]))
                            ->success()
                            ->send();
                        $this->redirect(url('/jabali-admin/security?tab=defense&defense=webshield'), navigate: true);
                    }),
                Action::make('update_db')
                    ->label(__('Update GeoIP DB'))
                    ->icon('heroicon-o-arrow-path')
                    ->requiresConfirmation()
                    ->modalDescription(__('Download the latest MaxMind GeoLite2-Country database. Requires a license key configured below.'))
                    ->action(function (): void {
                        $result = $this->client()->post('/webshield/geo-update-db');
                        Notification::make()
                            ->title($result ? __('GeoIP database updated') : __('GeoIP update failed'))
                            ->{($result ? 'success' : 'danger')}()
                            ->send();
                    }),
                Action::make('configure_maxmind')
                    ->label(__('MaxMind Settings'))
                    ->icon('heroicon-o-cog-6-tooth')
                    ->color('gray')
                    ->modalHeading(__('MaxMind GeoIP Configuration'))
                    ->modalWidth('lg')
                    ->form(function (): array {
                        $config = $this->client()->get('/config');
                        $hasKey = ($config['GEOIP_MAXMIND_LICENSE_KEY'] ?? '') === 'set';

                        return [
                            Placeholder::make('instructions')
                                ->label('')
                                ->content(
                                    __('To use GeoIP blocking, you need a free MaxMind account:') . "\n\n" .
                                    '1. ' . __('Sign up at maxmind.com/en/geolite2/signup') . "\n" .
                                    '2. ' . __('Go to Account → Manage License Keys → Generate New License Key') . "\n" .
                                    '3. ' . __('Copy your Account ID and License Key below') . "\n" .
                                    '4. ' . __('Click Save, then use "Update GeoIP DB" to download the database')
                                ),
                            TextInput::make('account_id')
                                ->label(__('MaxMind Account ID'))
                                ->helperText(__('Your numeric Account ID from maxmind.com'))
                                ->placeholder('123456'),
                            TextInput::make('license_key')
                                ->label(__('License Key'))
                                ->helperText($hasKey ? __('A license key is already configured. Leave blank to keep it.') : __('Generate this from your MaxMind account'))
                                ->placeholder($hasKey ? '••••••••' : 'xxxx_xxxxxxxxxxxx')
                                ->password()
                                ->revealable(),
                            Select::make('geoip_action')
                                ->label(__('Default Action'))
                                ->options([
                                    'block' => __('Block (403 Forbidden)'),
                                    'challenge' => __('Challenge (JS page)'),
                                    'log' => __('Log only'),
                                ])
                                ->default($config['GEOIP_ACTION'] ?? 'block'),
                        ];
                    })
                    ->action(function (array $data): void {
                        $patch = ['GEOIP_ENABLED' => 'yes'];

                        if (! empty($data['license_key'])) {
                            $patch['GEOIP_MAXMIND_LICENSE_KEY'] = $data['license_key'];
                        }
                        if (! empty($data['geoip_action'])) {
                            $patch['GEOIP_ACTION'] = $data['geoip_action'];
                        }

                        $this->client()->patch('/config', $patch);

                        // Write /etc/GeoIP.conf for geoipupdate CLI tool
                        if (! empty($data['account_id']) && ! empty($data['license_key'])) {
                            $this->client()->post('/webshield/geo-update-db', [
                                'account_id' => $data['account_id'],
                                'license_key' => $data['license_key'],
                            ]);
                        }

                        Notification::make()
                            ->title(__('MaxMind settings saved'))
                            ->success()
                            ->send();
                        $this->redirect(url('/jabali-admin/security?tab=defense&defense=geoip'), navigate: true);
                    }),
            ])
            ->emptyStateHeading(__('No country rules'))
            ->emptyStateDescription(__('Block or allow traffic by country using MaxMind GeoIP database'))
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
