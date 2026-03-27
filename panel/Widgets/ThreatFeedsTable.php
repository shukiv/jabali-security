<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class ThreatFeedsTable extends Widget implements HasTable
{
    use InteractsWithTable;

    protected static string $view = 'filament-widgets::table-widget';

    protected function client(): JabaliSecurityClient
    {
        return new JabaliSecurityClient;
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/threat-intel/feeds') ?? [])
            ->columns([
                TextColumn::make('name')
                    ->label(__('Name')),
                TextColumn::make('feed_type')
                    ->label(__('Type'))
                    ->badge()
                    ->color('gray'),
                TextColumn::make('entry_count')
                    ->label(__('Entries')),
                TextColumn::make('last_update')
                    ->label(__('Last Update'))
                    ->since(),
                IconColumn::make('enabled')
                    ->label(__('Enabled'))
                    ->boolean(),
            ])
            ->headerActions([
                Action::make('update_feeds')
                    ->label(__('Update Feeds'))
                    ->icon('heroicon-o-arrow-path')
                    ->action(function (): void {
                        $result = $this->client()->post('/threat-intel/update');

                        Notification::make()
                            ->title($result ? __('Feeds updated') : __('Failed to update feeds'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('check_ip')
                    ->label(__('Check IP'))
                    ->icon('heroicon-o-magnifying-glass')
                    ->form([
                        TextInput::make('ip')
                            ->label(__('IP Address'))
                            ->required()
                            ->ipv4(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->get("/threat-intel/check/ip/{$data['ip']}");

                        if ($result) {
                            Notification::make()
                                ->title(__('IP Check Result'))
                                ->body(($result['threat'] ?? false) ? __('Threat detected') : __('No threats found'))
                                ->color(($result['threat'] ?? false) ? 'danger' : 'success')
                                ->send();
                        } else {
                            Notification::make()
                                ->title(__('Failed to check IP'))
                                ->danger()
                                ->send();
                        }
                    }),
            ])
            ->emptyStateHeading(__('No threat feeds'))
            ->striped();
    }
}
