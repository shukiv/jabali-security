<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class BruteforceBlockedTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/bruteforce/blocked')['blocked_ips'] ?? [])
            ->columns([
                TextColumn::make('ip')
                    ->label(__('IP Address'))
                    ->state(fn ($record): string => is_string($record) ? $record : ($record['ip'] ?? '')),
            ])
            ->headerActions([
                Action::make('whitelist')
                    ->label(__('Whitelist IP'))
                    ->icon('heroicon-o-shield-check')
                    ->form([
                        TextInput::make('ip')
                            ->label(__('IP Address'))
                            ->required()
                            ->ipv4(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/bruteforce/whitelist', $data);

                        Notification::make()
                            ->title($result ? __('IP whitelisted') : __('Failed to whitelist IP'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No blocked IPs'))
            ->striped();
    }
}
