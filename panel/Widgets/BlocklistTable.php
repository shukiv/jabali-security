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

class BlocklistTable extends Widget implements HasTable
{
    use InteractsWithTable;

    protected string $view = 'filament-widgets::table-widget';

    protected function client(): JabaliSecurityClient
    {
        return new JabaliSecurityClient;
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(fn () => $this->client()->get('/blocklist') ?? [])
            ->columns([
                TextColumn::make('ip')
                    ->label(__('IP Address'))
                    ->copyable(),
                TextColumn::make('reason')
                    ->label(__('Reason')),
                TextColumn::make('blocked_at')
                    ->label(__('Blocked'))
                    ->since(),
                TextColumn::make('expires_at')
                    ->label(__('Expires'))
                    ->placeholder(__('permanent')),
                TextColumn::make('blocked_by')
                    ->label(__('Blocked By'))
                    ->badge()
                    ->color('gray'),
            ])
            ->headerActions([
                Action::make('block')
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
                            ->numeric(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/block', $data);

                        Notification::make()
                            ->title($result ? __('IP blocked') : __('Failed to block IP'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->recordActions([
                Action::make('unblock')
                    ->label(__('Unblock'))
                    ->icon('heroicon-o-lock-open')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->delete("/block/{$record['ip']}");

                        Notification::make()
                            ->title($result ? __('IP unblocked') : __('Failed to unblock IP'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No blocked IPs'))
            ->striped();
    }
}
