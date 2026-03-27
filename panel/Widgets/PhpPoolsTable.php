<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class PhpPoolsTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/proactive/php/pools') ?? [])
            ->columns([
                TextColumn::make('pool_name')
                    ->label(__('Pool')),
                TextColumn::make('php_version')
                    ->label(__('PHP Version')),
                TextColumn::make('user')
                    ->label(__('User')),
                IconColumn::make('hardened')
                    ->label(__('Hardened'))
                    ->boolean(),
                TextColumn::make('issues')
                    ->label(__('Issues'))
                    ->state(fn (array $record): string => implode(', ', $record['issues'] ?? [])),
            ])
            ->recordActions([
                Action::make('harden')
                    ->label(__('Harden'))
                    ->icon('heroicon-o-shield-check')
                    ->visible(fn (array $record): bool => ! ($record['hardened'] ?? false))
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/proactive/php/harden', [
                            'conf_path' => $record['socket_path'] ?? '',
                        ]);

                        Notification::make()
                            ->title($result ? __('Pool hardened') : __('Failed to harden pool'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('unharden')
                    ->label(__('Unharden'))
                    ->icon('heroicon-o-shield-exclamation')
                    ->visible(fn (array $record): bool => (bool) ($record['hardened'] ?? false))
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->post('/proactive/php/unharden', [
                            'conf_path' => $record['socket_path'] ?? '',
                        ]);

                        Notification::make()
                            ->title($result ? __('Pool unhardened') : __('Failed to unharden pool'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No PHP pools'))
            ->striped();
    }
}
