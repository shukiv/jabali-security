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

class WebshieldRulesTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/webshield/rules') ?? [])
            ->columns([
                TextColumn::make('name')
                    ->label(__('Name')),
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
                    ->label(__('Enabled'))
                    ->boolean(),
            ])
            ->headerActions([
                Action::make('install')
                    ->label(__('Install'))
                    ->icon('heroicon-o-arrow-down-on-square')
                    ->requiresConfirmation()
                    ->action(function (): void {
                        $result = $this->client()->post('/webshield/install');

                        Notification::make()
                            ->title($result ? __('WebShield installed') : __('Failed to install WebShield'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
                Action::make('uninstall')
                    ->label(__('Uninstall'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (): void {
                        $result = $this->client()->post('/webshield/uninstall');

                        Notification::make()
                            ->title($result ? __('WebShield uninstalled') : __('Failed to uninstall WebShield'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No WebShield rules'))
            ->striped();
    }
}
