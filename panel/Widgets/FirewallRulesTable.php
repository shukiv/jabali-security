<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class FirewallRulesTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/firewall/ufw/status')['rules'] ?? [])
            ->columns([
                TextColumn::make('number')
                    ->label(__('Number')),
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
                    ->label(__('Direction')),
                IconColumn::make('v6')
                    ->label(__('IPv6'))
                    ->boolean(),
            ])
            ->headerActions([
                Action::make('add_rule')
                    ->label(__('Add Rule'))
                    ->icon('heroicon-o-plus')
                    ->form([
                        Select::make('action')
                            ->label(__('Action'))
                            ->options([
                                'allow' => __('Allow'),
                                'deny' => __('Deny'),
                                'reject' => __('Reject'),
                                'limit' => __('Limit'),
                            ])
                            ->required(),
                        TextInput::make('port')
                            ->label(__('Port'))
                            ->required(),
                        Select::make('protocol')
                            ->label(__('Protocol'))
                            ->options([
                                'tcp' => 'TCP',
                                'udp' => 'UDP',
                                'any' => __('Any'),
                            ])
                            ->required(),
                        TextInput::make('from_ip')
                            ->label(__('From IP')),
                        TextInput::make('comment')
                            ->label(__('Comment')),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/firewall/ufw/rules', $data);

                        Notification::make()
                            ->title($result ? __('Rule added') : __('Failed to add rule'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->recordActions([
                Action::make('delete')
                    ->label(__('Delete'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $result = $this->client()->delete("/firewall/ufw/rules/{$record['number']}");

                        Notification::make()
                            ->title($result ? __('Rule deleted') : __('Failed to delete rule'))
                            ->color($result ? 'success' : 'danger')
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No firewall rules'))
            ->striped();
    }
}
