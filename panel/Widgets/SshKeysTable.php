<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Actions\BulkAction;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Illuminate\Support\Collection;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Livewire\Component;

class SshKeysTable extends Component implements HasActions, HasSchemas, HasTable
{
    use InteractsWithActions;
    use InteractsWithSchemas;
    use InteractsWithTable;

    public string $sshUsername = '';

    protected function client(): JabaliSecurityClient
    {
        return JabaliSecurityClient::getInstance();
    }

    public function table(Table $table): Table
    {
        return $table
            ->records(function () {
                if (! $this->sshUsername) {
                    // Show all system users with shell status
                    $users = $this->client()->get('/ssh/users') ?? [];
                    $records = [];
                    foreach ($users as $user) {
                        $username = $user['username'] ?? '';
                        if (! $username) {
                            continue;
                        }
                        $records[] = [
                            'username' => $username,
                            'shell' => $user['shell'] ?? '/usr/sbin/nologin',
                            'shell_enabled' => ($user['shell'] ?? '') !== '/usr/sbin/nologin',
                            'sftp_only' => ($user['shell'] ?? '') === '/usr/sbin/nologin',
                            'key_count' => $user['key_count'] ?? 0,
                        ];
                    }

                    return $records;
                }

                return $this->client()->get('/ssh/keys', ['username' => $this->sshUsername]) ?? [];
            })
            ->columns([
                TextColumn::make('username')
                    ->label(__('User'))
                    ->weight('bold')
                    ->searchable(),
                TextColumn::make('shell_enabled')
                    ->label(__('Permission'))
                    ->badge()
                    ->state(fn (array $record): string => ($record['shell_enabled'] ?? false) ? 'SSH / SFTP' : 'SFTP Only')
                    ->color(fn (array $record): string => ($record['shell_enabled'] ?? false) ? 'success' : 'gray'),
                TextColumn::make('key_count')
                    ->label(__('SSH Keys'))
                    ->badge()
                    ->color(fn ($state) => $state > 0 ? 'success' : 'gray'),
            ])
            ->recordActions([
                Action::make('toggleShell')
                    ->label(fn (array $record) => ($record['shell_enabled'] ?? false) ? __('Disable Shell') : __('Enable Shell'))
                    ->icon(fn (array $record) => ($record['shell_enabled'] ?? false) ? 'heroicon-o-x-circle' : 'heroicon-o-check-circle')
                    ->color(fn (array $record) => ($record['shell_enabled'] ?? false) ? 'danger' : 'success')
                    ->requiresConfirmation()
                    ->action(function (array $record): void {
                        $username = $record['username'] ?? '';
                        $enabled = $record['shell_enabled'] ?? false;
                        $endpoint = $enabled ? '/ssh/shell/disable' : '/ssh/shell/enable';
                        $result = $this->client()->post($endpoint, ['username' => $username]);

                        Notification::make()
                            ->title($result !== null
                                ? ($enabled ? __('Shell disabled for :user', ['user' => $username]) : __('Shell enabled for :user', ['user' => $username]))
                                : __('Failed'))
                            ->{$result !== null ? 'success' : 'danger'}()
                            ->send();
                    }),
            ])
            ->headerActions([])
            ->bulkActions([
                BulkAction::make('enable_shell')
                    ->label(__('Enable Shell'))
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->requiresConfirmation()
                    ->deselectRecordsAfterCompletion()
                    ->action(function (Collection $records): void {
                        $count = 0;
                        foreach ($records as $record) {
                            $result = $this->client()->post('/ssh/shell/enable', ['username' => $record['username']]);
                            if ($result !== null) {
                                $count++;
                            }
                        }
                        Notification::make()
                            ->title(__(':count shells enabled', ['count' => $count]))
                            ->success()
                            ->send();
                    }),
                BulkAction::make('disable_shell')
                    ->label(__('Disable Shell'))
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->deselectRecordsAfterCompletion()
                    ->action(function (Collection $records): void {
                        $count = 0;
                        foreach ($records as $record) {
                            $result = $this->client()->post('/ssh/shell/disable', ['username' => $record['username']]);
                            if ($result !== null) {
                                $count++;
                            }
                        }
                        Notification::make()
                            ->title(__(':count shells disabled', ['count' => $count]))
                            ->success()
                            ->send();
                    }),
            ])
            ->emptyStateHeading(__('No SSH users found'))
            ->emptyStateDescription(__('Users with SSH access will appear here'))
            ->emptyStateIcon('heroicon-o-key')
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
