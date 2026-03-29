<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
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
                TextColumn::make('shell')
                    ->label(__('Shell'))
                    ->fontFamily('mono')
                    ->size('sm')
                    ->color('gray'),
                IconColumn::make('shell_enabled')
                    ->label(__('Terminal'))
                    ->boolean(),
                IconColumn::make('sftp_only')
                    ->label(__('SFTP Only'))
                    ->boolean(),
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
            ->headerActions([
                Action::make('addKey')
                    ->label(__('Add SSH Key'))
                    ->icon('heroicon-o-key')
                    ->form([
                        TextInput::make('username')
                            ->label(__('Username'))
                            ->required(),
                        TextInput::make('name')
                            ->label(__('Key Name'))
                            ->required()
                            ->maxLength(50),
                        Textarea::make('public_key')
                            ->label(__('Public Key'))
                            ->required()
                            ->rows(3)
                            ->placeholder('ssh-ed25519 AAAAC3... or ssh-rsa AAAAB3...'),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/ssh/keys', $data);

                        Notification::make()
                            ->title($result ? __('SSH key added') : __('Failed to add key'))
                            ->{($result ? "success" : "danger")}()
                            ->send();
                    }),
                Action::make('generateKey')
                    ->label(__('Generate Key'))
                    ->icon('heroicon-o-sparkles')
                    ->color('success')
                    ->form([
                        TextInput::make('username')
                            ->label(__('Username'))
                            ->required(),
                        TextInput::make('name')
                            ->label(__('Key Name'))
                            ->required()
                            ->maxLength(50),
                        Select::make('type')
                            ->label(__('Key Type'))
                            ->options([
                                'ed25519' => 'ED25519 (Recommended)',
                                'rsa' => 'RSA 4096-bit',
                            ])
                            ->default('ed25519')
                            ->required(),
                        TextInput::make('passphrase')
                            ->label(__('Passphrase (Optional)'))
                            ->password(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/ssh/keys/generate', $data);

                        if ($result && ($result['private_key'] ?? '')) {
                            Notification::make()
                                ->title(__('Key generated'))
                                ->body(__('Private key returned — save it securely.'))
                                ->success()
                                ->persistent()
                                ->send();
                        } else {
                            Notification::make()->title(__('Generation failed'))->danger()->send();
                        }
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
