<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Tables\Columns\TextColumn;
use Filament\Actions\BulkAction;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Illuminate\Support\Collection;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Livewire\Component;

class WhitelistTable extends Component implements HasActions, HasSchemas, HasTable
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
            ->records(fn () => $this->client()->get('/bruteforce/whitelist')['whitelist'] ?? [])
            ->columns([
                TextColumn::make('ip')
                    ->label(__('IP Address'))
                    ->state(fn ($record): string => is_string($record) ? $record : ($record['ip'] ?? '')),
            ])
            ->actions([
                Action::make('remove')
                    ->label(__('Remove'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function ($record): void {
                        $ip = is_string($record) ? $record : ($record['ip'] ?? '');
                        if ($ip) {
                            $this->client()->delete('/bruteforce/whitelist/' . urlencode($ip));
                            Notification::make()->title(__('Removed :ip from whitelist', ['ip' => $ip]))->success()->send();
                            $this->resetTable();
                        }
                    }),
            ])
            ->headerActions([
                Action::make('add')
                    ->label(__('Add IP'))
                    ->icon('heroicon-o-plus')
                    ->form([
                        TextInput::make('ip')
                            ->label(__('IP Address'))
                            ->required()
                            ->ip(),
                    ])
                    ->action(function (array $data): void {
                        $result = $this->client()->post('/bruteforce/whitelist', $data);
                        Notification::make()
                            ->title($result ? __('IP whitelisted') : __('Failed to whitelist IP'))
                            ->{($result ? 'success' : 'danger')}()
                            ->send();
                        $this->resetTable();
                    }),
            ])
            ->bulkActions([
                BulkAction::make('remove')
                    ->label(__('Remove Selected'))
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->deselectRecordsAfterCompletion()
                    ->action(function (Collection $records): void {
                        $count = 0;
                        foreach ($records as $record) {
                            $ip = is_string($record) ? $record : ($record['ip'] ?? '');
                            if ($ip) {
                                $this->client()->delete('/bruteforce/whitelist/' . urlencode($ip));
                                $count++;
                            }
                        }
                        Notification::make()->title(__(':count IPs removed from whitelist', ['count' => $count]))->success()->send();
                    }),
            ])
            ->emptyStateHeading(__('No whitelisted IPs'))
            ->emptyStateDescription(__('Add IPs that should never be blocked'))
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
