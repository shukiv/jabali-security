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
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Livewire\Component;

class BruteforceBlockedTable extends Component implements HasActions, HasSchemas, HasTable
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

    public function render()
    {
        return $this->getTable()->render();
    }
}
