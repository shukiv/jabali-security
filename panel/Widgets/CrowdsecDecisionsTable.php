<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Actions\Concerns\InteractsWithActions;
use Filament\Actions\Contracts\HasActions;
use Filament\Schemas\Concerns\InteractsWithSchemas;
use Filament\Schemas\Contracts\HasSchemas;
use Livewire\Component;

class CrowdsecDecisionsTable extends Component implements HasActions, HasSchemas, HasTable
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
            ->records(fn () => $this->client()->get('/crowdsec/decisions')['decisions'] ?? [])
            ->columns([
                TextColumn::make('value')
                    ->label(__('IP Address'))
                    ->searchable(),
                TextColumn::make('type')
                    ->label(__('Action'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'ban' => 'danger',
                        'captcha' => 'warning',
                        default => 'gray',
                    }),
                TextColumn::make('scenario')
                    ->label(__('Scenario'))
                    ->limit(40),
                TextColumn::make('duration')
                    ->label(__('Duration')),
                TextColumn::make('origin')
                    ->label(__('Source'))
                    ->badge()
                    ->color(fn (string $state): string => match ($state) {
                        'CAPI' => 'info',
                        'crowdsec' => 'success',
                        'cscli' => 'gray',
                        default => 'gray',
                    }),
            ])
            ->emptyStateHeading(__('No active CrowdSec decisions'))
            ->emptyStateDescription(__('CrowdSec will show blocked IPs here when attacks are detected'))
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
