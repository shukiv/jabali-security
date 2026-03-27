<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class UsersTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/users') ?? [])
            ->columns([
                TextColumn::make('username')
                    ->label(__('Username')),
                TextColumn::make('incident_count')
                    ->label(__('Incidents')),
                TextColumn::make('max_score')
                    ->label(__('Max Score'))
                    ->color(fn ($state): string => match (true) {
                        (int) $state >= 70 => 'danger',
                        (int) $state >= 40 => 'warning',
                        default => 'success',
                    }),
            ])
            ->emptyStateHeading(__('No users'))
            ->striped();
    }
}
