<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;
use Filament\Widgets\Widget;

class YaraRulesTable extends Widget implements HasTable
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
            ->records(fn () => $this->client()->get('/rules')['yara_rules'] ?? [])
            ->columns([
                TextColumn::make('name')
                    ->label(__('Rule Name')),
                TextColumn::make('size')
                    ->label(__('Size'))
                    ->formatStateUsing(fn ($state): string => number_format((int) $state).' bytes'),
            ])
            ->emptyStateHeading(__('No YARA rules'))
            ->striped();
    }
}
