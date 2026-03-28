<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
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

class PhpPoolsTable extends Component implements HasActions, HasSchemas, HasTable
{
    use InteractsWithActions;
    use InteractsWithSchemas;
    use InteractsWithTable;

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
            ->emptyStateHeading(__('No PHP pools'))
            ->striped();
    }

    public function render()
    {
        return $this->getTable()->render();
    }
}
