<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class SecurityStatsWidget extends BaseWidget
{
    protected static ?int $sort = 1;

    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 5;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $status = $client->get('/status');

        if (! $status) {
            return [
                Stat::make(__('Daemon'), __('Offline'))
                    ->description(__('Not responding'))
                    ->icon('heroicon-o-exclamation-circle')
                    ->color('danger')
                    ->extraAttributes(['class' => '!p-3']),
            ];
        }

        return [
            Stat::make(__('Incidents'), (string) ($status['incidents_24h'] ?? 0))
                ->description(__('Last 24 hours'))
                ->icon('heroicon-o-exclamation-triangle')
                ->color(($status['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success')
                ->extraAttributes(['class' => '!p-3']),

            Stat::make(__('Quarantine'), (string) ($status['quarantined_count'] ?? 0))
                ->description(__('Files isolated'))
                ->icon('heroicon-o-lock-closed')
                ->color(($status['quarantined_count'] ?? 0) > 0 ? 'warning' : 'success')
                ->extraAttributes(['class' => '!p-3']),

            Stat::make(__('Watching'), (string) ($status['watched_dirs'] ?? 0))
                ->description(__('Folders monitored'))
                ->icon('heroicon-o-eye')
                ->color('info')
                ->extraAttributes(['class' => '!p-3']),

            Stat::make(__('Memory'), round($status['memory_mb'] ?? 0, 1).' MB')
                ->description(($status['workers'] ?? 0).' '.__('workers'))
                ->icon('heroicon-o-cpu-chip')
                ->color('gray')
                ->extraAttributes(['class' => '!p-3']),

            Stat::make(__('Daemon'), ($status['running'] ?? false) ? __('Online') : __('Offline'))
                ->description(($status['running'] ?? false) ? __('All systems go') : __('Service down'))
                ->icon(($status['running'] ?? false) ? 'heroicon-o-check-circle' : 'heroicon-o-x-circle')
                ->color(($status['running'] ?? false) ? 'success' : 'danger')
                ->extraAttributes(['class' => '!p-3']),
        ];
    }
}
