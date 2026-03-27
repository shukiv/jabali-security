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
                    ->icon('heroicon-o-exclamation-circle')
                    ->color('danger'),
            ];
        }

        return [
            Stat::make(__('Incidents'), (string) ($status['incidents_24h'] ?? 0))
                ->icon('heroicon-o-exclamation-triangle')
                ->color(($status['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success'),

            Stat::make(__('Quarantine'), (string) ($status['quarantined_count'] ?? 0))
                ->icon('heroicon-o-lock-closed')
                ->color(($status['quarantined_count'] ?? 0) > 0 ? 'warning' : 'success'),

            Stat::make(__('Watching'), (string) ($status['watched_dirs'] ?? 0))
                ->icon('heroicon-o-eye')
                ->color('info'),

            Stat::make(__('Memory'), round($status['memory_mb'] ?? 0, 1).' MB')
                ->icon('heroicon-o-cpu-chip')
                ->color('gray'),

            Stat::make(__('Daemon'), ($status['running'] ?? false) ? __('Online') : __('Offline'))
                ->icon(($status['running'] ?? false) ? 'heroicon-o-check-circle' : 'heroicon-o-x-circle')
                ->color(($status['running'] ?? false) ? 'success' : 'danger'),
        ];
    }
}
