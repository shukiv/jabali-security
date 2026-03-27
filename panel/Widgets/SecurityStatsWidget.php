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

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $status = $client->get('/status');

        if (! $status) {
            return [
                Stat::make('Daemon', 'Offline')
                    ->description('Security daemon is not responding')
                    ->icon('heroicon-o-exclamation-circle')
                    ->color('danger'),
            ];
        }

        return [
            Stat::make('Incidents (24h)', (string) ($status['incidents_24h'] ?? 0))
                ->description('Security events detected')
                ->icon('heroicon-o-exclamation-triangle')
                ->color(($status['incidents_24h'] ?? 0) > 0 ? 'danger' : 'success'),

            Stat::make('Quarantined', (string) ($status['quarantined_count'] ?? 0))
                ->description('Files in quarantine')
                ->icon('heroicon-o-lock-closed')
                ->color(($status['quarantined_count'] ?? 0) > 0 ? 'warning' : 'success'),

            Stat::make('Watched Dirs', (string) ($status['watched_dirs'] ?? 0))
                ->description('Directories monitored')
                ->icon('heroicon-o-eye')
                ->color('info'),

            Stat::make('Daemon', ($status['running'] ?? false) ? 'Running' : 'Stopped')
                ->description(sprintf(
                    'v%s | %s MB | %d workers',
                    $status['version'] ?? '?',
                    round($status['memory_mb'] ?? 0, 1),
                    $status['workers'] ?? 0,
                ))
                ->icon(($status['running'] ?? false) ? 'heroicon-o-check-circle' : 'heroicon-o-x-circle')
                ->color(($status['running'] ?? false) ? 'success' : 'danger'),
        ];
    }
}
