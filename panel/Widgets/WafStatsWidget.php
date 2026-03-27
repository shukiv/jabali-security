<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class WafStatsWidget extends BaseWidget
{
    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 2;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $stats = $client->get('/waf/stats') ?? [];

        return [
            Stat::make(__('Events (24h)'), (string) ($stats['total_events_24h'] ?? 0))
                ->icon('heroicon-o-shield-exclamation')
                ->color(($stats['total_events_24h'] ?? 0) > 0 ? 'warning' : 'success'),
            Stat::make(__('Blocked (24h)'), (string) ($stats['blocked_24h'] ?? 0))
                ->icon('heroicon-o-no-symbol')
                ->color(($stats['blocked_24h'] ?? 0) > 0 ? 'danger' : 'success'),
        ];
    }
}
