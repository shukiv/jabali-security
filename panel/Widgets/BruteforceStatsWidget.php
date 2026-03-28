<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class BruteforceStatsWidget extends BaseWidget
{
    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 2;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $stats = $client->get('/bruteforce/stats') ?? [];

        return [
            Stat::make(__('Tracked IPs'), (string) ($stats['tracked_ips'] ?? 0))
                ->icon('heroicon-o-eye')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs'])
                ->color('info'),
            Stat::make(__('Blocked'), (string) ($stats['blocked_count'] ?? 0))
                ->icon('heroicon-o-no-symbol')
                ->color(($stats['blocked_count'] ?? 0) > 0 ? 'danger' : 'success')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
        ];
    }
}
