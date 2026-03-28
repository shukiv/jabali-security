<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class WebshieldStatsWidget extends BaseWidget
{
    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 4;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $status = $client->get('/webshield/status') ?? [];

        return [
            Stat::make(__('Installed'), ($status['installed'] ?? false) ? __('Yes') : __('No'))
                ->icon('heroicon-o-globe-alt')
                ->color(($status['installed'] ?? false) ? 'success' : 'gray')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
            Stat::make(__('Rate Limiting'), ($status['rate_limiting'] ?? false) ? __('On') : __('Off'))
                ->icon('heroicon-o-clock')
                ->color(($status['rate_limiting'] ?? false) ? 'success' : 'gray')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
            Stat::make(__('Bot Filtering'), ($status['bot_filtering'] ?? false) ? __('On') : __('Off'))
                ->icon('heroicon-o-funnel')
                ->color(($status['bot_filtering'] ?? false) ? 'success' : 'gray')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
            Stat::make(__('Blocked IPs'), (string) ($status['blocked_ips_count'] ?? 0))
                ->icon('heroicon-o-no-symbol')
                ->color(($status['blocked_ips_count'] ?? 0) > 0 ? 'danger' : 'success')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
        ];
    }
}
