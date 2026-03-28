<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class ProactiveStatsWidget extends BaseWidget
{
    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 3;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $status = $client->get('/proactive/status') ?? [];

        return [
            Stat::make(__('Process Killer'), ($status['process_kill_enabled'] ?? false) ? __('Active') : __('Disabled'))
                ->icon('heroicon-o-bolt')
                ->color(($status['process_kill_enabled'] ?? false) ? 'success' : 'gray')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
            Stat::make(__('Processes Killed'), (string) ($status['process_kill_count'] ?? 0))
                ->icon('heroicon-o-x-circle')
                ->color(($status['process_kill_count'] ?? 0) > 0 ? 'warning' : 'success')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
            Stat::make(__('PHP Hardening'), ($status['php_hardening_enabled'] ?? false) ? __('Active') : __('Disabled'))
                ->icon('heroicon-o-shield-check')
                ->color(($status['php_hardening_enabled'] ?? false) ? 'success' : 'gray')
                ->extraAttributes(['class' => '!p-2 [&_dd]:!text-lg [&_p]:!text-xs']),
        ];
    }
}
