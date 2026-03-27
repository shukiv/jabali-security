<?php

declare(strict_types=1);

namespace App\JabaliSecurity\Widgets;

use App\JabaliSecurity\JabaliSecurityClient;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class RulesStatsWidget extends BaseWidget
{
    protected int|string|array $columnSpan = 'full';

    protected function getColumns(): int
    {
        return 4;
    }

    protected function getStats(): array
    {
        $client = new JabaliSecurityClient;
        $rules = $client->get('/rules') ?? [];

        return [
            Stat::make(__('YARA'), ($rules['yara_enabled'] ?? false) ? __('Enabled') : __('Disabled'))
                ->icon('heroicon-o-document-text')
                ->color(($rules['yara_enabled'] ?? false) ? 'success' : 'gray'),
            Stat::make(__('ClamAV'), ($rules['clamav_enabled'] ?? false) ? __('Enabled') : __('Disabled'))
                ->icon('heroicon-o-shield-check')
                ->color(($rules['clamav_enabled'] ?? false) ? 'success' : 'gray'),
            Stat::make(__('Scanners'), implode(', ', $rules['scanners'] ?? []))
                ->icon('heroicon-o-magnifying-glass')
                ->color('info'),
            Stat::make(__('Rules Dir'), $rules['yara_rules_dir'] ?? '?')
                ->icon('heroicon-o-folder')
                ->color('gray'),
        ];
    }
}
