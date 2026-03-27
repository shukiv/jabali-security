<x-filament-panels::page>
    @if($activeTab === 'overview')
        @livewire(\App\JabaliSecurity\Widgets\SecurityStatsWidget::class)
    @elseif($activeTab === 'waf')
        @livewire(\App\JabaliSecurity\Widgets\WafStatsWidget::class)
    @elseif($activeTab === 'bruteforce')
        @livewire(\App\JabaliSecurity\Widgets\BruteforceStatsWidget::class)
    @elseif($activeTab === 'proactive')
        @livewire(\App\JabaliSecurity\Widgets\ProactiveStatsWidget::class)
    @elseif($activeTab === 'webshield')
        @livewire(\App\JabaliSecurity\Widgets\WebshieldStatsWidget::class)
    @elseif($activeTab === 'rules')
        @livewire(\App\JabaliSecurity\Widgets\RulesStatsWidget::class)
    @endif

    {{ $this->securitySchema }}

    <x-filament-actions::modals />
</x-filament-panels::page>
