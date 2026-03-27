<x-filament-panels::page>
    @livewire(\App\JabaliSecurity\Widgets\SecurityStatsWidget::class)

    <x-filament::tabs label="Security Management">
        <x-filament::tabs.item
            :active="$activeTab === 'overview'"
            wire:click="$set('activeTab', 'overview')"
            icon="heroicon-o-home"
        >
            {{ __('Overview') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'incidents'"
            wire:click="$set('activeTab', 'incidents')"
            icon="heroicon-o-exclamation-triangle"
        >
            {{ __('Incidents') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'quarantine'"
            wire:click="$set('activeTab', 'quarantine')"
            icon="heroicon-o-lock-closed"
        >
            {{ __('Quarantine') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'blocklist'"
            wire:click="$set('activeTab', 'blocklist')"
            icon="heroicon-o-no-symbol"
        >
            {{ __('Blocklist') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'firewall'"
            wire:click="$set('activeTab', 'firewall')"
            icon="heroicon-o-fire"
        >
            {{ __('Firewall') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'config'"
            wire:click="$set('activeTab', 'config')"
            icon="heroicon-o-cog-6-tooth"
        >
            {{ __('Configuration') }}
        </x-filament::tabs.item>
    </x-filament::tabs>

    @if($activeTab === 'overview')
        @php
            $status = $this->getStatusData();
            $config = $this->getConfigData();
            $modules = \App\JabaliSecurity\Pages\Security::getModuleToggles();
        @endphp
        @if(!empty($status))
        <x-filament::section>
            <x-slot name="heading">{{ __('Daemon Status') }}</x-slot>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Version') }}</span>
                    <div class="font-mono font-semibold">{{ $status['version'] ?? '?' }}</div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Uptime') }}</span>
                    @php
                        $u = (int)($status['uptime_seconds'] ?? 0);
                        $uptime = sprintf('%dh %dm %ds', intdiv($u, 3600), intdiv($u % 3600, 60), $u % 60);
                    @endphp
                    <div class="font-mono font-semibold">{{ $uptime }}</div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Memory') }}</span>
                    <div class="font-mono font-semibold">{{ round($status['memory_mb'] ?? 0, 1) }} MB</div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Workers') }}</span>
                    <div class="font-mono font-semibold">{{ $status['workers'] ?? 0 }}</div>
                </div>
            </div>
        </x-filament::section>

        <x-filament::section>
            <x-slot name="heading">{{ __('Protection Modules') }}</x-slot>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                @foreach($modules['core'] as $key => $mod)
                    @php $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']); @endphp
                    <div class="flex items-center justify-between rounded-lg border border-gray-200 dark:border-white/10 px-4 py-3">
                        <div class="flex items-center gap-3">
                            <div class="w-2.5 h-2.5 rounded-full {{ $enabled ? 'bg-success-500' : 'bg-gray-400' }}"></div>
                            <div>
                                <div class="text-sm font-medium">{{ __($mod['label']) }}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400">{{ __($mod['desc']) }}</div>
                            </div>
                        </div>
                        <button
                            wire:click="toggleModule('{{ $key }}')"
                            class="px-3 py-1 text-xs font-medium rounded-md {{ $enabled ? 'bg-success-500/10 text-success-600 dark:text-success-400' : 'bg-gray-100 text-gray-500 dark:bg-white/5 dark:text-gray-400' }}"
                        >
                            {{ $enabled ? __('Enabled') : __('Disabled') }}
                        </button>
                    </div>
                @endforeach
            </div>
        </x-filament::section>

        <x-filament::section>
            <x-slot name="heading">{{ __('Advanced Protection') }}</x-slot>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                @foreach($modules['advanced'] as $key => $mod)
                    @php $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']); @endphp
                    <div class="flex items-center justify-between rounded-lg border border-gray-200 dark:border-white/10 px-4 py-3">
                        <div class="flex items-center gap-3">
                            <div class="w-2.5 h-2.5 rounded-full {{ $enabled ? 'bg-success-500' : 'bg-gray-400' }}"></div>
                            <div>
                                <div class="text-sm font-medium">{{ __($mod['label']) }}</div>
                                <div class="text-xs text-gray-500 dark:text-gray-400">{{ __($mod['desc']) }}</div>
                            </div>
                        </div>
                        <button
                            wire:click="toggleModule('{{ $key }}')"
                            class="px-3 py-1 text-xs font-medium rounded-md {{ $enabled ? 'bg-success-500/10 text-success-600 dark:text-success-400' : 'bg-gray-100 text-gray-500 dark:bg-white/5 dark:text-gray-400' }}"
                        >
                            {{ $enabled ? __('Enabled') : __('Disabled') }}
                        </button>
                    </div>
                @endforeach
            </div>
        </x-filament::section>

        @else
            <x-filament::section>
                <div class="text-center text-gray-500 py-8">
                    <x-heroicon-o-exclamation-circle class="w-12 h-12 mx-auto mb-2 text-danger-500" />
                    <p class="font-semibold">{{ __('Security daemon is not responding') }}</p>
                    <p class="text-sm">{{ __('Check that jabali-security service is running') }}</p>
                </div>
            </x-filament::section>
        @endif

    @elseif($activeTab === 'firewall')
        @php $fw = $this->getFirewallStatus(); @endphp
        <x-filament::section>
            <x-slot name="heading">{{ __('UFW Status') }}</x-slot>
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-4">
                    <span class="inline-flex items-center gap-1.5 text-sm font-medium {{ ($fw['active'] ?? false) ? 'text-success-600' : 'text-danger-600' }}">
                        @if($fw['active'] ?? false)
                            <x-heroicon-o-check-circle class="w-5 h-5" /> {{ __('Active') }}
                        @else
                            <x-heroicon-o-x-circle class="w-5 h-5" /> {{ __('Inactive') }}
                        @endif
                    </span>
                    @if($fw['active'] ?? false)
                        <span class="text-sm text-gray-500">
                            {{ __('Default') }}: {{ $fw['default_incoming'] ?? '?' }} / {{ $fw['default_outgoing'] ?? '?' }}
                        </span>
                    @endif
                </div>
                <div class="flex gap-2">
                    @if($fw['active'] ?? false)
                        <x-filament::button color="danger" size="sm" wire:click="disableFirewall" wire:confirm="{{ __('Disable the firewall?') }}">
                            {{ __('Disable') }}
                        </x-filament::button>
                    @else
                        <x-filament::button color="success" size="sm" wire:click="enableFirewall">
                            {{ __('Enable') }}
                        </x-filament::button>
                    @endif
                </div>
            </div>
        </x-filament::section>

        {{ $this->table }}
    @else
        {{ $this->table }}
    @endif

    <x-filament-actions::modals />
</x-filament-panels::page>
