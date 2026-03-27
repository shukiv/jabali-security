<x-filament-panels::page>
    <x-filament::section>
    <x-filament::tabs label="Security Management">
        <x-filament::tabs.item :active="$activeTab === 'overview'" wire:click="$set('activeTab', 'overview')" icon="heroicon-o-home">{{ __('Overview') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'incidents'" wire:click="$set('activeTab', 'incidents')" icon="heroicon-o-exclamation-triangle">{{ __('Incidents') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'quarantine'" wire:click="$set('activeTab', 'quarantine')" icon="heroicon-o-lock-closed">{{ __('Quarantine') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'blocklist'" wire:click="$set('activeTab', 'blocklist')" icon="heroicon-o-no-symbol">{{ __('Blocklist') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'waf'" wire:click="$set('activeTab', 'waf')" icon="heroicon-o-shield-exclamation">{{ __('WAF') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'firewall'" wire:click="$set('activeTab', 'firewall')" icon="heroicon-o-fire">{{ __('Firewall') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'bruteforce'" wire:click="$set('activeTab', 'bruteforce')" icon="heroicon-o-key">{{ __('Brute-Force') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'proactive'" wire:click="$set('activeTab', 'proactive')" icon="heroicon-o-bolt">{{ __('Proactive') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'webshield'" wire:click="$set('activeTab', 'webshield')" icon="heroicon-o-globe-alt">{{ __('WebShield') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'threatintel'" wire:click="$set('activeTab', 'threatintel')" icon="heroicon-o-globe-americas">{{ __('Threat Intel') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'users'" wire:click="$set('activeTab', 'users')" icon="heroicon-o-users">{{ __('Users') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'cleanup'" wire:click="$set('activeTab', 'cleanup')" icon="heroicon-o-sparkles">{{ __('Cleanup') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'rules'" wire:click="$set('activeTab', 'rules')" icon="heroicon-o-document-text">{{ __('Rules') }}</x-filament::tabs.item>
        <x-filament::tabs.item :active="$activeTab === 'config'" wire:click="$set('activeTab', 'config')" icon="heroicon-o-cog-6-tooth">{{ __('Configuration') }}</x-filament::tabs.item>
    </x-filament::tabs>
    </x-filament::section>

    @if($activeTab === 'overview')
        @php
            $status = $this->getStatusData();
            $config = $this->getConfigData();
            $modules = \App\JabaliSecurity\Pages\Security::getModuleToggles();
        @endphp
        @if(!empty($status))
            @livewire(\App\JabaliSecurity\Widgets\SecurityStatsWidget::class)

            <x-filament::section>
                <x-slot name="heading">{{ __('Protection Modules') }}</x-slot>
                @foreach($modules['core'] as $key => $mod)
                    @php $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']); @endphp
                    <x-filament::section aside compact>
                        <x-slot name="heading">{{ __($mod['label']) }}</x-slot>
                        <x-slot name="description">{{ __($mod['desc']) }}</x-slot>
                        <x-filament::button :color="$enabled ? 'success' : 'gray'" size="xs" wire:click="toggleModule('{{ $key }}')">
                            {{ $enabled ? __('Enabled') : __('Disabled') }}
                        </x-filament::button>
                    </x-filament::section>
                @endforeach
            </x-filament::section>

            <x-filament::section>
                <x-slot name="heading">{{ __('Advanced Protection') }}</x-slot>
                @foreach($modules['advanced'] as $key => $mod)
                    @php $enabled = in_array($config[$key] ?? 'no', ['yes', 'true', '1']); @endphp
                    <x-filament::section aside compact>
                        <x-slot name="heading">{{ __($mod['label']) }}</x-slot>
                        <x-slot name="description">{{ __($mod['desc']) }}</x-slot>
                        <x-filament::button :color="$enabled ? 'success' : 'gray'" size="xs" wire:click="toggleModule('{{ $key }}')">
                            {{ $enabled ? __('Enabled') : __('Disabled') }}
                        </x-filament::button>
                    </x-filament::section>
                @endforeach
            </x-filament::section>
        @else
            <x-filament::section>
                <x-slot name="heading">{{ __('Security daemon is not responding') }}</x-slot>
                <x-slot name="description">{{ __('Check that jabali-security service is running') }}</x-slot>
            </x-filament::section>
        @endif

    @elseif($activeTab === 'waf')
        @php $wafStats = $this->getWafStats(); @endphp
        @livewire(\App\JabaliSecurity\Widgets\WafStatsWidget::class)
        {{ $this->table }}

    @elseif($activeTab === 'bruteforce')
        @php $bfStats = $this->getBruteforceStats(); @endphp
        @if(!empty($bfStats))
            @livewire(\App\JabaliSecurity\Widgets\BruteforceStatsWidget::class)
        @else
            <x-filament::section>
                <x-slot name="heading">{{ __('Brute-force protection not enabled') }}</x-slot>
                <x-slot name="description">{{ __('Enable it in the Overview tab') }}</x-slot>
            </x-filament::section>
        @endif
        {{ $this->table }}

    @elseif($activeTab === 'proactive')
        @livewire(\App\JabaliSecurity\Widgets\ProactiveStatsWidget::class)
        <x-filament::section>
            <x-slot name="heading">{{ __('PHP-FPM Pools') }}</x-slot>
            {{ $this->table }}
        </x-filament::section>

    @elseif($activeTab === 'webshield')
        @livewire(\App\JabaliSecurity\Widgets\WebshieldStatsWidget::class)
        {{ $this->table }}

    @elseif($activeTab === 'firewall')
        @php $fw = $this->getFirewallStatus(); @endphp
        <x-filament::section>
            <x-slot name="heading">{{ __('UFW Status') }}</x-slot>
            <x-slot name="headerEnd">
                @if($fw['active'] ?? false)
                    <x-filament::button color="danger" size="sm" wire:click="disableFirewall" wire:confirm="{{ __('Disable the firewall?') }}">
                        {{ __('Disable') }}
                    </x-filament::button>
                @else
                    <x-filament::button color="success" size="sm" wire:click="enableFirewall">
                        {{ __('Enable') }}
                    </x-filament::button>
                @endif
            </x-slot>
            <x-filament::badge :color="($fw['active'] ?? false) ? 'success' : 'danger'">
                {{ ($fw['active'] ?? false) ? __('Active') : __('Inactive') }}
            </x-filament::badge>
            @if($fw['active'] ?? false)
                <x-filament::badge color="gray">
                    {{ __('Default') }}: {{ $fw['default_incoming'] ?? '?' }} / {{ $fw['default_outgoing'] ?? '?' }}
                </x-filament::badge>
            @endif
        </x-filament::section>
        {{ $this->table }}

    @elseif($activeTab === 'rules')
        @livewire(\App\JabaliSecurity\Widgets\RulesStatsWidget::class)
        {{ $this->table }}

    @elseif($activeTab === 'config')
        @php
            $categories = \App\JabaliSecurity\Pages\Security::$configCategories;
            $boolKeys = \App\JabaliSecurity\Pages\Security::$booleanKeys;
            $selectKeys = \App\JabaliSecurity\Pages\Security::$selectKeys;
            $configData = $this->getConfigData();
        @endphp
        <x-filament::section>
        <x-filament::tabs label="Config categories">
            @foreach(array_keys($categories) as $cat)
                <x-filament::tabs.item
                    :active="$configCategory === $cat"
                    wire:click="$set('configCategory', '{{ $cat }}')"
                >
                    {{ __($cat) }}
                </x-filament::tabs.item>
            @endforeach
        </x-filament::tabs>
        </x-filament::section>

        <x-filament::section>
            @foreach($categories[$configCategory] ?? [] as $key)
                @php $val = $configData[$key] ?? ''; @endphp
                <x-filament::section aside compact>
                    <x-slot name="heading">{{ $key }}</x-slot>
                    @if(in_array($key, $boolKeys))
                        <select x-on:change="$wire.updateConfigValue('{{ $key }}', $event.target.value)" class="fi-select-input">
                            <option value="yes" {{ in_array($val, ['yes', 'true', '1']) ? 'selected' : '' }}>yes</option>
                            <option value="no" {{ !in_array($val, ['yes', 'true', '1']) ? 'selected' : '' }}>no</option>
                        </select>
                    @elseif(isset($selectKeys[$key]))
                        <select x-on:change="$wire.updateConfigValue('{{ $key }}', $event.target.value)" class="fi-select-input">
                            @foreach($selectKeys[$key] as $opt)
                                <option value="{{ $opt }}" {{ $val === $opt ? 'selected' : '' }}>{{ $opt }}</option>
                            @endforeach
                        </select>
                    @else
                        <x-filament::badge color="gray">{{ $val }}</x-filament::badge>
                    @endif
                </x-filament::section>
            @endforeach
        </x-filament::section>

    @else
        {{ $this->table }}
    @endif

    <x-filament-actions::modals />
</x-filament-panels::page>
