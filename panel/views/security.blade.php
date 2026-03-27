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
            :active="$activeTab === 'waf'"
            wire:click="$set('activeTab', 'waf')"
            icon="heroicon-o-shield-exclamation"
        >
            {{ __('WAF') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'firewall'"
            wire:click="$set('activeTab', 'firewall')"
            icon="heroicon-o-fire"
        >
            {{ __('Firewall') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'bruteforce'"
            wire:click="$set('activeTab', 'bruteforce')"
            icon="heroicon-o-key"
        >
            {{ __('Brute-Force') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'proactive'"
            wire:click="$set('activeTab', 'proactive')"
            icon="heroicon-o-bolt"
        >
            {{ __('Proactive') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'webshield'"
            wire:click="$set('activeTab', 'webshield')"
            icon="heroicon-o-globe-alt"
        >
            {{ __('WebShield') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'threatintel'"
            wire:click="$set('activeTab', 'threatintel')"
            icon="heroicon-o-globe-americas"
        >
            {{ __('Threat Intel') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'users'"
            wire:click="$set('activeTab', 'users')"
            icon="heroicon-o-users"
        >
            {{ __('Users') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'cleanup'"
            wire:click="$set('activeTab', 'cleanup')"
            icon="heroicon-o-sparkles"
        >
            {{ __('Cleanup') }}
        </x-filament::tabs.item>

        <x-filament::tabs.item
            :active="$activeTab === 'rules'"
            wire:click="$set('activeTab', 'rules')"
            icon="heroicon-o-document-text"
        >
            {{ __('Rules') }}
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

    @elseif($activeTab === 'waf')
        @php
            $wafStats = $this->getWafStats();
            $wafRules = $this->getWafRules();
        @endphp
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <x-filament::section>
                <div class="text-center">
                    <div class="text-3xl font-bold">{{ $wafStats['total_events_24h'] ?? 0 }}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Events (24h)') }}</div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-3xl font-bold">{{ $wafStats['blocked_24h'] ?? 0 }}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Blocked (24h)') }}</div>
                </div>
            </x-filament::section>
        </div>

        {{ $this->table }}

        @if(!empty($wafRules['rule_files']))
        <x-filament::section>
            <x-slot name="heading">{{ __('Rule Files') }}</x-slot>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-gray-500 dark:text-gray-400 border-b dark:border-white/10">
                            <th class="py-2 px-3 font-medium">{{ __('File') }}</th>
                            <th class="py-2 px-3 font-medium text-right">{{ __('Size') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($wafRules['rule_files'] as $rf)
                        <tr class="border-b dark:border-white/10">
                            <td class="py-2 px-3 font-mono text-xs">{{ $rf['file'] ?? '' }}</td>
                            <td class="py-2 px-3 text-right text-gray-500">{{ number_format($rf['size'] ?? 0) }} bytes</td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if(!empty($wafRules['disabled_rules']))
                <div class="mt-3 text-sm text-gray-500">
                    {{ __('Disabled rules') }}: {{ implode(', ', $wafRules['disabled_rules']) }}
                </div>
            @endif
        </x-filament::section>
        @endif

    @elseif($activeTab === 'bruteforce')
        @php $bfStats = $this->getBruteforceStats(); @endphp
        @if(!empty($bfStats))
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <x-filament::section>
                <div class="text-center">
                    <div class="text-3xl font-bold">{{ $bfStats['tracked_ips'] ?? 0 }}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Tracked IPs') }}</div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-3xl font-bold">{{ $bfStats['blocked_count'] ?? 0 }}</div>
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Blocked Count') }}</div>
                </div>
            </x-filament::section>
        </div>
        @else
        <x-filament::section>
            <div class="text-center text-gray-500 py-4">
                <p class="font-semibold">{{ __('Brute-force protection not enabled') }}</p>
                <p class="text-sm">{{ __('Enable it in the Overview tab') }}</p>
            </div>
        </x-filament::section>
        @endif

        {{ $this->table }}

    @elseif($activeTab === 'proactive')
        @php
            $proStatus = $this->getProactiveStatus();
            $kills = $this->getProactiveKills();
        @endphp
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Process Killer') }}</div>
                    <div class="text-lg font-bold {{ ($proStatus['process_kill_enabled'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($proStatus['process_kill_enabled'] ?? false) ? __('Active') : __('Disabled') }}
                    </div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Processes Killed') }}</div>
                    <div class="text-3xl font-bold">{{ $proStatus['process_kill_count'] ?? 0 }}</div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('PHP Hardening') }}</div>
                    <div class="text-lg font-bold {{ ($proStatus['php_hardening_enabled'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($proStatus['php_hardening_enabled'] ?? false) ? __('Active') : __('Disabled') }}
                    </div>
                </div>
            </x-filament::section>
        </div>

        <x-filament::section>
            <x-slot name="heading">{{ __('PHP-FPM Pools') }}</x-slot>
            {{ $this->table }}
        </x-filament::section>

        @if(!empty($kills))
        <x-filament::section>
            <x-slot name="heading">{{ __('Recent Process Kills') }}</x-slot>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-gray-500 dark:text-gray-400 border-b dark:border-white/10">
                            <th class="py-2 px-3">{{ __('PID') }}</th>
                            <th class="py-2 px-3">{{ __('User') }}</th>
                            <th class="py-2 px-3">{{ __('Score') }}</th>
                            <th class="py-2 px-3">{{ __('Reason') }}</th>
                            <th class="py-2 px-3">{{ __('Result') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($kills as $kill)
                        <tr class="border-b dark:border-white/10">
                            <td class="py-2 px-3 font-mono">{{ $kill['pid'] ?? '' }}</td>
                            <td class="py-2 px-3">{{ $kill['username'] ?? '' }}</td>
                            <td class="py-2 px-3 font-bold">{{ $kill['score'] ?? '' }}</td>
                            <td class="py-2 px-3 text-xs">{{ $kill['reason'] ?? '' }}</td>
                            <td class="py-2 px-3">
                                @if($kill['success'] ?? false)
                                    <span class="text-success-600">{{ __('Killed') }}</span>
                                @else
                                    <span class="text-danger-600">{{ __('Failed') }}</span>
                                @endif
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </x-filament::section>
        @endif

    @elseif($activeTab === 'webshield')
        @php $wsStatus = $this->getWebshieldStatus(); @endphp
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Installed') }}</div>
                    <div class="text-lg font-bold {{ ($wsStatus['installed'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($wsStatus['installed'] ?? false) ? __('Yes') : __('No') }}
                    </div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Rate Limiting') }}</div>
                    <div class="text-lg font-bold {{ ($wsStatus['rate_limiting'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($wsStatus['rate_limiting'] ?? false) ? __('On') : __('Off') }}
                    </div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Bot Filtering') }}</div>
                    <div class="text-lg font-bold {{ ($wsStatus['bot_filtering'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($wsStatus['bot_filtering'] ?? false) ? __('On') : __('Off') }}
                    </div>
                </div>
            </x-filament::section>
            <x-filament::section>
                <div class="text-center">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{{ __('Blocked IPs') }}</div>
                    <div class="text-3xl font-bold">{{ $wsStatus['blocked_ips_count'] ?? 0 }}</div>
                </div>
            </x-filament::section>
        </div>

        {{ $this->table }}

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
    @elseif($activeTab === 'rules')
        @php $rulesInfo = $this->getRulesInfo(); @endphp
        <x-filament::section>
            <x-slot name="heading">{{ __('Scanner Status') }}</x-slot>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('YARA') }}</span>
                    <div class="font-semibold {{ ($rulesInfo['yara_enabled'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($rulesInfo['yara_enabled'] ?? false) ? __('Enabled') : __('Disabled') }}
                    </div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('ClamAV') }}</span>
                    <div class="font-semibold {{ ($rulesInfo['clamav_enabled'] ?? false) ? 'text-success-600' : 'text-gray-400' }}">
                        {{ ($rulesInfo['clamav_enabled'] ?? false) ? __('Enabled') : __('Disabled') }}
                    </div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Active Scanners') }}</span>
                    <div class="font-semibold">{{ implode(', ', $rulesInfo['scanners'] ?? []) }}</div>
                </div>
                <div>
                    <span class="text-gray-500 dark:text-gray-400">{{ __('Rules Dir') }}</span>
                    <div class="font-mono text-xs">{{ $rulesInfo['yara_rules_dir'] ?? '?' }}</div>
                </div>
            </div>
        </x-filament::section>

        {{ $this->table }}

    @elseif($activeTab === 'config')
        @php $categories = \App\JabaliSecurity\Pages\Security::$configCategories; @endphp
        <div class="flex flex-wrap gap-2 mb-4">
            @foreach(array_keys($categories) as $cat)
                <button
                    wire:click="$set('configCategory', '{{ $cat }}')"
                    class="px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors
                        {{ $configCategory === $cat
                            ? 'bg-primary-500 text-white border-primary-500 dark:bg-primary-600'
                            : 'bg-white text-gray-600 border-gray-200 hover:border-primary-300 dark:bg-white/5 dark:text-gray-400 dark:border-white/10' }}"
                >
                    {{ __($cat) }}
                </button>
            @endforeach
        </div>

        {{ $this->table }}
    @else
        {{ $this->table }}
    @endif

    <x-filament-actions::modals />
</x-filament-panels::page>
