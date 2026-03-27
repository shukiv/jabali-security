<div class="space-y-4 text-sm">
    <div class="grid grid-cols-2 gap-4">
        <div>
            <span class="text-gray-500 dark:text-gray-400">{{ __('Incidents') }}</span>
            <div class="font-bold text-lg">{{ $user['incident_count'] ?? 0 }}</div>
        </div>
        <div>
            <span class="text-gray-500 dark:text-gray-400">{{ __('Quarantined') }}</span>
            <div class="font-bold text-lg">{{ $user['quarantine_count'] ?? 0 }}</div>
        </div>
    </div>

    @if(!empty($user['incidents']))
    <div>
        <h4 class="font-semibold mb-2">{{ __('Recent Incidents') }}</h4>
        <div class="space-y-2">
            @foreach(array_slice($user['incidents'], 0, 10) as $inc)
            <div class="rounded-lg border dark:border-white/10 p-3">
                <div class="flex justify-between items-start">
                    <div class="font-mono text-xs text-gray-500">{{ $inc['path'] ?? '' }}</div>
                    <span class="px-2 py-0.5 text-xs rounded-full {{ ($inc['severity'] ?? '') === 'critical' || ($inc['severity'] ?? '') === 'high' ? 'bg-danger-100 text-danger-700 dark:bg-danger-500/20 dark:text-danger-400' : 'bg-warning-100 text-warning-700 dark:bg-warning-500/20 dark:text-warning-400' }}">
                        {{ $inc['severity'] ?? '' }} ({{ $inc['total_score'] ?? 0 }})
                    </span>
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ $inc['action_taken'] ?? '' }} | {{ $inc['timestamp'] ?? '' }}</div>
            </div>
            @endforeach
        </div>
    </div>
    @endif

    @if(!empty($user['quarantine']))
    <div>
        <h4 class="font-semibold mb-2">{{ __('Quarantined Files') }}</h4>
        @foreach(array_slice($user['quarantine'], 0, 5) as $q)
        <div class="font-mono text-xs text-gray-500 py-1">{{ $q['original_path'] ?? '' }}</div>
        @endforeach
    </div>
    @endif
</div>
