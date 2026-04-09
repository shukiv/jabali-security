<div>
    {{-- Progress bar while scanning --}}
    @if($this->scanning)
        <div wire:poll.1s="processNextScan" class="mb-4 rounded-xl border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-900">
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                    <x-filament::loading-indicator class="h-5 w-5 text-primary-500" />
                    <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                        {{ __('Scanning users: :progress', ['progress' => $this->scanProgress]) }}
                    </span>
                </div>
                <span class="text-sm text-gray-500 dark:text-gray-400">{{ $this->scanPercent }}%</span>
            </div>
            <div class="h-2 w-full overflow-hidden rounded-full bg-gray-200 dark:bg-gray-700">
                <div class="h-full rounded-full bg-primary-500 transition-all duration-500"
                     style="width: {{ $this->scanPercent }}%"></div>
            </div>
        </div>
    @endif

    {{-- Results summary --}}
    @if($this->showResults)
        @php $results = $this->totalResults; @endphp
        <div class="mb-4 rounded-xl border {{ $results['threats'] > 0 ? 'border-danger-300 bg-danger-50 dark:border-danger-700 dark:bg-danger-950/20' : 'border-success-300 bg-success-50 dark:border-success-700 dark:bg-success-950/20' }} p-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    @if($results['threats'] > 0)
                        <x-filament::icon icon="heroicon-o-shield-exclamation" class="h-6 w-6 text-danger-500" />
                    @else
                        <x-filament::icon icon="heroicon-o-shield-check" class="h-6 w-6 text-success-500" />
                    @endif
                    <div>
                        <p class="font-medium text-gray-900 dark:text-white">
                            {{ __('Scan Complete') }}
                        </p>
                        <p class="text-sm text-gray-600 dark:text-gray-400">
                            {{ __(':users users scanned, :files files checked, :threats threats found', [
                                'users' => $results['users'],
                                'files' => number_format($results['files']),
                                'threats' => $results['threats'],
                            ]) }}
                        </p>
                    </div>
                </div>
                <button wire:click="dismissResults" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    <x-filament::icon icon="heroicon-o-x-mark" class="h-5 w-5" />
                </button>
            </div>

            @if($results['threats'] > 0)
                <div class="mt-3 space-y-1 text-sm text-gray-700 dark:text-gray-300">
                    @foreach($this->scanJobs as $username => $job)
                        @if(($job['threats_count'] ?? 0) > 0)
                            <div class="flex items-center gap-2">
                                <span class="inline-flex items-center rounded-md bg-danger-100 px-2 py-0.5 text-xs font-medium text-danger-700 dark:bg-danger-900/30 dark:text-danger-400">
                                    {{ $job['threats_count'] }} {{ __('threats') }}
                                </span>
                                <span class="font-mono">{{ $username }}</span>
                                <span class="text-gray-400">/home/{{ $username }}</span>
                            </div>
                            @foreach(array_slice($job['threats'], 0, 5) as $threat)
                                <div class="ml-6 text-xs text-gray-500 dark:text-gray-400">
                                    {{ basename($threat['path'] ?? '') }}
                                    (score: {{ $threat['score'] ?? 0 }})
                                    @if(!empty($threat['findings']))
                                        — {{ collect($threat['findings'])->pluck('rule')->implode(', ') }}
                                    @endif
                                </div>
                            @endforeach
                            @if(count($job['threats']) > 5)
                                <div class="ml-6 text-xs text-gray-400">
                                    {{ __('... and :more more', ['more' => count($job['threats']) - 5]) }}
                                </div>
                            @endif
                        @endif
                    @endforeach
                </div>
            @endif
        </div>
    @endif

    {{-- Table --}}
    {{ $this->table }}
</div>
