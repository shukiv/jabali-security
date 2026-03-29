<div class="grid grid-cols-1 gap-3 sm:grid-cols-{{ count($stats) }} lg:grid-cols-{{ count($stats) }}">
    @foreach($stats as $stat)
        <x-filament::section
            :icon="$stat['icon']"
            :icon-color="$stat['color']"
            class="!px-2 !py-1"
        >
            <x-slot name="heading">
                <div class="flex items-center gap-2">
                    <span class="fi-section-header-heading">{{ $stat['value'] }}</span>
                    <span class="fi-section-header-description">{{ $stat['label'] }}</span>
                </div>
            </x-slot>
            <x-slot name="description"></x-slot>
        </x-filament::section>
    @endforeach
</div>
