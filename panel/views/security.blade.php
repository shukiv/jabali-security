<x-filament-panels::page>
    {{ $this->securitySchema }}

    <x-filament-actions::modals />

    <style>
        [data-attack-mode] { background: #991b1b !important; border-color: #7f1d1d !important; }
        [data-attack-mode] > div { background: transparent !important; }
        [data-attack-mode] h2,
        [data-attack-mode] h3,
        [data-attack-mode] p,
        [data-attack-mode] span,
        [data-attack-mode] svg { color: #fecaca !important; }
        [data-attack-mode] h2 { color: #ffffff !important; }
    </style>
</x-filament-panels::page>
