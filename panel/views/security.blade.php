<x-filament-panels::page>
    {{ $this->securitySchema }}

    <x-filament-actions::modals />

    <style>
        #attack-mode-card,
        #attack-mode-card > div,
        #attack-mode-card .fi-section-content-ctn,
        #attack-mode-card .fi-section-header {
            background-color: #dc2626 !important;
            border-color: #b91c1c !important;
        }
        #attack-mode-card * {
            color: white !important;
        }
        #attack-mode-card .fi-btn {
            background-color: white !important;
            color: #dc2626 !important;
        }
    </style>
</x-filament-panels::page>
