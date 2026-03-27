<?php

declare(strict_types=1);

namespace App\JabaliSecurity;

use App\JabaliSecurity\Pages\Security;
use Filament\Contracts\Plugin;
use Filament\Panel;
use Illuminate\Support\Facades\View;

class JabaliSecurityPlugin implements Plugin
{
    public static function make(): static
    {
        return app(static::class);
    }

    public static function get(): static
    {
        return filament(static::class);
    }

    public function getId(): string
    {
        return 'jabali-security';
    }

    public function register(Panel $panel): void
    {
        $panel->pages([
            Security::class,
        ]);
    }

    public function boot(Panel $panel): void
    {
        $viewPath = app_path('JabaliSecurity/views');
        if (is_dir($viewPath)) {
            View::addNamespace('jabali-security', $viewPath);
        }
    }
}
