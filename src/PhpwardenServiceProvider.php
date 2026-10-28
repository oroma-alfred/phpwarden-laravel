<?php

declare(strict_types=1);

namespace Phpwarden\Laravel;

use Illuminate\Support\ServiceProvider;
use Phpwarden\Laravel\Console\ScanCommand;

final class PhpwardenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/phpwarden.php', 'phpwarden');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/phpwarden.php' => $this->app->configPath('phpwarden.php'),
            ], 'phpwarden-config');

            $this->commands([ScanCommand::class]);
        }
    }
}
