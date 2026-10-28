<?php

declare(strict_types=1);

namespace Phpwarden\Laravel\Tests;

use Orchestra\Testbench\TestCase;
use Phpwarden\Laravel\PhpwardenServiceProvider;

final class ScanCommandTest extends TestCase
{
    private const FIXTURE = __DIR__ . '/fixtures/composer.lock';

    protected function getPackageProviders($app): array
    {
        return [PhpwardenServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        // Testbench's skeleton app has no vendor/bin; point at this package's own
        // install of the phpwarden/phpwarden shim (or a CLI on PATH, so CI can
        // `pip install phpwarden` without Composer resolving the shim).
        $shim = dirname(__DIR__) . '/vendor/bin/phpwarden';
        $app['config']->set('phpwarden.binary', is_file($shim) ? $shim : 'phpwarden');
        $app['config']->set('phpwarden.lockfile', self::FIXTURE);
    }

    public function test_vulnerable_lockfile_fails_and_names_the_cve(): void
    {
        $this->artisan('phpwarden:scan', ['--no-reachability' => true])
            ->expectsOutputToContain('CVE-2022-31091')
            ->assertExitCode(1);
    }

    public function test_json_output_is_the_cli_document(): void
    {
        $this->artisan('phpwarden:scan', ['--json' => true, '--no-reachability' => true])
            ->expectsOutputToContain('"cve": "CVE-2022-31091"')
            ->assertExitCode(1);
    }

    public function test_fail_on_never_passes_but_still_reports(): void
    {
        $this->artisan('phpwarden:scan', ['--fail-on' => 'never', '--no-reachability' => true])
            ->expectsOutputToContain('CVE-2022-31091')
            ->assertExitCode(0);
    }

    public function test_fail_on_exploited_only_fails_on_kev(): void
    {
        // The fixture's advisories are not in CISA KEV, so this policy passes.
        $this->artisan('phpwarden:scan', ['--fail-on' => 'exploited', '--no-reachability' => true])
            ->assertExitCode(0);
    }

    public function test_missing_lockfile_is_an_input_error(): void
    {
        $this->artisan('phpwarden:scan', ['--lockfile' => __DIR__ . '/fixtures/nope.lock'])
            ->assertExitCode(4);
    }

    public function test_bad_fail_on_is_a_usage_error(): void
    {
        $this->artisan('phpwarden:scan', ['--fail-on' => 'sometimes'])
            ->assertExitCode(64);
    }
}
