# phpwarden/laravel

`php artisan phpwarden:scan` — scan your Laravel app's `composer.lock` for
known-vulnerable packages, ranked by real-world exploitation (CISA KEV + EPSS),
and fail the build on what matters.

Thin Artisan wrapper around the [phpwarden](https://github.com/oroma-alfred/phpwarden)
CLI (Apache-2.0, zero-dependency Python). It depends on
[`phpwarden/phpwarden`](https://packagist.org/packages/phpwarden/phpwarden),
whose `vendor/bin/phpwarden` shim finds a `phpwarden` already on `PATH` or
installs the CLI into a private virtualenv on first run (Python 3.8+ required).

Supports Laravel 10, 11, 12 and 13 on PHP 8.1+ (Laravel 13 itself needs PHP 8.3).

## Install

```bash
composer require --dev phpwarden/laravel
```

The service provider is auto-discovered. Optionally publish the config:

```bash
php artisan vendor:publish --tag=phpwarden-config
```

## Usage

```bash
php artisan phpwarden:scan                       # table, exit 1 on any finding
php artisan phpwarden:scan --json                # the CLI's JSON document
php artisan phpwarden:scan --no-reachability     # faster: skip "is it referenced in code?"
php artisan phpwarden:scan --fail-on=exploited   # exit 1 only for CISA-KEV findings
php artisan phpwarden:scan --lockfile=apps/api/composer.lock
```

Sample output (`--no-reachability` shows `unknown` in the Reach column):

```
18 vulnerable package(s) in composer.lock; 0 actively exploited (KEV). Ranked by exploitation risk, then reachability:
+---------------------+-----------+----------------+--------------+---------+---------+---------------+
| Package             | Installed | CVE            | Severity     | Risk    | Reach   | Fixed in      |
+---------------------+-----------+----------------+--------------+---------+---------+---------------+
| symfony/http-kernel | 5.4.0     | CVE-2022-24894 | medium (5.9) | EPSS 4% | unknown | 4.4.50, 5.4.20|
| guzzlehttp/guzzle   | 7.4.0     | CVE-2022-31091 | high (8.1)   | EPSS 2% | unknown | 6.5.8, 7.4.5  |
...
```

### Options

| Option               | Default                | Meaning                                                                                 |
|----------------------|------------------------|-----------------------------------------------------------------------------------------|
| `--lockfile=PATH`    | `base_path('composer.lock')` | Lockfile to scan.                                                                 |
| `--json`             | off                    | Print the CLI's JSON (`{"lockfile": …, "vulnerable": [...]}`) instead of a table.        |
| `--no-reachability`  | off                    | Skip checking whether each vulnerable package is referenced in your code.               |
| `--fail-on=POLICY`   | `exposed`              | `exposed` (any finding), `exploited` (only findings with `known_exploited: true`), `never`. |

Defaults, the binary path and a timeout can be set in `config/phpwarden.php`
or via `PHPWARDEN_LARAVEL_BIN`, `PHPWARDEN_LOCKFILE`, `PHPWARDEN_FAIL_ON`,
`PHPWARDEN_NO_REACHABILITY`, `PHPWARDEN_TIMEOUT`.

### Exit codes

The command returns the CLI's exit code, adjusted only by `--fail-on`:

| Code | Meaning                                                                   |
|------|---------------------------------------------------------------------------|
| 0    | clean — or findings that the `--fail-on` policy tolerates                 |
| 1    | vulnerable packages found (with `--fail-on=exploited`: a KEV finding)     |
| 4    | lockfile missing, unreadable or not a `composer.lock`                     |
| 5    | `--report-to` upload failed (when configured through the shim's env)      |
| 64   | usage error (bad `--fail-on`, unknown flag)                               |
| 127  | the phpwarden CLI could not be found or installed by the shim             |

Codes other than 0/1 always propagate, whatever `--fail-on` says: a scan that
did not run must not pass silently.

## Scheduling

Scan nightly and let the exit code reach your scheduler's failure hooks
(`routes/console.php`, Laravel 11+):

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('phpwarden:scan --no-reachability')
    ->dailyAt('06:00')
    ->onFailure(fn () => \Log::alert('phpwarden found vulnerable Composer packages'));
```

On Laravel 10 put the same call in `App\Console\Kernel::schedule()` with
`$schedule->command(...)`.

## In CI

Any runner works: `php artisan phpwarden:scan` after `composer install`. The
first run installs the Python CLI (needs `python3`), so cache
`vendor/phpwarden/.venv` or `pip install "phpwarden>=2,<3"` in the image.
GitHub users can use the
[phpwarden action](https://github.com/oroma-alfred/phpwarden-action)
instead; GitLab CI and Bitbucket templates live in the
[main repo](https://github.com/oroma-alfred/phpwarden/tree/main/integrations).

## Testing this package

```bash
composer install
vendor/bin/phpunit
```

The tests run the real CLI against a deliberately outdated lockfile
(`tests/fixtures/composer.lock`) through orchestra/testbench.

## License

Apache-2.0. phpwarden is open-core: the CLI and this package are free; the
exploitation-ranked feed and the dashboard at [phpwarden.io](https://phpwarden.io)
are the paid part.
