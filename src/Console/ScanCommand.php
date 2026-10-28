<?php

declare(strict_types=1);

namespace Phpwarden\Laravel\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Process\Exception\ExceptionInterface as ProcessException;
use Symfony\Component\Process\Process;

/**
 * php artisan phpwarden:scan
 *
 * Runs `phpwarden deps composer.lock --json` through the vendor/bin/phpwarden
 * shim, prints a short ranked table (or the raw JSON with --json) and exits
 * with the CLI's code, adjusted by --fail-on:
 *
 *   0  clean                 1  vulnerable packages found
 *   4  bad / missing lockfile 5  --report-to upload failed
 *   64 usage error           127 phpwarden CLI could not be found or installed
 */
final class ScanCommand extends Command
{
    public const EXIT_CLEAN = 0;
    public const EXIT_VULNERABLE = 1;
    public const EXIT_INPUT = 4;
    public const EXIT_SHIM = 127;

    protected $signature = 'phpwarden:scan
        {--lockfile= : composer.lock to scan (default: config phpwarden.lockfile)}
        {--json : print the CLI\'s JSON document instead of a table}
        {--no-reachability : skip checking whether vulnerable packages are referenced in code}
        {--fail-on= : exposed (any finding), exploited (CISA KEV only) or never}';

    protected $description = 'Scan composer.lock for known-vulnerable packages, ranked by real-world exploitation (KEV + EPSS)';

    public function handle(): int
    {
        $failOn = strtolower((string) ($this->option('fail-on') ?: config('phpwarden.fail_on', 'exposed')));
        if (!in_array($failOn, ['exposed', 'exploited', 'never'], true)) {
            $this->error("--fail-on must be exposed, exploited or never (got '{$failOn}')");

            return 64;
        }

        $binary = (string) config('phpwarden.binary', base_path('vendor/bin/phpwarden'));
        $lockfile = (string) ($this->option('lockfile') ?: config('phpwarden.lockfile', base_path('composer.lock')));
        if ($this->option('lockfile') && !$this->isAbsolute($lockfile)) {
            // The scan runs with base_path() as cwd; a relative --lockfile should
            // still mean "relative to where I typed the command".
            $lockfile = rtrim((string) getcwd(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $lockfile;
        }

        $cmd = [$binary, 'deps', $lockfile, '--json'];
        if ($this->option('no-reachability') || config('phpwarden.no_reachability', false)) {
            $cmd[] = '--no-reachability';
        }

        $process = new Process($cmd, base_path(), null, null, (float) config('phpwarden.timeout', 600));
        $stdout = '';
        $console = $this->output->getOutput();
        $stderr = $console instanceof ConsoleOutputInterface ? $console->getErrorOutput() : $console;
        try {
            // stdout is the JSON document and is buffered; stderr (progress,
            // errors, the shim installing the CLI on first run) streams through.
            $process->run(function (string $type, string $buffer) use (&$stdout, $stderr): void {
                if ($type === Process::ERR) {
                    $stderr->write($buffer);
                } else {
                    $stdout .= $buffer;
                }
            });
        } catch (ProcessException $e) {
            $this->error('phpwarden could not be run: ' . $e->getMessage());

            return self::EXIT_SHIM;
        }

        $rc = $process->getExitCode() ?? self::EXIT_SHIM;
        $doc = json_decode($stdout, true);

        if (!is_array($doc) || !array_key_exists('vulnerable', $doc)) {
            // Not a scan result: a missing lockfile (4), usage error (64) or the
            // shim failing (127). Show whatever came back and pass the code on.
            if ($stdout !== '') {
                $this->output->write($stdout);
            }
            if ($rc === self::EXIT_CLEAN) {
                $this->error('phpwarden returned no JSON result');

                return self::EXIT_SHIM;
            }

            return $rc;
        }

        /** @var array<int, array<string, mixed>> $findings */
        $findings = $doc['vulnerable'];
        $exploited = array_values(array_filter($findings, static fn (array $f): bool => !empty($f['known_exploited'])));

        if ($this->option('json')) {
            $this->output->writeln($stdout === '' ? json_encode($doc, JSON_PRETTY_PRINT) : rtrim($stdout));
        } else {
            $this->printTable($lockfile, $findings, count($exploited));
        }

        return $this->verdict($rc, $failOn, count($findings) > 0, count($exploited) > 0);
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    private function printTable(string $lockfile, array $findings, int $exploitedCount): void
    {
        if ($findings === []) {
            $this->info("No known-vulnerable Composer packages in {$lockfile}.");

            return;
        }

        $this->warn(sprintf(
            '%d vulnerable package(s) in %s; %d actively exploited (KEV). Ranked by exploitation risk, then reachability:',
            count($findings),
            $lockfile,
            $exploitedCount
        ));

        $rows = [];
        foreach ($findings as $f) {
            $risk = [];
            if (!empty($f['known_exploited'])) {
                $risk[] = !empty($f['ransomware']) ? 'KEV·ransomware' : 'KEV';
            }
            if (isset($f['epss']) && $f['epss'] !== null) {
                $risk[] = sprintf('EPSS %d%%', (int) round(((float) $f['epss']) * 100));
            }
            $severity = (string) ($f['severity'] ?? 'unknown');
            if (!empty($f['cvss']) && (float) $f['cvss'] > 0) {
                $severity .= sprintf(' (%s)', rtrim(rtrim(number_format((float) $f['cvss'], 1, '.', ''), '0'), '.'));
            }
            $fixed = $f['fixed'] ?? [];
            $rows[] = [
                (string) ($f['package'] ?? ''),
                (string) ($f['installed'] ?? ''),
                (string) ($f['cve'] ?? ''),
                $severity,
                implode(', ', $risk),
                (string) ($f['reach'] ?? 'unknown'),
                is_array($fixed) ? implode(', ', $fixed) : (string) $fixed,
            ];
        }

        $this->table(['Package', 'Installed', 'CVE', 'Severity', 'Risk', 'Reach', 'Fixed in'], $rows);
    }

    private function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\/]#', $path) === 1;
    }

    private function verdict(int $rc, string $failOn, bool $anyFinding, bool $anyExploited): int
    {
        // Errors other than the CLI's own "vulnerable" verdict always win: a
        // scan that did not run as configured must not pass silently.
        if ($rc !== self::EXIT_CLEAN && $rc !== self::EXIT_VULNERABLE) {
            return $rc;
        }

        return match ($failOn) {
            'never' => self::EXIT_CLEAN,
            'exploited' => $anyExploited ? self::EXIT_VULNERABLE : self::EXIT_CLEAN,
            default => $anyFinding ? self::EXIT_VULNERABLE : $rc,
        };
    }
}
