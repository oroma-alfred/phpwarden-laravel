<?php

return [
    /*
     * Path to the phpwarden CLI. The default is the shim installed by the
     * phpwarden/phpwarden Composer package, which finds or installs the
     * Python CLI on first run (see PHPWARDEN_BIN / PHPWARDEN_VENV in its docs).
     */
    'binary' => env('PHPWARDEN_LARAVEL_BIN', base_path('vendor/bin/phpwarden')),

    /* Lockfile to scan. */
    'lockfile' => env('PHPWARDEN_LOCKFILE', base_path('composer.lock')),

    /*
     * Default failure policy for `phpwarden:scan`:
     *   exposed   — exit 1 on any known-vulnerable package (the CLI's verdict)
     *   exploited — exit 1 only when a finding is in CISA's KEV catalogue
     *   never     — always exit 0 when the scan itself ran
     */
    'fail_on' => env('PHPWARDEN_FAIL_ON', 'exposed'),

    /* Skip the "is this package referenced in my code?" pass (faster). */
    'no_reachability' => (bool) env('PHPWARDEN_NO_REACHABILITY', false),

    /* Seconds before the scan is killed. First run may install the CLI. */
    'timeout' => (int) env('PHPWARDEN_TIMEOUT', 600),
];
