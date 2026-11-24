<?php
/**
 * ===================================================================
 * School management system — database and security configuration
 * ===================================================================
 * Configure these values through environment variables on your PHP host.
 * GitHub Pages is static hosting and cannot execute this PHP application.
 */

function school_env(string $name, string $fallback): string {
    $value = getenv($name);
    return ($value !== false && $value !== '') ? $value : $fallback;
}

// Database settings: set SCHOOL_DB_* variables in your PHP hosting panel.
defined('DB_DRIVER')   || define('DB_DRIVER', school_env('SCHOOL_DB_DRIVER', 'mysql'));
defined('DB_HOST')     || define('DB_HOST', school_env('SCHOOL_DB_HOST', 'localhost'));
defined('DB_PORT')     || define('DB_PORT', (int) school_env('SCHOOL_DB_PORT', '3306'));
defined('DB_NAME')     || define('DB_NAME', school_env('SCHOOL_DB_NAME', 'CHANGE_ME'));
defined('DB_USER')     || define('DB_USER', school_env('SCHOOL_DB_USER', 'CHANGE_ME'));
defined('DB_PASS')     || define('DB_PASS', school_env('SCHOOL_DB_PASS', ''));
defined('DB_PREFIX')   || define('DB_PREFIX', school_env('SCHOOL_DB_PREFIX', 'sc_'));

// SQLite is intended only for local testing. The PHP host must allow writes
// to this directory if SQLite is selected.
defined('DB_SQLITE_PATH') || define('DB_SQLITE_PATH', __DIR__ . '/data/school.sqlite');

// Set a unique initial password before first use; change it immediately after
// the first login. Never commit production credentials to this repository.
defined('INITIAL_USER') || define('INITIAL_USER', school_env('SCHOOL_INITIAL_USER', 'admin'));
defined('INITIAL_PASS') || define('INITIAL_PASS', school_env('SCHOOL_INITIAL_PASS', 'CHANGE_ME_BEFORE_DEPLOYMENT'));

defined('DEBUG_SETUP')  || define('DEBUG_SETUP', false);
defined('SITE_URL')     || define('SITE_URL', school_env('SCHOOL_SITE_URL', ''));
defined('CRON_KEY')     || define('CRON_KEY', school_env('SCHOOL_CRON_KEY', 'CHANGE_ME_TO_A_RANDOM_SECRET'));
