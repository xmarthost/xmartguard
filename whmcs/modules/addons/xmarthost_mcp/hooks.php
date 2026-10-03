<?php
/**
 * XMart Host MCP for WHMCS - hooks.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/autoload.php';

// Keep the audit log to the configured retention period.
add_hook('DailyCronJob', 1, function () {
    try {
        if (\WHMCS\Database\Capsule::schema()->hasTable(\XMartHost\Mcp\Schema::LOGS)) {
            \XMartHost\Mcp\Logger::prune(\XMartHost\Mcp\Settings::int('log_retention_days', 1, 3650));
        }
    } catch (\Exception $e) {
        // never break the cron
    }
});
