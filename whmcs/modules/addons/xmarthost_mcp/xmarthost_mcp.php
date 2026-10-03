<?php
/**
 * XMart Host MCP for WHMCS
 *
 * A Model Context Protocol (MCP) server inside WHMCS, so Claude, ChatGPT and
 * other AI assistants can read and manage WHMCS through a custom connector.
 *
 * @copyright XMart Host
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/autoload.php';

use XMartHost\Mcp\Admin;
use XMartHost\Mcp\Schema;

function xmarthost_mcp_config()
{
    return [
        'name' => 'XMart Host MCP',
        'description' => 'Connect Claude, ChatGPT, Cursor and other AI assistants to WHMCS through the Model Context Protocol. '
            . 'Manage clients, products, orders, services, invoices, domains and tickets, and get MRR, churn and revenue reports, '
            . 'with per-connector permissions, rate limiting and a full audit log.',
        'author' => 'XMart Host',
        'language' => 'english',
        'version' => XMH_MCP_VERSION,
        'fields' => [],
    ];
}

function xmarthost_mcp_activate()
{
    try {
        Schema::install();
        return [
            'status' => 'success',
            'description' => 'XMart Host MCP is active. Set Access Control for the admin roles that may manage it, then open Addons > XMart Host MCP.',
        ];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => 'Could not create the module tables: ' . $e->getMessage()];
    }
}

/**
 * Deactivation turns the MCP endpoint off immediately (it only answers while the
 * addon is active) but keeps connectors, settings and logs, so reactivating
 * restores everything. To remove all data, drop the mod_xmarthost_mcp_* tables.
 */
function xmarthost_mcp_deactivate()
{
    return [
        'status' => 'success',
        'description' => 'XMart Host MCP is deactivated: AI connectors no longer work. Settings and connectors are kept for reactivation.',
    ];
}

function xmarthost_mcp_upgrade($vars)
{
    Schema::install();
}

function xmarthost_mcp_output($vars)
{
    (new Admin($vars))->run();
}
