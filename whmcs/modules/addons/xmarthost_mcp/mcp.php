<?php
/**
 * XMart Host MCP for WHMCS - public MCP endpoint.
 *
 * Paste this URL (with your connector key) into Claude > Settings > Connectors
 * > Add custom connector, or ChatGPT > Settings > Apps & Connectors > Create.
 *   https://your-whmcs/modules/addons/xmarthost_mcp/mcp.php?key=xmh_...
 */

require_once __DIR__ . '/../../../init.php';
require_once __DIR__ . '/lib/autoload.php';

use WHMCS\Database\Capsule;

$send = function ($status, array $headers, $body) {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($status);
    foreach ($headers as $k => $v) {
        header($k . ': ' . $v);
    }
    if ($body !== null) {
        echo $body;
    }
    exit;
};

try {
    $active = Capsule::table('tbladdonmodules')->where('module', 'xmarthost_mcp')->where('setting', 'version')->exists();
    if (!$active || !Capsule::schema()->hasTable(\XMartHost\Mcp\Schema::TOKENS)) {
        $send(503, ['Content-Type' => 'application/json'], '{"jsonrpc":"2.0","id":null,"error":{"code":-32002,"message":"XMart Host MCP is not activated in WHMCS."}}');
    }
    $server = new \XMartHost\Mcp\Server();
    list($status, $headers, $body) = $server->handle($_SERVER, $_GET, file_get_contents('php://input', false, null, 0, \XMartHost\Mcp\Server::MAX_BODY + 1));
    $send($status, $headers, $body);
} catch (\Throwable $e) {
    if (function_exists('logActivity')) {
        logActivity('XMart Host MCP endpoint error: ' . $e->getMessage());
    }
    $send(500, ['Content-Type' => 'application/json'], '{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal server error. See the WHMCS activity log."}}');
}
