<?php
/**
 * XMart Host MCP for WHMCS - class loader.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

if (!defined('XMH_MCP_VERSION')) {
    define('XMH_MCP_VERSION', '1.0.0');
}

spl_autoload_register(function ($class) {
    $prefix = 'XMartHost\\Mcp\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});
