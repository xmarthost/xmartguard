<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

/**
 * Module settings, kept in the module's own table so everything is configured
 * from the XMart Host dashboard. Secrets are encrypted with WHMCS's own
 * encryption key (configuration.php $cc_encryption_hash).
 */
class Settings
{
    const ENCRYPTED = ['api_secret', 'api_accesskey'];

    const DEFAULTS = [
        'enabled' => '1',
        'connection_mode' => 'api',
        'api_url' => '',
        'api_identifier' => '',
        'api_secret' => '',
        'api_accesskey' => '',
        'verify_ssl' => '1',
        'local_admin' => '',
        'require_https' => '1',
        'rate_limit' => '120',
        'auth_fail_limit' => '10',
        'global_ip_allow' => '',
        'trust_proxy' => '0',
        'blocked_actions' => '',
        'disabled_tools' => '',
        'allowed_origins' => "https://claude.ai\nhttps://claude.com\nhttps://chatgpt.com\nhttps://chat.openai.com",
        'log_retention_days' => '90',
        'log_params' => '1',
        'last_test_ok' => '',
        'last_test_at' => '',
        'last_test_msg' => '',
        'whmcs_version' => '',
    ];

    /** @var array|null */
    private static $cache = null;

    public static function all()
    {
        if (self::$cache === null) {
            $rows = [];
            foreach (Capsule::table(Schema::SETTINGS)->get() as $row) {
                $rows[$row->setting] = (string) $row->value;
            }
            self::$cache = array_merge(self::DEFAULTS, $rows);
        }
        return self::$cache;
    }

    public static function get($key)
    {
        $all = self::all();
        $value = isset($all[$key]) ? $all[$key] : '';
        if ($value !== '' && in_array($key, self::ENCRYPTED, true)) {
            $value = self::decrypt($value);
        }
        return $value;
    }

    public static function bool($key)
    {
        return self::get($key) === '1';
    }

    public static function int($key, $min, $max)
    {
        return max($min, min($max, (int) self::get($key)));
    }

    public static function set($key, $value)
    {
        $value = (string) $value;
        if ($value !== '' && in_array($key, self::ENCRYPTED, true)) {
            $value = self::encrypt($value);
        }
        Capsule::table(Schema::SETTINGS)->updateOrInsert(['setting' => $key], ['value' => $value]);
        self::$cache = null;
    }

    public static function setMany(array $values)
    {
        foreach ($values as $k => $v) {
            self::set($k, $v);
        }
    }

    /** Newline/comma separated setting as a clean list. */
    public static function lines($key)
    {
        return self::splitList(self::get($key));
    }

    public static function splitList($text)
    {
        $out = [];
        foreach (preg_split('/[\r\n,]+/', (string) $text) as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] !== '#') {
                $out[] = $line;
            }
        }
        return array_values(array_unique($out));
    }

    public static function systemUrl()
    {
        $url = '';
        if (class_exists('\WHMCS\Config\Setting')) {
            $url = (string) \WHMCS\Config\Setting::getValue('SystemURL');
        }
        if ($url === '') {
            $row = Capsule::table('tblconfiguration')->where('setting', 'SystemURL')->first();
            $url = $row ? (string) $row->value : '';
        }
        return rtrim($url, '/') . '/';
    }

    public static function endpointUrl()
    {
        return self::systemUrl() . 'modules/addons/xmarthost_mcp/mcp.php';
    }

    public static function connectorUrl($token)
    {
        return self::endpointUrl() . '?key=' . rawurlencode($token);
    }

    public static function encrypt($value)
    {
        return function_exists('encrypt') ? encrypt($value) : 'b64:' . base64_encode($value);
    }

    public static function decrypt($value)
    {
        if (strncmp($value, 'b64:', 4) === 0) {
            return (string) base64_decode(substr($value, 4));
        }
        return function_exists('decrypt') ? (string) decrypt($value) : $value;
    }

    public static function flush()
    {
        self::$cache = null;
    }
}
