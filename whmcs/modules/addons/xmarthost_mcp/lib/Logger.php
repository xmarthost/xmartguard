<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

/**
 * Audit log of every connector request, also used for rate limiting and
 * for locking out IPs that keep sending wrong keys.
 */
class Logger
{
    const SENSITIVE = '/pass|secret|token|key|cvv|cc(number|num)?$|card_number|card_expiry|bank_account|eppcode|rootpw/i';

    public static function write(array $entry)
    {
        $row = array_merge([
            'token_id' => null,
            'token_name' => null,
            'event' => 'tool_call',
            'tool' => null,
            'api_action' => null,
            'access' => null,
            'status' => 'ok',
            'message' => null,
            'params' => null,
            'ip' => null,
            'duration_ms' => 0,
            'created_at' => date('Y-m-d H:i:s'),
        ], $entry);
        if ($row['message'] !== null) {
            $row['message'] = mb_substr((string) $row['message'], 0, 500);
        }
        if (is_array($row['params'])) {
            $row['params'] = Settings::bool('log_params') ? self::encodeParams($row['params']) : null;
        }
        try {
            Capsule::table(Schema::LOGS)->insert($row);
        } catch (\Exception $e) {
            // Logging must never break a request.
        }
    }

    public static function encodeParams(array $params)
    {
        $json = json_encode(self::redact($params), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        if (strlen($json) > 4000) {
            $json = substr($json, 0, 4000) . '...';
        }
        return $json;
    }

    public static function redact($value, $key = '')
    {
        if ($key !== '' && !is_int($key) && preg_match(self::SENSITIVE, (string) $key)) {
            return '***';
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = self::redact($v, $k);
            }
            return $out;
        }
        if (is_string($value) && strlen($value) > 500) {
            return substr($value, 0, 500) . '...';
        }
        return $value;
    }

    public static function callsInLastMinute($tokenId)
    {
        return Capsule::table(Schema::LOGS)
            ->where('token_id', $tokenId)
            ->where('event', 'tool_call')
            ->where('created_at', '>=', date('Y-m-d H:i:s', time() - 60))
            ->count();
    }

    public static function authFailures($ip, $minutes = 15)
    {
        return Capsule::table(Schema::LOGS)
            ->where('ip', $ip)
            ->where('event', 'auth_fail')
            ->where('created_at', '>=', date('Y-m-d H:i:s', time() - 60 * $minutes))
            ->count();
    }

    public static function prune($days)
    {
        $days = max(1, (int) $days);
        return Capsule::table(Schema::LOGS)->where('created_at', '<', date('Y-m-d H:i:s', time() - 86400 * $days))->delete();
    }
}
