<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

/**
 * Small network helpers: client IP, IP/CIDR allowlists, origin checks.
 */
class Net
{
    public static function clientIp(array $server, $trustProxy)
    {
        $ip = isset($server['REMOTE_ADDR']) ? (string) $server['REMOTE_ADDR'] : '';
        if ($trustProxy) {
            foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'] as $h) {
                if (!empty($server[$h])) {
                    $first = trim(explode(',', (string) $server[$h])[0]);
                    if (filter_var($first, FILTER_VALIDATE_IP)) {
                        return $first;
                    }
                }
            }
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    public static function isHttps(array $server, $trustProxy)
    {
        if (!empty($server['HTTPS']) && strtolower((string) $server['HTTPS']) !== 'off') {
            return true;
        }
        if (isset($server['SERVER_PORT']) && (int) $server['SERVER_PORT'] === 443) {
            return true;
        }
        if ($trustProxy && isset($server['HTTP_X_FORWARDED_PROTO'])) {
            return strtolower((string) $server['HTTP_X_FORWARDED_PROTO']) === 'https';
        }
        return false;
    }

    /** True when $ip matches one of the IPs / CIDR ranges. An empty list allows all. */
    public static function ipAllowed($ip, array $list)
    {
        if (!$list) {
            return true;
        }
        foreach ($list as $entry) {
            if (self::ipMatches($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    public static function ipMatches($ip, $entry)
    {
        $entry = trim($entry);
        if (strpos($entry, '/') === false) {
            return inet_pton($ip) !== false && @inet_pton($entry) === inet_pton($ip);
        }
        list($subnet, $bits) = explode('/', $entry, 2);
        $ipBin = @inet_pton($ip);
        $netBin = @inet_pton($subnet);
        $bits = (int) $bits;
        if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
            return false;
        }
        $max = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $max) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rem)) & 0xff;
        return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }

    public static function validEntry($entry)
    {
        $entry = trim($entry);
        if (strpos($entry, '/') === false) {
            return (bool) filter_var($entry, FILTER_VALIDATE_IP);
        }
        list($subnet, $bits) = explode('/', $entry, 2);
        if (!filter_var($subnet, FILTER_VALIDATE_IP) || !ctype_digit($bits)) {
            return false;
        }
        $max = strpos($subnet, ':') !== false ? 128 : 32;
        return (int) $bits <= $max;
    }

    /**
     * Browsers send Origin; server-to-server connectors (Claude, ChatGPT) do not.
     * A present Origin must be on the allowlist (DNS-rebinding protection from the MCP spec).
     */
    public static function originAllowed($origin, array $allowed)
    {
        if ($origin === null || $origin === '') {
            return true;
        }
        $origin = rtrim(strtolower($origin), '/');
        foreach ($allowed as $a) {
            if (rtrim(strtolower($a), '/') === $origin) {
                return true;
            }
        }
        return false;
    }
}
