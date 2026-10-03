<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

/**
 * Connector keys. The key itself is shown once when created; only its
 * SHA-256 hash is stored, so a database leak does not expose working keys.
 */
class Tokens
{
    const PREFIX = 'xmh_';

    public static function create($name, $scope, array $categories, array $allowedIps, $expiresDays, $createdBy)
    {
        if (!isset(Catalog::SCOPES[$scope])) {
            throw new \InvalidArgumentException('Invalid access level.');
        }
        $categories = array_values(array_intersect($categories, array_keys(Catalog::CATEGORIES)));
        if (count($categories) === count(Catalog::CATEGORIES)) {
            $categories = [];
        }
        foreach ($allowedIps as $ip) {
            if (!Net::validEntry($ip)) {
                throw new \InvalidArgumentException('Invalid IP or CIDR range: ' . $ip);
            }
        }
        $token = self::PREFIX . bin2hex(random_bytes(24));
        $id = Capsule::table(Schema::TOKENS)->insertGetId([
            'name' => mb_substr(trim($name) !== '' ? trim($name) : 'AI connector', 0, 100),
            'token_hash' => hash('sha256', $token),
            'token_prefix' => substr($token, 0, 12),
            'scope' => $scope,
            'categories' => $categories ? implode(',', $categories) : null,
            'allowed_ips' => $allowedIps ? implode("\n", $allowedIps) : null,
            'expires_at' => $expiresDays > 0 ? date('Y-m-d H:i:s', time() + 86400 * (int) $expiresDays) : null,
            'calls' => 0,
            'revoked' => 0,
            'created_by' => mb_substr((string) $createdBy, 0, 100),
            'created_at' => date('Y-m-d H:i:s'),
        ]);
        return ['id' => $id, 'token' => $token];
    }

    /** Active (not revoked, not expired) token row for a raw key, or null. */
    public static function find($token)
    {
        $token = trim((string) $token);
        if ($token === '' || strlen($token) > 200 || strncmp($token, self::PREFIX, strlen(self::PREFIX)) !== 0) {
            return null;
        }
        $row = Capsule::table(Schema::TOKENS)->where('token_hash', hash('sha256', $token))->first();
        if (!$row || (int) $row->revoked === 1) {
            return null;
        }
        if ($row->expires_at && strtotime($row->expires_at) < time()) {
            return null;
        }
        return $row;
    }

    /** True when the key was issued here, even if it is now revoked or expired. */
    public static function exists($token)
    {
        return Capsule::table(Schema::TOKENS)->where('token_hash', hash('sha256', trim((string) $token)))->exists();
    }

    public static function touch($id, $ip)
    {
        Capsule::table(Schema::TOKENS)->where('id', $id)->update([
            'last_used_at' => date('Y-m-d H:i:s'),
            'last_ip' => $ip,
            'calls' => Capsule::raw('calls + 1'),
        ]);
    }

    public static function revoke($id)
    {
        return Capsule::table(Schema::TOKENS)->where('id', (int) $id)->where('revoked', 0)
            ->update(['revoked' => 1, 'revoked_at' => date('Y-m-d H:i:s')]);
    }

    public static function delete($id)
    {
        return Capsule::table(Schema::TOKENS)->where('id', (int) $id)->where('revoked', 1)->delete();
    }

    public static function categories($row)
    {
        $cats = Settings::splitList(isset($row->categories) ? $row->categories : '');
        return $cats ? $cats : array_keys(Catalog::CATEGORIES);
    }

    public static function allowedIps($row)
    {
        return Settings::splitList(isset($row->allowed_ips) ? $row->allowed_ips : '');
    }

    public static function all()
    {
        return Capsule::table(Schema::TOKENS)->orderBy('revoked')->orderBy('id', 'desc')->get();
    }
}
