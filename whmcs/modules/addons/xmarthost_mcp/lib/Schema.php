<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

/**
 * Module tables. install() is idempotent: it is run on activation and on
 * every upgrade, and only creates what is missing.
 */
class Schema
{
    const SETTINGS = 'mod_xmarthost_mcp_settings';
    const TOKENS = 'mod_xmarthost_mcp_tokens';
    const LOGS = 'mod_xmarthost_mcp_logs';

    public static function install()
    {
        $schema = Capsule::schema();

        if (!$schema->hasTable(self::SETTINGS)) {
            $schema->create(self::SETTINGS, function ($t) {
                $t->string('setting', 64)->primary();
                $t->text('value')->nullable();
            });
        }

        if (!$schema->hasTable(self::TOKENS)) {
            $schema->create(self::TOKENS, function ($t) {
                $t->increments('id');
                $t->string('name', 100);
                $t->string('token_hash', 64)->unique();
                $t->string('token_prefix', 16);
                $t->string('scope', 10)->default('read');
                $t->text('allowed_ips')->nullable();
                $t->text('categories')->nullable();
                $t->dateTime('expires_at')->nullable();
                $t->dateTime('last_used_at')->nullable();
                $t->string('last_ip', 45)->nullable();
                $t->unsignedBigInteger('calls')->default(0);
                $t->tinyInteger('revoked')->default(0);
                $t->dateTime('revoked_at')->nullable();
                $t->string('created_by', 100)->nullable();
                $t->dateTime('created_at');
            });
        }

        if (!$schema->hasTable(self::LOGS)) {
            $schema->create(self::LOGS, function ($t) {
                $t->bigIncrements('id');
                $t->unsignedInteger('token_id')->nullable();
                $t->string('token_name', 100)->nullable();
                $t->string('event', 20);
                $t->string('tool', 100)->nullable();
                $t->string('api_action', 100)->nullable();
                $t->string('access', 10)->nullable();
                $t->string('status', 10);
                $t->string('message', 500)->nullable();
                $t->text('params')->nullable();
                $t->string('ip', 45)->nullable();
                $t->unsignedInteger('duration_ms')->default(0);
                $t->dateTime('created_at');
                $t->index(['token_id', 'created_at'], 'xmh_logs_token_time');
                $t->index(['ip', 'created_at'], 'xmh_logs_ip_time');
                $t->index('created_at', 'xmh_logs_time');
            });
        }
    }

    /** Removes every module table (used only by the explicit "delete all data" action). */
    public static function drop()
    {
        $schema = Capsule::schema();
        foreach ([self::LOGS, self::TOKENS, self::SETTINGS] as $table) {
            $schema->dropIfExists($table);
        }
    }
}
