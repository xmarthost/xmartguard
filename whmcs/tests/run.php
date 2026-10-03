<?php
/**
 * XMart Host MCP test suite. Run: php run.php   (needs `composer install` here)
 * Unit-level: drives Server::handle() and the admin page against a SQLite WHMCS stand-in.
 */

putenv('XMH_TEST_DB=' . sys_get_temp_dir() . '/xmh_unit_' . getmypid() . '.sqlite');
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/../modules/addons/xmarthost_mcp/lib/autoload.php';
require __DIR__ . '/../modules/addons/xmarthost_mcp/xmarthost_mcp.php';

use WHMCS\Database\Capsule;
use XMartHost\Mcp\ApiClient;
use XMartHost\Mcp\Server;
use XMartHost\Mcp\Settings;
use XMartHost\Mcp\Tokens;

$fails = 0;
$passes = 0;
function ok($cond, $name, $extra = '')
{
    global $fails, $passes;
    if ($cond) {
        $passes++;
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name" . ($extra !== '' ? "\n       " . $extra : '') . "\n";
    }
}

xmh_seed_whmcs();
$act = xmarthost_mcp_activate();
ok($act['status'] === 'success', 'activate creates tables', json_encode($act));
Settings::flush();
Settings::setMany(['connection_mode' => 'local']);

$server = new Server(function () { return ApiClient::fromSettings(); });
$https = ['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '203.0.113.5'];

function rpc($server, $token, $method, $params = [], $id = 1, $srv = null)
{
    global $https;
    $srv = $srv ?: $https;
    $msg = ['jsonrpc' => '2.0', 'method' => $method];
    if ($id !== null) {
        $msg['id'] = $id;
    }
    if ($params) {
        $msg['params'] = $params;
    }
    list($status, $headers, $body) = $server->handle($srv, ['key' => $token], json_encode($msg));
    return [$status, $body === null ? null : json_decode($body, true), $headers];
}
function call($server, $token, $tool, $args = [])
{
    list($s, $r) = rpc($server, $token, 'tools/call', ['name' => $tool, 'arguments' => $args ?: new stdClass()]);
    $text = isset($r['result']['content'][0]['text']) ? $r['result']['content'][0]['text'] : null;
    return [$s, isset($r['result']['isError']) ? $r['result']['isError'] : null, $text, $r];
}

echo "auth\n";
list($s, $r) = rpc($server, '', 'initialize');
ok($s === 401, 'no key -> 401');
list($s) = rpc($server, 'xmh_' . str_repeat('0', 48), 'initialize');
ok($s === 401, 'unknown key -> 401');

$read = Tokens::create('Reader', 'read', [], [], 0, 'boss')['token'];
$write = Tokens::create('Writer', 'write', [], [], 0, 'boss')['token'];
$full = Tokens::create('Full', 'full', [], [], 0, 'boss')['token'];
$support = Tokens::create('Support only', 'write', ['Support'], [], 0, 'boss')['token'];
$ipLocked = Tokens::create('IP locked', 'full', [], ['198.51.100.0/24'], 0, 'boss')['token'];
ok(strpos($read, 'xmh_') === 0 && strlen($read) === 52, 'key format xmh_ + 48 hex');
ok(Capsule::table('mod_xmarthost_mcp_tokens')->where('token_hash', $read)->count() === 0, 'raw key is not stored');

list($s, $r) = rpc($server, $read, 'initialize', ['protocolVersion' => '2025-03-26', 'clientInfo' => ['name' => 'claude-ai', 'version' => '1']]);
ok($s === 200 && $r['result']['protocolVersion'] === '2025-03-26', 'initialize negotiates protocol');
ok($r['result']['serverInfo']['name'] === 'xmarthost-whmcs', 'server info');
ok(strpos($r['result']['instructions'], 'READ-ONLY') !== false, 'instructions mention read-only');
list($s, $r) = rpc($server, $read, 'initialize', ['protocolVersion' => '1999-01-01']);
ok($r['result']['protocolVersion'] === '2025-06-18', 'unknown protocol -> latest');

list($s, $r, $h) = $server->handle(['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '203.0.113.5', 'HTTP_AUTHORIZATION' => 'Bearer ' . $write], [], '{"jsonrpc":"2.0","id":1,"method":"ping"}');
ok($s === 200, 'Bearer header works');
list($s) = $server->handle(['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '203.0.113.5', 'PATH_INFO' => '/' . $write], [], '{"jsonrpc":"2.0","id":1,"method":"ping"}');
ok($s === 200, 'key in path works');

list($s) = rpc($server, $read, 'ping', [], 1, ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '203.0.113.5']);
ok($s === 403, 'plain HTTP refused when HTTPS required');
list($s) = rpc($server, $ipLocked, 'ping');
ok($s === 403, 'token IP allowlist blocks other IPs');
list($s) = rpc($server, $ipLocked, 'ping', [], 1, ['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '198.51.100.77']);
ok($s === 200, 'token IP allowlist allows CIDR member');
list($s) = rpc($server, $read, 'ping', [], 1, $https + ['HTTP_ORIGIN' => 'https://evil.example']);
ok($s === 403, 'foreign Origin refused');
list($s, $r, $h) = rpc($server, $read, 'ping', [], 1, $https + ['HTTP_ORIGIN' => 'https://claude.ai']);
ok($s === 200 && $h['Access-Control-Allow-Origin'] === 'https://claude.ai', 'allowed Origin gets CORS header');
list($s, $h) = $server->handle(['REQUEST_METHOD' => 'GET', 'HTTPS' => 'on', 'REMOTE_ADDR' => '203.0.113.5'], ['key' => $read], '');
ok($s === 405 && $h['Allow'] === 'POST, OPTIONS', 'GET -> 405');
list($s) = $server->handle($https, ['key' => $read], '{not json');
ok($s === 400, 'bad JSON -> 400');
list($s, $r) = rpc($server, $read, 'notifications/initialized', [], null);
ok($s === 202 && $r === null, 'notification -> 202 no body');
list($s, $r) = rpc($server, $read, 'nope/method');
ok($r['error']['code'] === -32601, 'unknown method -> -32601');

Capsule::table('mod_xmarthost_mcp_tokens')->where('name', 'Writer')->update(['expires_at' => '2000-01-01 00:00:00']);
list($s) = rpc($server, $write, 'ping');
ok($s === 401, 'expired key -> 401');
Capsule::table('mod_xmarthost_mcp_tokens')->where('name', 'Writer')->update(['expires_at' => null]);

echo "tools/list\n";
$names = function ($token) use ($server) {
    list($s, $r) = rpc($server, $token, 'tools/list');
    return array_column($r['result']['tools'], 'name');
};
$readTools = $names($read);
$writeTools = $names($write);
$supportTools = $names($support);
ok(in_array('search_clients', $readTools) && !in_array('create_client', $readTools), 'read connector sees read tools only');
ok(in_array('create_product', $writeTools) && in_array('report_mrr', $writeTools), 'write connector sees write tools');
ok(in_array('reply_ticket', $supportTools) && !in_array('search_clients', $supportTools) && in_array('whmcs_api_call', $supportTools), 'category-limited connector');
list($s, $h, $raw) = $server->handle($https, ['key' => $read], '{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
ok(strpos($raw, '"properties":[]') === false && strpos($raw, '"properties":{}') !== false, 'empty properties encode as {}');
list($s, $r) = rpc($server, $read, 'tools/list');
$t = $r['result']['tools'][array_search('search_clients', array_column($r['result']['tools'], 'name'))];
ok($t['annotations']['readOnlyHint'] === true, 'read tools carry readOnlyHint');

echo "tool calls\n";
list($s, $err, $text) = call($server, $read, 'whmcs_overview');
$o = json_decode($text, true);
ok($err === false && $o['whmcs']['whmcs']['version'] === '8.13.0', 'overview: version', $text);
ok($o['overdue_invoices']['count'] === 2 && (float) $o['overdue_invoices']['total'] === 3050.0, 'overview: overdue invoices', json_encode($o['overdue_invoices']));
ok($o['counts']['domains_expiring_30d'] === 1, 'overview: expiring domains');

list($s, $err, $text) = call($server, $read, 'search_clients', ['search' => 'ali', 'status' => '', 'limitnum' => 9999]);
$o = json_decode($text, true);
ok($err === false && $o['echo']['search'] === 'ali' && !isset($o['echo']['status']) && $o['echo']['limitnum'] === 250, 'wrapper passes args, drops empty, clamps limitnum', $text);

list($s, $err, $text) = call($server, $read, 'create_client', ['firstname' => 'x', 'lastname' => 'y', 'email' => 'z@z.z']);
ok($err === true && strpos($text, 'needs write access') !== false, 'read connector cannot create', $text);
list($s, $err, $text) = call($server, $write, 'create_client', ['firstname' => 'x', 'lastname' => 'y', 'email' => 'z@z.z', 'noemail' => true]);
$o = json_decode($text, true);
ok($err === false && $o['action'] === 'AddClient' && $o['echo']['noemail'] === 1, 'write connector creates client', $text);

list($s, $err, $text) = call($server, $read, 'whmcs_api_call', ['action' => 'getclients', 'params' => ['search' => 'k']]);
ok($err === false && json_decode($text, true)['echo']['search'] === 'k', 'generic call, case-insensitive action');
list($s, $err, $text) = call($server, $write, 'whmcs_api_call', ['action' => 'DeleteClient', 'params' => ['clientid' => 2]]);
ok($err === true && strpos($text, 'full access') !== false, 'write connector cannot delete', $text);
list($s, $err, $text) = call($server, $full, 'whmcs_api_call', ['action' => 'DeleteClient', 'params' => ['clientid' => 2]]);
ok($err === false, 'full connector can delete');
list($s, $err, $text) = call($server, $write, 'whmcs_api_call', ['action' => 'SomeFutureAction']);
ok($err === true && strpos($text, 'not in the catalog') !== false, 'unknown action needs full');
list($s, $err, $text) = call($server, $support, 'whmcs_api_call', ['action' => 'GetClients']);
ok($err === true && strpos($text, 'belongs to "Clients"') !== false, 'generic call honours categories', $text);
list($s, $err, $text) = call($server, $support, 'search_clients');
ok($err === true && strpos($text, 'does not have it') !== false, 'category tool refused', $text);
list($s, $err, $text) = call($server, $full, 'whmcs_api_call', ['action' => 'FailingAction']);
ok($err === true && strpos($text, 'Something went wrong') !== false, 'API error is surfaced', $text);
list($s, $err, $text) = call($server, $full, 'whmcs_api_call', ['action' => 'Get Clients; drop']);
ok($err === true && strpos($text, 'Invalid API action') !== false, 'action name validated');
list($s, $err, $text) = call($server, $read, 'whmcs_find_actions', ['query' => 'ticket']);
$o = json_decode($text, true);
ok($o['count'] > 10 && $o['actions'][0]['action'] !== '', 'find actions');

list($s, $err, $text) = call($server, $write, 'service_action', ['serviceid' => 5, 'action' => 'terminate']);
ok($err === true && strpos($text, 'ModuleTerminate needs full') !== false, 'terminate needs full', $text);
list($s, $err, $text) = call($server, $write, 'service_action', ['serviceid' => 5, 'action' => 'suspend', 'suspendreason' => 'Overdue']);
ok($err === false && json_decode($text, true)['action'] === 'ModuleSuspend', 'suspend works');

list($s, $err, $text) = call($server, $read, 'get_client', ['clientid' => 1]);
$o = json_decode($text, true);
ok($err === false && !isset($o['client']['password']) && isset($o['services']['product']), 'client 360', $text);

list($s, $err, $text) = call($server, $write, 'create_invoice', ['userid' => 1, 'items' => [['description' => 'Setup', 'amount' => 25, 'taxed' => true], ['description' => 'Hosting', 'amount' => 10]]]);
$o = json_decode($text, true);
ok($o['echo']['itemdescription2'] === 'Hosting' && $o['echo']['itemtaxed1'] === 1, 'create invoice maps items', $text);

echo "products (Capsule)\n";
list($s, $err, $text) = call($server, $write, 'create_product_group', ['name' => 'Business Hosting', 'headline' => 'Fast']);
$o = json_decode($text, true);
ok($err === false && $o['slug'] === 'business-hosting', 'create product group', $text);
$gid = $o['gid'];
list($s, $err, $text) = call($server, $write, 'create_product_group', ['name' => 'Business Hosting']);
ok(json_decode($text, true)['slug'] === 'business-hosting-2', 'unique slug');
list($s, $err, $text) = call($server, $write, 'create_product', ['name' => 'Biz 50', 'gid' => $gid, 'type' => 'hostingaccount', 'module' => 'cpanel', 'configoption1' => 'biz50', 'pricing' => ['USD' => ['monthly' => 9.99, 'annually' => 99]]]);
$o = json_decode($text, true);
ok($err === false && $o['echo']['pricing'][1]['monthly'] === 9.99 && $o['echo']['paytype'] === 'recurring', 'create product resolves currency code', $text);
$pid = $o['pid'];
list($s, $err, $text) = call($server, $write, 'create_product', ['name' => 'X', 'gid' => $gid, 'type' => 'other', 'pricing' => ['EUR' => ['monthly' => 1]]]);
ok($err === true && strpos($text, 'Unknown currency') !== false, 'unknown currency rejected');
list($s, $err, $text) = call($server, $write, 'update_product', ['pid' => $pid, 'name' => 'Biz 50 GB', 'hidden' => true, 'configoptions' => ['1' => 'biz50gb'], 'pricing' => ['usd' => ['monthly' => 11, 'msetupfee' => 5], 'PKR' => ['annually' => 25000]]]);
$p = Capsule::table('tblproducts')->find($pid);
ok($err === false && $p->name === 'Biz 50 GB' && (int) $p->hidden === 1 && $p->configoption1 === 'biz50gb', 'update product fields', $text);
$usd = Capsule::table('tblpricing')->where(['type' => 'product', 'relid' => $pid, 'currency' => 1])->first();
$pkr = Capsule::table('tblpricing')->where(['type' => 'product', 'relid' => $pid, 'currency' => 2])->first();
ok($usd && (float) $usd->monthly === 11.0 && $pkr && (float) $pkr->annually === 25000.0 && (float) $pkr->monthly === -1.0, 'pricing upsert, new rows disable other cycles');
list($s, $err, $text) = call($server, $write, 'update_product', ['pid' => $pid, 'configoptions' => ['30' => 'x']]);
ok($err === true, 'configoption index validated');
list($s, $err, $text) = call($server, $write, 'create_configurable_option', ['group_name' => 'Extras', 'product_ids' => [$pid], 'option_name' => 'Extra Disk|disk', 'type' => 'dropdown', 'choices' => [['name' => '10 GB|10', 'pricing' => ['USD' => ['monthly' => 2]]], ['name' => '20 GB|20']]]);
$o = json_decode($text, true);
ok($err === false && count($o['choice_ids']) === 2, 'create configurable option', $text);
list($s, $err, $text) = call($server, $read, 'list_configurable_options', ['pid' => $pid]);
$o = json_decode($text, true);
ok($o['groups'][0]['options'][0]['choices'][0]['pricing'][0]['monthly'] == 2, 'list configurable options', $text);
list($s, $err, $text) = call($server, $write, 'create_configurable_option', ['product_ids' => [999], 'option_name' => 'Y', 'type' => 'yesno', 'choices' => [['name' => 'Yes']]]);
ok($err === true && Capsule::table('tblproductconfigoptions')->where('optionname', 'Y')->count() === 0, 'bad product id rolls back');

echo "reports\n";
list($s, $err, $text) = call($server, $read, 'report_mrr');
$o = json_decode($text, true);
$byCur = array_column($o['totals'], null, 'currency');
ok(abs($byCur['USD']['mrr'] - 21.0) < 0.01 && abs($byCur['PKR']['mrr'] - 1000) < 0.01, 'MRR per currency (10 + 120/12 + 24/24)', $text);
list($s, $err, $text) = call($server, $read, 'report_aging_invoices');
$o = json_decode($text, true);
$byCur = array_column($o['summary'], null, 'currency');
ok($byCur['USD']['31_60_days']['balance'] == 40 && $byCur['PKR']['over_90_days']['count'] === 1 && $byCur['USD']['not_due']['count'] === 1, 'aging buckets minus payments', $text);
list($s, $err, $text) = call($server, $read, 'report_top_clients');
$o = json_decode($text, true);
ok($o['clients'][0]['clientid'] === 2 && $o['clients'][1]['revenue'] == 110, 'top clients', $text);
list($s, $err, $text) = call($server, $read, 'report_revenue');
$o = json_decode($text, true);
ok(count($o['by_gateway']) === 2 && $err === false, 'revenue report', $text);
list($s, $err, $text) = call($server, $read, 'report_churn', ['days' => 30]);
$o = json_decode($text, true);
ok($o['churned_services'] === 1 && $o['new_services'] === 1, 'churn report', $text);

echo "admin controls\n";
Settings::set('disabled_tools', 'search_clients');
ok(!in_array('search_clients', $names($read)), 'disabled tool hidden');
list($s, $err, $text) = call($server, $read, 'search_clients');
ok($err === true && strpos($text, 'disabled') !== false, 'disabled tool refused');
Settings::set('disabled_tools', '');
Settings::set('blocked_actions', "GetClients");
list($s, $err, $text) = call($server, $read, 'whmcs_api_call', ['action' => 'GetClients']);
ok($err === true && strpos($text, 'blocked') !== false, 'blocked action refused');
Settings::set('blocked_actions', '');
Settings::set('enabled', '0');
list($s) = rpc($server, $read, 'ping');
ok($s === 503, 'kill switch');
Settings::set('enabled', '1');

echo "prompts\n";
list($s, $r) = rpc($server, $read, 'prompts/list');
ok(count($r['result']['prompts']) === 6, 'prompts listed');
list($s, $r) = rpc($server, $read, 'prompts/get', ['name' => 'client_360', 'arguments' => ['client' => '42']]);
ok(strpos($r['result']['messages'][0]['content']['text'], '"42"') !== false, 'prompt rendered');

echo "batch, rate limit, lockout, logging\n";
list($s, $h, $body) = $server->handle($https, ['key' => $read], json_encode([['jsonrpc' => '2.0', 'id' => 1, 'method' => 'ping'], ['jsonrpc' => '2.0', 'method' => 'notifications/initialized'], ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/list']]));
$b = json_decode($body, true);
ok($s === 200 && count($b) === 2 && $b[1]['id'] === 2, 'batch');
Settings::set('rate_limit', '3');
$limited = Tokens::create('Limited', 'read', [], [], 0, 'boss')['token'];
for ($i = 0; $i < 3; $i++) {
    call($server, $limited, 'whmcs_find_actions');
}
list($s, $err, $text, $r) = call($server, $limited, 'whmcs_find_actions');
ok($s === 429 && $r['error']['code'] === -32005, 'rate limit per connector');
Settings::set('rate_limit', '120');
$row = Capsule::table('mod_xmarthost_mcp_logs')->where('tool', 'create_client')->where('status', 'ok')->first();
ok($row && $row->access === 'w' && $row->api_action === 'AddClient' && $row->token_name === 'Writer', 'tool call logged');
$attackSrv = ['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '192.0.2.66'];
for ($i = 0; $i < 10; $i++) {
    rpc($server, 'xmh_bad' . $i, 'ping', [], 1, $attackSrv);
}
list($s) = rpc($server, 'xmh_bad_again', 'ping', [], 1, $attackSrv);
ok($s === 429, 'IP locked out after repeated unknown keys');
list($s) = rpc($server, $read, 'ping', [], 1, $attackSrv);
ok($s === 200, 'valid key still works from a locked-out (shared) IP');
$revoked = Tokens::create('Old', 'read', [], [], 0, 'boss');
Tokens::revoke($revoked['id']);
$sharedSrv = ['REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'REMOTE_ADDR' => '192.0.2.99'];
for ($i = 0; $i < 15; $i++) {
    rpc($server, $revoked['token'], 'ping', [], 1, $sharedSrv);
}
list($s) = rpc($server, 'xmh_' . str_repeat('1', 48), 'ping', [], 1, $sharedSrv);
ok($s === 401, 'revoked-key retries do not trigger the lockout');
call($server, $write, 'service_action', ['serviceid' => 1, 'action' => 'changepassword', 'password' => 'S3cret!']);
$row = Capsule::table('mod_xmarthost_mcp_logs')->where('tool', 'service_action')->orderBy('id', 'desc')->first();
ok(strpos($row->params, 'S3cret') === false && strpos($row->params, '***') !== false, 'passwords masked in log', $row->params);

echo "settings & secrets\n";
Settings::set('api_secret', 'top-secret');
$raw = Capsule::table('mod_xmarthost_mcp_settings')->where('setting', 'api_secret')->value('value');
ok($raw !== 'top-secret' && Settings::get('api_secret') === 'top-secret', 'API secret encrypted at rest');
ok(Settings::connectorUrl('xmh_abc') === 'https://billing.example.com/modules/addons/xmarthost_mcp/mcp.php?key=xmh_abc', 'connector URL');
ok(ApiClient::normalizeUrl('https://x.com/billing/') === 'https://x.com/billing/includes/api.php', 'API URL normalized');

echo "admin page\n";
$_SESSION = ['adminid' => 1];
$_SERVER['REQUEST_METHOD'] = 'GET';
foreach (array_keys(\XMartHost\Mcp\Admin::TABS) as $tab) {
    $_REQUEST = $_GET = ['tab' => $tab];
    ob_start();
    xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
    $html = ob_get_clean();
    ok(strpos($html, 'XMart Host') !== false && strpos($html, 'class="active"') !== false, "renders tab $tab");
}
$_SERVER['REQUEST_METHOD'] = 'POST';
$_REQUEST = $_GET = ['tab' => 'connectors'];
$_POST = ['xmh_action' => 'create_token', 'xmh_csrf' => 'wrong', 'name' => 'X', 'scope' => 'read', 'categories' => ['Clients']];
ob_start();
xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
$html = ob_get_clean();
ok(strpos($html, 'session expired') !== false, 'CSRF enforced');
$_POST['xmh_csrf'] = $_SESSION['xmh_csrf'];
$_POST['name'] = '<script>alert(1)</script>';
ob_start();
xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
$html = ob_get_clean();
ok(preg_match('/value="(https:[^"]+key=(xmh_[0-9a-f]{48}))"/', $html, $m) === 1, 'admin creates connector and shows URL once');
ok(strpos($html, '<script>alert(1)</script>') === false, 'output escaped');
ok(Tokens::find($m[2]) !== null && Tokens::find($m[2])->categories === 'Clients', 'created key works with chosen area');

$_REQUEST = $_GET = ['tab' => 'connection'];
$_POST = ['xmh_action' => 'test_connection', 'xmh_csrf' => $_SESSION['xmh_csrf'], 'connection_mode' => 'local', 'api_url' => '', 'api_identifier' => '', 'api_secret' => ''];
ob_start();
xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
$html = ob_get_clean();
ok(strpos($html, 'Connected to WHMCS 8.13.0') !== false, 'connection test (internal API)');
ok(Settings::get('api_secret') === 'top-secret', 'blank secret keeps saved secret');

$_REQUEST = $_GET = ['tab' => 'tools'];
$_POST = ['xmh_action' => 'save_tools', 'xmh_csrf' => $_SESSION['xmh_csrf'], 'tools' => ['whmcs_overview']];
ob_start();
xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
ob_end_clean();
ok(count(Settings::lines('disabled_tools')) === count(\XMartHost\Mcp\Tools::definitions()) - 1, 'tool management saves');
Settings::set('disabled_tools', '');

$_REQUEST = $_GET = ['tab' => 'security'];
$_POST = ['xmh_action' => 'save_security', 'xmh_csrf' => $_SESSION['xmh_csrf'], 'enabled' => '1', 'global_ip_allow' => "10.0.0.0/33"];
ob_start();
xmarthost_mcp_output(['modulelink' => 'addonmodules.php?module=xmarthost_mcp']);
$html = ob_get_clean();
ok(strpos($html, 'Invalid IP or CIDR range') !== false && Settings::bool('require_https'), 'security validates input before saving');

@unlink(getenv('XMH_TEST_DB'));
echo "\n$passes passed, $fails failed\n";
exit($fails ? 1 : 0);
