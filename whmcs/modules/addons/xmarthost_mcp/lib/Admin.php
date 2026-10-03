<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

/**
 * The module's page in WHMCS admin: Addons > XMart Host MCP.
 * Who may open it is set in Setup > Addon Modules > Access Control.
 */
class Admin
{
    const TABS = [
        'dashboard' => 'Dashboard',
        'connection' => 'API Connection',
        'connectors' => 'AI Connectors',
        'tools' => 'Tool Management',
        'activity' => 'Activity Log',
        'security' => 'Security',
        'guide' => 'Setup Guide',
    ];

    private $link;
    private $admin;
    private $tab;
    private $flash = [];
    private $newKey = null;

    public function __construct(array $vars)
    {
        $this->link = isset($vars['modulelink']) ? $vars['modulelink'] : 'addonmodules.php?module=xmarthost_mcp';
        $this->admin = self::adminName();
        $tab = isset($_REQUEST['tab']) ? (string) $_REQUEST['tab'] : 'dashboard';
        $this->tab = isset(self::TABS[$tab]) ? $tab : 'dashboard';
    }

    public function run()
    {
        Schema::install();
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xmh_action'])) {
            $this->handlePost((string) $_POST['xmh_action']);
        }
        echo $this->render();
    }

    // ------------------------------------------------------------------ helpers

    private static function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
    }

    private static function adminName()
    {
        $id = isset($_SESSION['adminid']) ? (int) $_SESSION['adminid'] : 0;
        if ($id) {
            $a = Capsule::table('tbladmins')->where('id', $id)->first(['username']);
            if ($a) {
                return $a->username;
            }
        }
        return 'admin';
    }

    private function csrf()
    {
        if (empty($_SESSION['xmh_csrf'])) {
            $_SESSION['xmh_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['xmh_csrf'];
    }

    private function formStart($action, $tab = null, $extra = '')
    {
        $t = $tab ? $tab : $this->tab;
        $whmcsToken = function_exists('generate_token') ? generate_token('plain') : '';
        return '<form method="post" action="' . self::e($this->link . '&tab=' . $t) . '" ' . $extra . '>'
            . '<input type="hidden" name="xmh_action" value="' . self::e($action) . '">'
            . '<input type="hidden" name="xmh_csrf" value="' . self::e($this->csrf()) . '">'
            . ($whmcsToken !== '' ? '<input type="hidden" name="token" value="' . self::e($whmcsToken) . '">' : '');
    }

    private function url($tab, array $q = [])
    {
        return $this->link . '&tab=' . $tab . ($q ? '&' . http_build_query($q) : '');
    }

    private function audit($text)
    {
        if (function_exists('logActivity')) {
            logActivity('XMart Host MCP: ' . $text);
        }
    }

    private function post($k, $default = '')
    {
        return isset($_POST[$k]) && !is_array($_POST[$k]) ? trim((string) $_POST[$k]) : $default;
    }

    private function since($seconds)
    {
        return date('Y-m-d H:i:s', time() - $seconds);
    }

    private function ago($date)
    {
        if (!$date) {
            return '<span class="xmh-muted">never</span>';
        }
        $d = time() - strtotime($date);
        if ($d < 60) {
            $s = 'just now';
        } elseif ($d < 3600) {
            $s = floor($d / 60) . ' min ago';
        } elseif ($d < 86400) {
            $s = floor($d / 3600) . ' h ago';
        } else {
            $s = floor($d / 86400) . ' d ago';
        }
        return '<span title="' . self::e($date) . '">' . $s . '</span>';
    }

    private function scopeBadge($scope)
    {
        $labels = ['read' => 'Read only', 'write' => 'Read & write', 'full' => 'Full access', 'r' => 'read', 'w' => 'write', 'f' => 'full'];
        $cls = ['r' => 'read', 'w' => 'write', 'f' => 'full'];
        $c = isset($cls[$scope]) ? $cls[$scope] : $scope;
        return '<span class="xmh-badge ' . self::e($c) . '">' . self::e(isset($labels[$scope]) ? $labels[$scope] : $scope) . '</span>';
    }

    // ------------------------------------------------------------------ POST actions

    private function handlePost($action)
    {
        $sent = isset($_POST['xmh_csrf']) ? (string) $_POST['xmh_csrf'] : '';
        if (empty($_SESSION['xmh_csrf']) || !hash_equals($_SESSION['xmh_csrf'], $sent)) {
            $this->flash[] = ['bad', 'Your session expired or the form was sent twice. Please try again.'];
            return;
        }
        try {
            switch ($action) {
                case 'save_connection':
                case 'test_connection':
                    $this->saveConnection($action === 'test_connection');
                    break;
                case 'create_token':
                    $this->createToken();
                    break;
                case 'revoke_token':
                    if (Tokens::revoke((int) $this->post('id'))) {
                        $this->audit('revoked connector #' . (int) $this->post('id'));
                        $this->flash[] = ['ok', 'Connector revoked. It stops working immediately.'];
                    }
                    break;
                case 'delete_token':
                    Tokens::delete((int) $this->post('id'));
                    $this->flash[] = ['ok', 'Revoked connector removed from the list.'];
                    break;
                case 'revoke_all':
                    $n = Capsule::table(Schema::TOKENS)->where('revoked', 0)->update(['revoked' => 1, 'revoked_at' => date('Y-m-d H:i:s')]);
                    $this->audit('revoked all connectors (' . $n . ')');
                    $this->flash[] = ['ok', $n . ' connector(s) revoked.'];
                    break;
                case 'save_tools':
                    $this->saveTools();
                    break;
                case 'save_security':
                    $this->saveSecurity();
                    break;
                case 'clear_logs':
                    $n = Capsule::table(Schema::LOGS)->delete();
                    $this->audit('cleared the activity log (' . $n . ' rows)');
                    $this->flash[] = ['ok', 'Activity log cleared.'];
                    break;
            }
        } catch (\InvalidArgumentException $e) {
            $this->flash[] = ['bad', $e->getMessage()];
        } catch (\Exception $e) {
            $this->flash[] = ['bad', 'Error: ' . $e->getMessage()];
        }
    }

    private function saveConnection($test)
    {
        $mode = $this->post('connection_mode') === 'local' ? 'local' : 'api';
        $url = $this->post('api_url');
        if ($url !== '' && !preg_match('#^https?://#i', $url)) {
            throw new \InvalidArgumentException('The API URL must start with https://');
        }
        Settings::setMany([
            'connection_mode' => $mode,
            'api_url' => $url,
            'api_identifier' => $this->post('api_identifier'),
            'verify_ssl' => isset($_POST['verify_ssl']) ? '1' : '0',
            'local_admin' => $this->post('local_admin'),
        ]);
        // Blank secret fields keep the stored value.
        if ($this->post('api_secret') !== '') {
            Settings::set('api_secret', $this->post('api_secret'));
        }
        if (isset($_POST['clear_accesskey'])) {
            Settings::set('api_accesskey', '');
        } elseif ($this->post('api_accesskey') !== '') {
            Settings::set('api_accesskey', $this->post('api_accesskey'));
        }
        $this->audit('updated the API connection settings');
        $this->flash[] = ['ok', 'Connection settings saved.'];
        if ($test) {
            $this->testConnection();
        }
    }

    private function testConnection()
    {
        $api = ApiClient::fromSettings();
        try {
            $res = $api->call('WhmcsDetails');
            $version = isset($res['whmcs']['version']) ? $res['whmcs']['version'] : (isset($res['whmcs']['canonicalversion']) ? $res['whmcs']['canonicalversion'] : '');
            $stats = $api->call('GetStats');
            $msg = 'Connected to WHMCS ' . $version . ' (' . ($api->mode() === 'local' ? 'internal API' : $api->url()) . '). '
                . 'Clients: ' . (isset($stats['clients_active']) ? $stats['clients_active'] : '?') . ' active.';
            Settings::setMany(['last_test_ok' => '1', 'last_test_at' => date('Y-m-d H:i:s'), 'last_test_msg' => $msg, 'whmcs_version' => $version]);
            $this->flash[] = ['ok', $msg];
        } catch (\Exception $e) {
            Settings::setMany(['last_test_ok' => '0', 'last_test_at' => date('Y-m-d H:i:s'), 'last_test_msg' => $e->getMessage()]);
            $this->flash[] = ['bad', 'Connection test failed: ' . $e->getMessage()];
        }
    }

    private function createToken()
    {
        $scope = $this->post('scope', 'read');
        $cats = isset($_POST['categories']) && is_array($_POST['categories']) ? array_map('strval', $_POST['categories']) : [];
        if (!$cats) {
            throw new \InvalidArgumentException('Pick at least one area this connector may use.');
        }
        $ips = Settings::splitList($this->post('allowed_ips'));
        $res = Tokens::create($this->post('name'), $scope, $cats, $ips, (int) $this->post('expires'), $this->admin);
        $this->newKey = $res['token'];
        $this->audit('created connector #' . $res['id'] . ' "' . $this->post('name') . '" with ' . $scope . ' access');
    }

    private function saveTools()
    {
        $enabled = isset($_POST['tools']) && is_array($_POST['tools']) ? array_map('strval', $_POST['tools']) : [];
        $disabled = array_values(array_diff(array_keys(Tools::definitions()), $enabled));
        Settings::set('disabled_tools', implode(',', $disabled));
        $this->audit('updated tool management (' . count($disabled) . ' disabled)');
        $this->flash[] = ['ok', 'Tool settings saved. ' . count($disabled) . ' tool(s) disabled.'];
    }

    private function saveSecurity()
    {
        $ips = Settings::splitList($this->post('global_ip_allow'));
        foreach ($ips as $ip) {
            if (!Net::validEntry($ip)) {
                throw new \InvalidArgumentException('Invalid IP or CIDR range: ' . $ip);
            }
        }
        $origins = Settings::splitList($this->post('allowed_origins'));
        foreach ($origins as $o) {
            if (!preg_match('#^https?://[a-z0-9.\-]+(:\d+)?$#i', $o)) {
                throw new \InvalidArgumentException('Invalid origin (use https://host): ' . $o);
            }
        }
        $blocked = Settings::splitList($this->post('blocked_actions'));
        foreach ($blocked as $b) {
            if (!preg_match('/^[A-Za-z][A-Za-z0-9]+$/', $b)) {
                throw new \InvalidArgumentException('Invalid API action name: ' . $b);
            }
        }
        Settings::setMany([
            'enabled' => isset($_POST['enabled']) ? '1' : '0',
            'require_https' => isset($_POST['require_https']) ? '1' : '0',
            'trust_proxy' => isset($_POST['trust_proxy']) ? '1' : '0',
            'log_params' => isset($_POST['log_params']) ? '1' : '0',
            'rate_limit' => (string) max(1, min(100000, (int) $this->post('rate_limit', '120'))),
            'auth_fail_limit' => (string) max(3, min(1000, (int) $this->post('auth_fail_limit', '10'))),
            'log_retention_days' => (string) max(1, min(3650, (int) $this->post('log_retention_days', '90'))),
            'global_ip_allow' => implode("\n", $ips),
            'allowed_origins' => implode("\n", $origins),
            'blocked_actions' => implode("\n", $blocked),
        ]);
        $this->audit('updated security settings');
        $this->flash[] = ['ok', 'Security settings saved.'];
    }

    // ------------------------------------------------------------------ page

    private function render()
    {
        $css = @file_get_contents(dirname(__DIR__) . '/assets/admin.css');
        $h = '<style>' . $css . '</style><div class="xmh">';
        $h .= $this->hero();
        $h .= '<nav class="xmh-tabs">';
        foreach (self::TABS as $k => $label) {
            $h .= '<a class="' . ($k === $this->tab ? 'active' : '') . '" href="' . self::e($this->url($k)) . '">' . self::e($label) . '</a>';
        }
        $h .= '</nav>';
        foreach ($this->flash as $f) {
            $h .= '<div class="xmh-alert ' . $f[0] . '">' . self::e($f[1]) . '</div>';
        }
        $method = 'tab' . str_replace(' ', '', ucwords(str_replace('_', ' ', $this->tab)));
        $h .= $this->$method();
        $h .= '<div class="xmh-footer">XMart Host MCP for WHMCS v' . XMH_MCP_VERSION . ' &middot; Model Context Protocol server for Claude, ChatGPT and other AI assistants</div>';
        $h .= '</div>' . $this->script();
        return $h;
    }

    private function hero()
    {
        $on = Settings::bool('enabled');
        $test = Settings::get('last_test_ok');
        $apiState = $test === '1' ? ['ok', 'WHMCS API connected'] : ($test === '0' ? ['bad', 'API connection failed'] : ['warn', 'API not tested']);
        $logo = '<svg width="28" height="28" viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M6 6l8 10-8 10h5l5.5-7 5.5 7h5l-8-10 8-10h-5l-5.5 7L11 6H6z" fill="#fff"/><circle cx="26" cy="6" r="3" fill="#ff7a1a"/></svg>';
        return '<div class="xmh-hero"><div class="xmh-brand"><div class="xmh-logo">' . $logo . '</div><div><h2>XMart Host &middot; WHMCS MCP Server</h2>'
            . '<p>Connect Claude, ChatGPT and other AI assistants to your WHMCS, with full read &amp; write control.</p></div></div>'
            . '<div class="xmh-pills">'
            . '<span class="xmh-pill"><i class="xmh-dot ' . ($on ? 'ok' : 'bad') . '"></i>' . ($on ? 'MCP server online' : 'MCP server off') . '</span>'
            . '<span class="xmh-pill"><i class="xmh-dot ' . $apiState[0] . '"></i>' . $apiState[1] . '</span>'
            . '<span class="xmh-pill">v' . XMH_MCP_VERSION . '</span>'
            . '</div></div>';
    }

    // ------------------------------------------------------------------ dashboard

    private function tabDashboard()
    {
        $day = $this->since(86400);
        $logs = function () {
            return Capsule::table(Schema::LOGS);
        };
        $activeTokens = Capsule::table(Schema::TOKENS)->where('revoked', 0)->where(function ($q) {
            $q->whereNull('expires_at')->orWhere('expires_at', '>', date('Y-m-d H:i:s'));
        })->count();
        $calls = $logs()->where('event', 'tool_call')->where('created_at', '>=', $day)->count();
        $changes = $logs()->where('event', 'tool_call')->whereIn('access', ['w', 'f'])->where('status', 'ok')->where('created_at', '>=', $day)->count();
        $errors = $logs()->where('event', 'tool_call')->where('status', 'error')->where('created_at', '>=', $day)->count();
        $blocked = $logs()->where('status', 'denied')->where('created_at', '>=', $day)->count();

        $h = '<div class="xmh-grid xmh-kpis">'
            . $this->kpi('Active connectors', $activeTokens, 'AI apps that can connect', 'accent')
            . $this->kpi('Tool calls · 24h', $calls, 'Requests from AI assistants', '')
            . $this->kpi('Changes made · 24h', $changes, 'Successful write actions', 'warn')
            . $this->kpi('Errors · 24h', $errors, 'Failed tool calls', $errors ? 'bad' : 'ok')
            . $this->kpi('Blocked · 24h', $blocked, 'Bad keys, IPs, permissions, limits', $blocked ? 'bad' : 'ok')
            . '</div>';

        $h .= '<div class="xmh-grid xmh-two">';
        $h .= '<div class="xmh-card"><h3>Activity, last 14 days</h3><p class="xmh-sub">Tool calls per day.</p>' . $this->chart() . '</div>';
        $h .= '<div class="xmh-card"><h3>Getting started</h3><p class="xmh-sub">Three steps to talk to WHMCS from your AI.</p>' . $this->checklist($activeTokens) . '</div>';
        $h .= '</div><div style="height:16px"></div>';

        $h .= '<div class="xmh-grid xmh-two">';
        $h .= '<div class="xmh-card"><h3>Recent activity</h3><p class="xmh-sub">Latest requests from connected AI assistants. <a href="' . self::e($this->url('activity')) . '">View all</a></p>'
            . $this->logTable($logs()->orderBy('id', 'desc')->limit(10)->get(), false) . '</div>';

        $top = $logs()->where('event', 'tool_call')->where('created_at', '>=', $this->since(7 * 86400))
            ->groupBy('tool')->select('tool', Capsule::raw('COUNT(*) AS n'))->orderBy('n', 'desc')->limit(8)->get();
        $t = '<table class="xmh-table"><thead><tr><th>Tool</th><th class="num">Calls</th></tr></thead><tbody>';
        foreach ($top as $r) {
            $t .= '<tr><td><code>' . self::e($r->tool) . '</code></td><td class="num">' . (int) $r->n . '</td></tr>';
        }
        if (!count($top)) {
            $t .= '<tr><td colspan="2" class="xmh-empty">No tool calls yet.</td></tr>';
        }
        $t .= '</tbody></table>';
        $h .= '<div class="xmh-card"><h3>Most used tools · 7 days</h3><p class="xmh-sub">What your AI assistants do most.</p>' . $t . '</div>';
        $h .= '</div>';
        return $h;
    }

    private function kpi($label, $value, $hint, $cls)
    {
        return '<div class="xmh-card xmh-kpi ' . $cls . '"><div class="label">' . self::e($label) . '</div><div class="value">' . number_format((int) $value) . '</div><div class="hint">' . self::e($hint) . '</div></div>';
    }

    private function checklist($activeTokens)
    {
        $connected = Capsule::table(Schema::LOGS)->where('event', 'connect')->exists();
        $steps = [
            [Settings::get('last_test_ok') === '1', 'Connect the WHMCS API', 'Enter your API identifier and secret, then test.', 'connection'],
            [$activeTokens > 0, 'Create an AI connector', 'Generate a connector URL with the access you want.', 'connectors'],
            [$connected, 'Add it to Claude or ChatGPT', 'Paste the URL as a custom connector.', 'guide'],
        ];
        $h = '<ul class="xmh-steps">';
        foreach ($steps as $i => $s) {
            $h .= '<li><div class="xmh-check ' . ($s[0] ? 'done' : '') . '">' . ($s[0] ? '&#10003;' : ($i + 1)) . '</div><div><strong><a href="' . self::e($this->url($s[3])) . '">' . self::e($s[1]) . '</a></strong><span>' . self::e($s[2]) . '</span></div></li>';
        }
        return $h . '</ul>';
    }

    private function chart()
    {
        $days = 14;
        $start = date('Y-m-d', time() - ($days - 1) * 86400);
        $rows = Capsule::table(Schema::LOGS)->where('event', 'tool_call')->where('created_at', '>=', $start . ' 00:00:00')
            ->groupBy(Capsule::raw('SUBSTR(created_at, 1, 10)'), 'status')
            ->select(Capsule::raw('SUBSTR(created_at, 1, 10) AS d'), 'status', Capsule::raw('COUNT(*) AS n'))->get();
        $data = [];
        for ($i = 0; $i < $days; $i++) {
            $data[date('Y-m-d', strtotime($start) + $i * 86400)] = ['ok' => 0, 'bad' => 0];
        }
        foreach ($rows as $r) {
            if (isset($data[$r->d])) {
                $data[$r->d][$r->status === 'ok' ? 'ok' : 'bad'] += (int) $r->n;
            }
        }
        $max = 1;
        foreach ($data as $v) {
            $max = max($max, $v['ok'] + $v['bad']);
        }
        $w = 700;
        $hgt = 200;
        $pad = 26;
        $bw = ($w - $pad) / $days;
        $svg = '<svg viewBox="0 0 ' . $w . ' ' . ($hgt + 24) . '" role="img" aria-label="Tool calls per day">';
        for ($g = 0; $g <= 4; $g++) {
            $y = 6 + ($hgt - 6) * $g / 4;
            $svg .= '<line x1="' . $pad . '" x2="' . $w . '" y1="' . $y . '" y2="' . $y . '" stroke="#eef0f5"/>';
            $svg .= '<text x="' . ($pad - 6) . '" y="' . ($y + 4) . '" font-size="10" text-anchor="end" fill="#94a3b8">' . round($max * (4 - $g) / 4) . '</text>';
        }
        $i = 0;
        foreach ($data as $d => $v) {
            $x = $pad + $i * $bw + $bw * 0.18;
            $bwi = $bw * 0.64;
            $hOk = ($hgt - 6) * $v['ok'] / $max;
            $hBad = ($hgt - 6) * $v['bad'] / $max;
            $title = '<title>' . $d . ': ' . $v['ok'] . ' ok, ' . $v['bad'] . ' failed/blocked</title>';
            if ($hOk > 0) {
                $svg .= '<rect x="' . round($x, 1) . '" y="' . round($hgt - $hOk, 1) . '" width="' . round($bwi, 1) . '" height="' . round($hOk, 1) . '" rx="3" fill="url(#xmhg)">' . $title . '</rect>';
            }
            if ($hBad > 0) {
                $svg .= '<rect x="' . round($x, 1) . '" y="' . round($hgt - $hOk - $hBad, 1) . '" width="' . round($bwi, 1) . '" height="' . round($hBad, 1) . '" rx="3" fill="#e5484d">' . $title . '</rect>';
            }
            if ($i % 2 === 0 || $days <= 7) {
                $svg .= '<text x="' . round($x + $bwi / 2, 1) . '" y="' . ($hgt + 16) . '" font-size="10" text-anchor="middle" fill="#94a3b8">' . date('M j', strtotime($d)) . '</text>';
            }
            $i++;
        }
        $svg .= '<defs><linearGradient id="xmhg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7b3fe4"/><stop offset="1" stop-color="#2546f0"/></linearGradient></defs></svg>';
        return '<div class="xmh-chart">' . $svg . '<div class="xmh-legend"><span><i style="background:#2546f0"></i>Successful</span><span><i style="background:#e5484d"></i>Failed or blocked</span></div></div>';
    }

    private function logTable($rows, $full)
    {
        $h = '<div class="xmh-table-wrap"><table class="xmh-table"><thead><tr><th>Time</th><th>Connector</th><th>Event / tool</th>'
            . ($full ? '<th>API action</th><th>Access</th>' : '') . '<th>Status</th>' . ($full ? '<th>Details</th><th>IP</th><th class="num">ms</th>' : '') . '</tr></thead><tbody>';
        $n = 0;
        foreach ($rows as $r) {
            $n++;
            $what = $r->tool ? '<code>' . self::e($r->tool) . '</code>' : self::e(str_replace('_', ' ', $r->event));
            $h .= '<tr><td class="xmh-small" style="white-space:nowrap">' . $this->ago($r->created_at) . '</td>'
                . '<td>' . ($r->token_name ? self::e($r->token_name) : '<span class="xmh-muted">-</span>') . '</td>'
                . '<td>' . $what . ($full ? '' : ($r->message && $r->status !== 'ok' ? '<div class="xmh-small xmh-muted">' . self::e(mb_substr($r->message, 0, 120)) . '</div>' : '')) . '</td>';
            if ($full) {
                $h .= '<td class="xmh-mono">' . self::e($r->api_action) . '</td><td>' . ($r->access ? $this->scopeBadge($r->access) : '') . '</td>';
            }
            $h .= '<td><span class="xmh-badge ' . self::e($r->status) . '">' . self::e($r->status) . '</span></td>';
            if ($full) {
                $details = $r->message ? '<div class="xmh-small">' . self::e(mb_substr($r->message, 0, 300)) . '</div>' : '';
                if ($r->params && $r->params !== '[]') {
                    $pretty = json_decode($r->params, true);
                    $details .= '<details class="xmh-params"><summary>parameters</summary><pre>' . self::e(is_array($pretty) ? json_encode($pretty, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : $r->params) . '</pre></details>';
                }
                $h .= '<td>' . $details . '</td><td class="xmh-mono">' . self::e($r->ip) . '</td><td class="num">' . (int) $r->duration_ms . '</td>';
            }
            $h .= '</tr>';
        }
        if (!$n) {
            $h .= '<tr><td colspan="' . ($full ? 9 : 4) . '" class="xmh-empty">No activity yet. Once an AI assistant connects, every request shows up here.</td></tr>';
        }
        return $h . '</tbody></table></div>';
    }

    // ------------------------------------------------------------------ connection

    private function tabConnection()
    {
        $mode = Settings::get('connection_mode');
        $hasSecret = Settings::get('api_secret') !== '';
        $hasKey = Settings::get('api_accesskey') !== '';
        $serverIp = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $h = '';
        if (Settings::get('last_test_at') !== '') {
            $ok = Settings::get('last_test_ok') === '1';
            $h .= '<div class="xmh-alert ' . ($ok ? 'ok' : 'bad') . '"><strong>' . ($ok ? 'Connected' : 'Not connected') . '</strong> &middot; last tested ' . $this->ago(Settings::get('last_test_at')) . '<br>' . self::e(Settings::get('last_test_msg')) . '</div>';
        }
        $h .= '<div class="xmh-grid xmh-two"><div class="xmh-card xmh-form">' . $this->formStart('save_connection');
        $h .= '<h3>WHMCS API connection</h3><p class="xmh-sub">The MCP server runs every AI request through the official WHMCS API with these credentials, so WHMCS\'s own API role permissions apply on top of the connector\'s permissions.</p>';
        $h .= '<div class="xmh-field"><label>Connection method</label><div class="xmh-choice">'
            . '<label><input type="radio" name="connection_mode" value="api"' . ($mode !== 'local' ? ' checked' : '') . '>API credentials (recommended)<small>API identifier + secret over HTTPS. Permissions follow the credential\'s API role.</small></label>'
            . '<label><input type="radio" name="connection_mode" value="local"' . ($mode === 'local' ? ' checked' : '') . '>Internal API<small>No credentials: runs in-process with localAPI() as an admin user. Use when API IP restrictions get in the way.</small></label>'
            . '</div></div>';
        $h .= '<div class="row2">'
            . '<div class="xmh-field"><label for="xmh-url">API URL</label><input id="xmh-url" type="url" name="api_url" value="' . self::e(Settings::get('api_url')) . '" placeholder="' . self::e(Settings::systemUrl() . 'includes/api.php') . '"><div class="help">Your WHMCS URL or its <code>/includes/api.php</code>. Empty = this WHMCS.</div></div>'
            . '<div class="xmh-field"><label for="xmh-id">API identifier</label><input id="xmh-id" type="text" name="api_identifier" autocomplete="off" value="' . self::e(Settings::get('api_identifier')) . '"></div>'
            . '<div class="xmh-field"><label for="xmh-secret">API secret</label><input id="xmh-secret" type="password" name="api_secret" autocomplete="new-password" placeholder="' . ($hasSecret ? '•••••••• saved (leave blank to keep)' : '') . '"><div class="help">Stored encrypted with your WHMCS encryption key.</div></div>'
            . '<div class="xmh-field"><label for="xmh-ak">API access key <span class="xmh-muted">(optional)</span></label><input id="xmh-ak" type="password" name="api_accesskey" autocomplete="new-password" placeholder="' . ($hasKey ? '•••••••• saved (leave blank to keep)' : '$api_access_key from configuration.php') . '">'
            . ($hasKey ? '<label class="xmh-switch xmh-small" style="margin-top:6px"><input type="checkbox" name="clear_accesskey"> Remove saved access key</label>' : '') . '<div class="help">Lets the API skip the IP restriction.</div></div>'
            . '<div class="xmh-field"><label for="xmh-la">Admin user for internal API</label><input id="xmh-la" type="text" name="local_admin" value="' . self::e(Settings::get('local_admin')) . '" placeholder="' . self::e($this->admin) . '"><div class="help">Only for the internal method. Actions are logged as this admin.</div></div>'
            . '<div class="xmh-field"><label>&nbsp;</label><label class="xmh-switch"><input type="checkbox" name="verify_ssl"' . (Settings::bool('verify_ssl') ? ' checked' : '') . '>Verify SSL certificate<small>Turn off only for a self-signed certificate on a private network.</small></label></div>'
            . '</div>';
        $h .= '<div class="xmh-actions"><button class="xmh-btn primary" type="submit" name="xmh_action" value="test_connection">Save &amp; test connection</button><button class="xmh-btn ghost" type="submit">Save only</button></div></form></div>';

        $h .= '<div class="xmh-card xmh-guide"><h3>Create the API credential</h3><p class="xmh-sub">One time, in WHMCS admin:</p><ol>'
            . '<li><strong>System Settings &rsaquo; API Credentials</strong> (Setup &rsaquo; Staff Management &rsaquo; Manage API Credentials).</li>'
            . '<li><strong>API Roles &rsaquo; Create API Role</strong>, name it <em>XMart Host AI</em> and tick <strong>all</strong> permissions (or only what the AI should do).</li>'
            . '<li><strong>API Credentials &rsaquo; Generate New API Credential</strong>, pick an admin user and the role above.</li>'
            . '<li>Copy the <strong>identifier</strong> and <strong>secret</strong> here, then <strong>Save &amp; test</strong>.</li>'
            . '<li>If the test returns HTTP 403, add <code>' . self::e($serverIp ? $serverIp : 'this server\'s IP') . '</code> under <strong>General Settings &rsaquo; Security &rsaquo; API IP Access Restriction</strong>, or set an API access key.</li>'
            . '</ol></div></div>';
        return $h;
    }

    // ------------------------------------------------------------------ connectors

    private function tabConnectors()
    {
        $h = '';
        if ($this->newKey) {
            $url = Settings::connectorUrl($this->newKey);
            $h .= '<div class="xmh-secret"><h3>&#10003; Connector created: copy it now</h3><p>This key is shown <strong>only once</strong>. Only its hash is stored, so it cannot be shown again. Treat the URL like a password.</p>'
                . '<label class="xmh-small"><strong>Connector URL</strong> (paste into Claude / ChatGPT)</label><div class="xmh-copy"><input type="text" readonly id="xmh-newurl" value="' . self::e($url) . '"><button type="button" class="xmh-btn primary" data-copy="xmh-newurl">Copy URL</button></div>'
                . '<label class="xmh-small"><strong>Server URL + Bearer key</strong> (for clients that support an Authorization header)</label><div class="xmh-copy"><input type="text" readonly id="xmh-ep" value="' . self::e(Settings::endpointUrl()) . '"><button type="button" class="xmh-btn ghost" data-copy="xmh-ep">Copy</button></div>'
                . '<div class="xmh-copy"><input type="text" readonly id="xmh-newkey" value="' . self::e($this->newKey) . '"><button type="button" class="xmh-btn ghost" data-copy="xmh-newkey">Copy key</button></div>'
                . '<p class="xmh-small" style="margin:0"><strong>Claude:</strong> Settings &rsaquo; Connectors &rsaquo; Add custom connector &rsaquo; paste the URL. &nbsp; <strong>ChatGPT:</strong> Settings &rsaquo; Apps &amp; Connectors &rsaquo; Create &rsaquo; paste the URL, Authentication: none. <a href="' . self::e($this->url('guide')) . '">Full guide</a></p></div>';
        }

        $h .= '<div class="xmh-card xmh-form">' . $this->formStart('create_token') . '<h3>Create an AI connector</h3><p class="xmh-sub">Each AI app (or person) gets its own connector, so you can see and revoke them one by one.</p>';
        $h .= '<div class="row2"><div class="xmh-field"><label for="xmh-name">Name</label><input id="xmh-name" type="text" name="name" maxlength="100" placeholder="e.g. Claude - Ali (support)" required></div>'
            . '<div class="xmh-field"><label for="xmh-exp">Expires</label><select id="xmh-exp" name="expires"><option value="0">Never</option><option value="7">In 7 days</option><option value="30">In 30 days</option><option value="90" selected>In 90 days</option><option value="180">In 180 days</option><option value="365">In 1 year</option></select></div></div>';
        $h .= '<div class="xmh-field"><label>Access level</label><div class="xmh-choice">'
            . '<label><input type="radio" name="scope" value="read">Read only<small>View clients, invoices, tickets, reports. Changes nothing.</small></label>'
            . '<label><input type="radio" name="scope" value="write" checked>Read &amp; write<small>Also create and update: clients, orders, products, invoices, tickets, provision &amp; suspend.</small></label>'
            . '<label><input type="radio" name="scope" value="full">Full access (A&ndash;Z)<small>Everything, including delete, terminate, SSO links and system settings.</small></label>'
            . '</div></div>';
        $h .= '<div class="xmh-field"><label>Areas this connector may use <a href="#" class="xmh-small" data-checkall="categories[]">select all</a></label><div class="xmh-cats">';
        foreach (Catalog::CATEGORIES as $k => $desc) {
            $h .= '<label><input type="checkbox" name="categories[]" value="' . self::e($k) . '" checked><span>' . self::e($k) . '<small>' . self::e($desc) . '</small></span></label>';
        }
        $h .= '</div></div>';
        $h .= '<div class="xmh-field"><label for="xmh-ips">Allowed IPs <span class="xmh-muted">(optional)</span></label><textarea id="xmh-ips" name="allowed_ips" placeholder="One IP or CIDR range per line. Empty = any IP."></textarea><div class="help">Claude and ChatGPT call from their cloud, so leave empty for them unless you know their current egress ranges.</div></div>';
        $h .= '<div class="xmh-actions"><button class="xmh-btn primary" type="submit">Generate connector</button></div></form></div>';

        $rows = Tokens::all();
        $h .= '<div class="xmh-card"><h3>Connectors</h3><p class="xmh-sub">Revoking stops a connector immediately.</p><div class="xmh-table-wrap"><table class="xmh-table"><thead><tr><th>Name</th><th>Key</th><th>Access</th><th>Areas</th><th>Last used</th><th class="num">Calls</th><th>Expires</th><th>Created</th><th></th></tr></thead><tbody>';
        $n = 0;
        foreach ($rows as $r) {
            $n++;
            $expired = $r->expires_at && strtotime($r->expires_at) < time();
            $cats = Settings::splitList($r->categories);
            $status = $r->revoked ? '<span class="xmh-badge off">revoked</span>' : ($expired ? '<span class="xmh-badge off">expired</span>' : '');
            $h .= '<tr' . ($r->revoked || $expired ? ' style="opacity:.6"' : '') . '><td><strong>' . self::e($r->name) . '</strong> ' . $status
                . ($r->allowed_ips ? '<div class="xmh-small xmh-muted">IPs: ' . self::e(str_replace("\n", ', ', $r->allowed_ips)) . '</div>' : '') . '</td>'
                . '<td class="xmh-mono">' . self::e($r->token_prefix) . '&hellip;</td>'
                . '<td>' . $this->scopeBadge($r->scope) . '</td>'
                . '<td>' . ($cats ? implode(' ', array_map(function ($c) {
                    return '<span class="xmh-badge cat">' . self::e($c) . '</span>';
                }, $cats)) : '<span class="xmh-muted">All</span>') . '</td>'
                . '<td class="xmh-small">' . $this->ago($r->last_used_at) . ($r->last_ip ? '<div class="xmh-mono xmh-muted">' . self::e($r->last_ip) . '</div>' : '') . '</td>'
                . '<td class="num">' . number_format((int) $r->calls) . '</td>'
                . '<td class="xmh-small">' . ($r->expires_at ? self::e(substr($r->expires_at, 0, 10)) : 'never') . '</td>'
                . '<td class="xmh-small">' . self::e(substr($r->created_at, 0, 10)) . '<div class="xmh-muted">' . self::e($r->created_by) . '</div></td><td>';
            if (!$r->revoked) {
                $h .= $this->formStart('revoke_token', 'connectors', 'onsubmit="return confirm(\'Revoke this connector? AI apps using it lose access immediately.\')"') . '<input type="hidden" name="id" value="' . (int) $r->id . '"><button class="xmh-btn danger sm">Revoke</button></form>';
            } else {
                $h .= $this->formStart('delete_token', 'connectors') . '<input type="hidden" name="id" value="' . (int) $r->id . '"><button class="xmh-btn ghost sm">Remove</button></form>';
            }
            $h .= '</td></tr>';
        }
        if (!$n) {
            $h .= '<tr><td colspan="9" class="xmh-empty">No connectors yet. Create one above.</td></tr>';
        }
        return $h . '</tbody></table></div></div>';
    }

    // ------------------------------------------------------------------ tools

    private function tabTools()
    {
        $defs = Tools::definitions();
        $disabled = Settings::lines('disabled_tools');
        $groups = [];
        foreach ($defs as $name => $d) {
            $cat = in_array($name, Tools::GENERIC, true) ? 'Generic' : $d[1];
            $groups[$cat][$name] = $d;
        }
        $total = count($defs);
        $off = count(array_intersect(array_keys($defs), $disabled));
        $h = '<div class="xmh-alert info"><strong>Tool management.</strong> Turn individual MCP tools on or off. Disabled tools are hidden from AI assistants and refused if called. '
            . 'Connector access levels and areas still apply. <br><strong>' . ($total - $off) . '</strong> enabled &middot; <strong>' . $off . '</strong> disabled &middot; ' . $total . ' total &middot; plus ' . count(Catalog::ACTIONS) . ' WHMCS API actions through <code>whmcs_api_call</code>.</div>';
        $h .= $this->formStart('save_tools', 'tools', 'class="xmh-form"');
        $order = array_merge(['Generic'], array_keys(Catalog::CATEGORIES));
        foreach ($order as $cat) {
            if (empty($groups[$cat])) {
                continue;
            }
            $on = count(array_diff(array_keys($groups[$cat]), $disabled));
            $gid = 'xmh-g-' . strtolower($cat);
            $label = $cat === 'Generic' ? 'Any WHMCS API action' : $cat;
            $h .= '<div class="xmh-toolgroup"><div class="head"><span>' . self::e($label) . '<span class="meta">' . $on . '/' . count($groups[$cat]) . ' enabled</span></span>'
                . '<label class="xmh-toggle" title="Turn the whole group on or off"><input type="checkbox" data-group="' . $gid . '"' . ($on ? ' checked' : '') . '><span></span></label></div>';
            foreach ($groups[$cat] as $name => $d) {
                $h .= '<label class="xmh-toolrow"><input type="checkbox" class="' . $gid . '" name="tools[]" value="' . self::e($name) . '"' . (in_array($name, $disabled, true) ? '' : ' checked') . '>'
                    . '<span><code>' . self::e($name) . '</code></span><span class="lvl">' . $this->scopeBadge($d[2]) . '</span><span class="desc xmh-small">' . self::e($d[3]) . '</span></label>';
            }
            $h .= '</div>';
        }
        $h .= '<div class="xmh-actions"><button class="xmh-btn primary" type="submit">Save tool settings</button></div></form>';

        $h .= '<div class="xmh-card" style="margin-top:16px"><h3>WHMCS API actions</h3><p class="xmh-sub">Everything <code>whmcs_api_call</code> can run, and the access level each needs. Block single actions under Security.</p><div class="xmh-table-wrap"><table class="xmh-table"><thead><tr><th>Action</th><th>Area</th><th>Access</th><th>Parameters</th></tr></thead><tbody>';
        $blocked = array_map('strtolower', Settings::lines('blocked_actions'));
        foreach (Catalog::ACTIONS as $a => $info) {
            $h .= '<tr><td class="xmh-mono">' . self::e($a) . (in_array(strtolower($a), $blocked, true) ? ' <span class="xmh-badge error">blocked</span>' : '') . '</td><td>' . self::e($info[0]) . '</td><td>' . $this->scopeBadge($info[1]) . '</td><td class="xmh-small xmh-muted">' . self::e($info[2]) . '</td></tr>';
        }
        return $h . '</tbody></table></div></div>';
    }

    // ------------------------------------------------------------------ activity

    private function tabActivity()
    {
        $status = isset($_GET['status']) ? (string) $_GET['status'] : '';
        $token = isset($_GET['token']) ? (int) $_GET['token'] : 0;
        $q = isset($_GET['q']) ? trim((string) $_GET['q']) : '';
        $page = max(1, isset($_GET['p']) ? (int) $_GET['p'] : 1);
        $per = 50;

        $query = Capsule::table(Schema::LOGS);
        if (in_array($status, ['ok', 'error', 'denied'], true)) {
            $query->where('status', $status);
        }
        if ($token) {
            $query->where('token_id', $token);
        }
        if ($q !== '') {
            $like = '%' . str_replace(['%', '_'], ['\%', '\_'], $q) . '%';
            $query->where(function ($w) use ($like) {
                $w->where('tool', 'like', $like)->orWhere('api_action', 'like', $like)->orWhere('message', 'like', $like)->orWhere('ip', 'like', $like)->orWhere('token_name', 'like', $like);
            });
        }
        $total = (clone $query)->count();
        $rows = $query->orderBy('id', 'desc')->offset(($page - 1) * $per)->limit($per)->get();

        $h = '<div class="xmh-card"><form method="get" class="xmh-filters"><input type="hidden" name="module" value="xmarthost_mcp"><input type="hidden" name="tab" value="activity">'
            . '<div><label class="xmh-small"><strong>Search</strong></label><input type="text" name="q" value="' . self::e($q) . '" placeholder="Tool, action, message, IP"></div>'
            . '<div><label class="xmh-small"><strong>Status</strong></label><select name="status"><option value="">All</option>';
        foreach (['ok' => 'Successful', 'error' => 'Errors', 'denied' => 'Blocked'] as $k => $v) {
            $h .= '<option value="' . $k . '"' . ($status === $k ? ' selected' : '') . '>' . $v . '</option>';
        }
        $h .= '</select></div><div><label class="xmh-small"><strong>Connector</strong></label><select name="token"><option value="0">All</option>';
        foreach (Tokens::all() as $t) {
            $h .= '<option value="' . (int) $t->id . '"' . ($token === (int) $t->id ? ' selected' : '') . '>' . self::e($t->name) . '</option>';
        }
        $h .= '</select></div><div><button class="xmh-btn ghost" type="submit">Filter</button></div></form>';
        $h .= $this->logTable($rows, true);
        $pages = max(1, (int) ceil($total / $per));
        $qs = ['status' => $status, 'token' => $token, 'q' => $q];
        $h .= '<div class="xmh-pager"><span>' . number_format($total) . ' entries &middot; page ' . $page . ' of ' . $pages . '</span><span class="xmh-actions" style="margin:0">'
            . ($page > 1 ? '<a class="xmh-btn ghost sm" href="' . self::e($this->url('activity', array_merge($qs, ['p' => $page - 1]))) . '">&larr; Newer</a>' : '')
            . ($page < $pages ? '<a class="xmh-btn ghost sm" href="' . self::e($this->url('activity', array_merge($qs, ['p' => $page + 1]))) . '">Older &rarr;</a>' : '')
            . '</span></div></div>';
        $h .= $this->formStart('clear_logs', 'activity', 'onsubmit="return confirm(\'Delete the whole activity log?\')"') . '<button class="xmh-btn danger sm">Clear activity log</button> <span class="xmh-small xmh-muted">Entries older than ' . (int) Settings::get('log_retention_days') . ' days are removed automatically by the daily cron.</span></form>';
        return $h;
    }

    // ------------------------------------------------------------------ security

    private function tabSecurity()
    {
        $chk = function ($k) {
            return Settings::bool($k) ? ' checked' : '';
        };
        $h = '<div class="xmh-card xmh-form">' . $this->formStart('save_security') . '<h3>Security settings</h3><p class="xmh-sub">Apply to every connector.</p>';
        $h .= '<div class="row2">'
            . '<div class="xmh-field"><label class="xmh-switch"><input type="checkbox" name="enabled"' . $chk('enabled') . '>MCP server enabled<small>Master switch. Off = every AI connector is refused.</small></label></div>'
            . '<div class="xmh-field"><label class="xmh-switch"><input type="checkbox" name="require_https"' . $chk('require_https') . '>Require HTTPS<small>Refuse plain HTTP requests, so keys are never sent unencrypted.</small></label></div>'
            . '<div class="xmh-field"><label class="xmh-switch"><input type="checkbox" name="trust_proxy"' . $chk('trust_proxy') . '>Behind Cloudflare / a reverse proxy<small>Read the client IP and HTTPS from proxy headers. Only enable if WHMCS is really behind one.</small></label></div>'
            . '<div class="xmh-field"><label class="xmh-switch"><input type="checkbox" name="log_params"' . $chk('log_params') . '>Log tool parameters<small>Store each call\'s arguments (passwords, keys and card data are always masked).</small></label></div>'
            . '<div class="xmh-field"><label>Rate limit (tool calls per minute, per connector)</label><input type="number" min="1" name="rate_limit" value="' . (int) Settings::get('rate_limit') . '"></div>'
            . '<div class="xmh-field"><label>Lock out an IP after this many bad keys (15 min)</label><input type="number" min="3" name="auth_fail_limit" value="' . (int) Settings::get('auth_fail_limit') . '"></div>'
            . '<div class="xmh-field"><label>Keep activity log (days)</label><input type="number" min="1" name="log_retention_days" value="' . (int) Settings::get('log_retention_days') . '"></div>'
            . '</div>';
        $h .= '<div class="row2">'
            . '<div class="xmh-field"><label>Global IP allowlist</label><textarea name="global_ip_allow" placeholder="Empty = any IP">' . self::e(Settings::get('global_ip_allow')) . '</textarea><div class="help">One IP or CIDR per line. Applies to all connectors.</div></div>'
            . '<div class="xmh-field"><label>Allowed browser origins</label><textarea name="allowed_origins">' . self::e(Settings::get('allowed_origins')) . '</textarea><div class="help">Requests that carry an Origin header must come from one of these (DNS-rebinding protection). Server-to-server connectors send none.</div></div>'
            . '<div class="xmh-field"><label>Blocked API actions</label><textarea name="blocked_actions" placeholder="e.g. DeleteClient&#10;DecryptPassword">' . self::e(Settings::get('blocked_actions')) . '</textarea><div class="help">Never run, whatever the connector\'s access level.</div></div>'
            . '</div>';
        $h .= '<div class="xmh-actions"><button class="xmh-btn primary" type="submit">Save security settings</button></div></form></div>';

        $h .= '<div class="xmh-grid xmh-half"><div class="xmh-card"><h3>How this module protects WHMCS</h3><ul class="xmh-small" style="padding-left:18px;margin:6px 0 0">'
            . '<li>Connector keys are 192-bit random values; only their SHA-256 hash is stored.</li>'
            . '<li>The WHMCS API secret is encrypted with your WHMCS encryption key.</li>'
            . '<li>Three access levels (read, write, full) plus per-area permissions per connector, per-tool switches and an action blocklist.</li>'
            . '<li>The WHMCS API role of the credential still limits what is possible.</li>'
            . '<li>Rate limiting per connector, lockout of IPs that send bad keys, optional IP allowlists and expiry dates.</li>'
            . '<li>HTTPS enforcement and Origin checks.</li>'
            . '<li>Every request is logged with connector, tool, API action, IP and duration; sensitive values are masked.</li>'
            . '<li>The AI is told to confirm destructive steps with you and to treat ticket text as data.</li>'
            . '</ul></div>';
        $h .= '<div class="xmh-card"><h3>Emergency</h3><p class="xmh-sub">Suspect a leaked URL? Revoke every connector at once, then create new ones.</p>'
            . $this->formStart('revoke_all', 'security', 'onsubmit="return confirm(\'Revoke ALL connectors now?\')"') . '<button class="xmh-btn danger">Revoke all connectors</button></form></div></div>';
        return $h;
    }

    // ------------------------------------------------------------------ guide

    private function tabGuide()
    {
        $ep = Settings::endpointUrl();
        $url = $ep . '?key=xmh_your_key';
        $h = '<div class="xmh-alert info">Your MCP endpoint: <code>' . self::e($ep) . '</code>. Create a connector under <a href="' . self::e($this->url('connectors')) . '">AI Connectors</a> to get your personal URL.</div>';
        $h .= '<div class="xmh-grid xmh-half xmh-guide">';
        $h .= '<div class="xmh-card"><h3>Claude (claude.ai, Desktop, mobile)</h3><ol>'
            . '<li>Open <strong>Settings &rsaquo; Connectors</strong> (Team/Enterprise: <strong>Admin settings &rsaquo; Connectors</strong>).</li>'
            . '<li>Click <strong>Add custom connector</strong>.</li>'
            . '<li>Name: <em>XMart Host WHMCS</em>. URL: paste your connector URL. Leave OAuth fields empty.</li>'
            . '<li>Click <strong>Add</strong>, then enable it in a chat from the <strong>+ &rsaquo; Connectors</strong> menu.</li>'
            . '<li>Ask: <em>"Give me the WHMCS system status overview."</em></li></ol></div>';
        $h .= '<div class="xmh-card"><h3>ChatGPT</h3><ol>'
            . '<li><strong>Settings &rsaquo; Apps &amp; Connectors &rsaquo; Advanced settings</strong>: turn on <strong>Developer mode</strong>.</li>'
            . '<li><strong>Apps &amp; Connectors &rsaquo; Create</strong>.</li>'
            . '<li>Name: <em>XMart Host WHMCS</em>. MCP server URL: paste your connector URL. Authentication: <strong>No authentication</strong> (the key is in the URL).</li>'
            . '<li>Tick "I trust this application", <strong>Create</strong>, then pick it from the <strong>+</strong> menu in a chat.</li></ol></div>';
        $h .= '<div class="xmh-card"><h3>Claude Code</h3><div class="xmh-pre">claude mcp add --transport http xmarthost-whmcs \\
  "' . self::e($url) . '"</div><p class="xmh-small xmh-muted">Or with a header: <code>--header "Authorization: Bearer xmh_your_key"</code> and the URL without <code>?key=</code>.</p></div>';
        $h .= '<div class="xmh-card"><h3>Cursor, VS Code, Windsurf, n8n</h3><p class="xmh-small">Add an HTTP (Streamable HTTP) MCP server, e.g. <code>.cursor/mcp.json</code> / <code>.vscode/mcp.json</code>:</p><div class="xmh-pre">{
  "mcpServers": {
    "xmarthost-whmcs": {
      "url": "' . self::e($ep) . '",
      "headers": { "Authorization": "Bearer xmh_your_key" }
    }
  }
}</div><p class="xmh-small xmh-muted">n8n: MCP Client node, Endpoint = your connector URL, transport HTTP Streamable.</p></div>';
        $h .= '<div class="xmh-card"><h3>Things to ask</h3><ul class="xmh-small" style="padding-left:18px">'
            . '<li>"Show me my top 10 clients by revenue."</li><li>"Which invoices are overdue? Group them by client."</li>'
            . '<li>"Create a product group <em>Business Hosting</em> and a package <em>Business 50GB</em> at 9.99 USD monthly / 99 USD yearly on cPanel package <em>biz50</em>."</li>'
            . '<li>"Tell me everything about client #42."</li><li>"Suspend service #315 for non-payment." (asks you first)</li>'
            . '<li>"What is our MRR and churn for the last 90 days?"</li><li>"Reply to ticket #ABC-123456 that the migration is done and close it."</li></ul>'
            . '<p class="xmh-small xmh-muted">Slash-command prompts: daily_briefing, client_360, overdue_followup, new_hosting_package, ticket_triage, revenue_report.</p></div>';
        $h .= '<div class="xmh-card"><h3>Troubleshooting</h3><ul class="xmh-small" style="padding-left:18px">'
            . '<li><strong>401</strong>: key wrong, revoked or expired. Create a new connector.</li>'
            . '<li><strong>403 HTTPS is required</strong>: use the https:// URL, or enable "Behind Cloudflare / a reverse proxy".</li>'
            . '<li><strong>403 IP</strong>: the caller is not on an allowlist.</li>'
            . '<li><strong>Tools fail with "API IP Access Restriction"</strong>: see API Connection.</li>'
            . '<li><strong>404 on mcp.php</strong>: check the module was uploaded to <code>modules/addons/xmarthost_mcp/</code> and nothing blocks <code>/modules/</code> in .htaccess or a WAF rule.</li>'
            . '<li>Every request, failed or not, is listed under <a href="' . self::e($this->url('activity')) . '">Activity Log</a>.</li></ul></div>';
        return $h . '</div>';
    }

    private function script()
    {
        return <<<'JS'
<script>
(function () {
  document.querySelectorAll('.xmh [data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var el = document.getElementById(b.getAttribute('data-copy'));
      el.select();
      var done = function () { var t = b.textContent; b.textContent = 'Copied!'; setTimeout(function () { b.textContent = t; }, 1500); };
      if (navigator.clipboard) { navigator.clipboard.writeText(el.value).then(done, function () { document.execCommand('copy'); done(); }); }
      else { document.execCommand('copy'); done(); }
    });
  });
  document.querySelectorAll('.xmh [data-group]').forEach(function (g) {
    g.addEventListener('change', function () {
      document.querySelectorAll('.xmh .' + g.getAttribute('data-group')).forEach(function (c) { c.checked = g.checked; });
    });
  });
  document.querySelectorAll('.xmh [data-checkall]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();
      document.querySelectorAll('.xmh input[name="' + a.getAttribute('data-checkall') + '"]').forEach(function (c) { c.checked = true; });
    });
  });
})();
</script>
JS;
    }
}
