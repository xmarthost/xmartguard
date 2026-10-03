<?php
/**
 * Minimal stand-in for WHMCS: Capsule on SQLite, the WHMCS tables the module
 * touches, and the global helper functions (localAPI, encrypt, ...).
 *
 * XMH_TEST_DB selects the SQLite file (shared between the PHP built-in web
 * server and the test runner).
 */

require __DIR__ . '/vendor/autoload.php';

if (!defined('WHMCS')) {
    define('WHMCS', true);
}

if (!class_exists('WHMCS\Database\Capsule')) {
    eval('namespace WHMCS\Database; class Capsule extends \Illuminate\Database\Capsule\Manager {}');
}

use WHMCS\Database\Capsule;

$xmhDb = getenv('XMH_TEST_DB') ?: __DIR__ . '/test.sqlite';
if (!is_file($xmhDb)) {
    touch($xmhDb);
}
$capsule = new Capsule();
$capsule->addConnection(['driver' => 'sqlite', 'database' => $xmhDb, 'prefix' => '']);
$capsule->setAsGlobal();
$capsule->bootEloquent();

function encrypt($v) { return 'enc:' . strrev(base64_encode($v)); }
function decrypt($v) { return strncmp($v, 'enc:', 4) === 0 ? base64_decode(strrev(substr($v, 4))) : ''; }
function logActivity($text) { $GLOBALS['xmh_activity'][] = $text; }
function generate_token($type = 'link') { return 'whmcs-csrf'; }

/** Fake WHMCS API used by "internal" mode and by the fake api.php. */
function localAPI($cmd, $params = [], $admin = null)
{
    $GLOBALS['xmh_api_calls'][] = [$cmd, $params, $admin];
    switch ($cmd) {
        case 'WhmcsDetails':
            return ['result' => 'success', 'whmcs' => ['version' => '8.13.0', 'canonicalversion' => '8.13.0-release.1']];
        case 'GetStats':
            return ['result' => 'success', 'income_today' => '10.00', 'clients_active' => 2, 'orders_pending' => 1, 'tickets_awaitingreply' => 3];
        case 'GetTicketCounts':
            return ['result' => 'success', 'allActive' => 4, 'awaitingReply' => 3];
        case 'GetOrders':
            return ['result' => 'success', 'totalresults' => 1, 'orders' => ['order' => [['id' => 7, 'ordernum' => '123', 'userid' => 1, 'name' => 'Ali Khan', 'date' => '2026-10-01', 'amount' => '9.99', 'paymentstatus' => 'Unpaid', 'status' => 'Pending', 'ipaddress' => '1.2.3.4']]]];
        case 'GetClients':
            return ['result' => 'success', 'totalresults' => 1, 'clients' => ['client' => [['id' => 1, 'firstname' => 'Ali', 'lastname' => 'Khan', 'email' => 'ali@example.com']]], 'echo' => $params];
        case 'GetClientsDetails':
            return ['result' => 'success', 'userid' => 1, 'client' => ['id' => 1, 'firstname' => 'Ali', 'lastname' => 'Khan', 'password' => 'hash'], 'stats' => ['numactiveproducts' => 1]];
        case 'GetClientsProducts':
            return ['result' => 'success', 'products' => ['product' => [['id' => 10, 'name' => 'Starter']]]];
        case 'GetClientsDomains':
            return ['result' => 'success', 'domains' => ['domain' => []]];
        case 'GetInvoices':
            return ['result' => 'success', 'invoices' => ['invoice' => [['id' => 3]]]];
        case 'GetTickets':
            return ['result' => 'success', 'tickets' => ['ticket' => []]];
        case 'AddProduct':
            $id = Capsule::table('tblproducts')->insertGetId(['type' => $params['type'], 'gid' => $params['gid'], 'name' => $params['name'], 'paytype' => isset($params['paytype']) ? $params['paytype'] : 'free']);
            return ['result' => 'success', 'pid' => $id, 'echo' => $params];
        case 'DeleteClient':
            return ['result' => 'success', 'clientid' => $params['clientid']];
        case 'FailingAction':
            return ['result' => 'error', 'message' => 'Something went wrong'];
    }
    return ['result' => 'success', 'action' => $cmd, 'echo' => $params];
}

/** Creates the WHMCS core tables the module reads, with a little sample data. */
function xmh_seed_whmcs()
{
    $s = Capsule::schema();
    foreach (['tblconfiguration', 'tbladdonmodules', 'tbladmins', 'tblclients', 'tblcurrencies', 'tblhosting', 'tblhostingaddons', 'tbldomains', 'tblaccounts', 'tblinvoices',
        'tblproductgroups', 'tblproducts', 'tblpricing', 'tblproductconfiggroups', 'tblproductconfiglinks', 'tblproductconfigoptions', 'tblproductconfigoptionssub',
        'mod_xmarthost_mcp_settings', 'mod_xmarthost_mcp_tokens', 'mod_xmarthost_mcp_logs'] as $t) {
        $s->dropIfExists($t);
    }
    $s->create('tblconfiguration', function ($t) { $t->string('setting'); $t->text('value'); });
    $s->create('tbladdonmodules', function ($t) { $t->string('module'); $t->string('setting'); $t->text('value'); });
    $s->create('tbladmins', function ($t) { $t->increments('id'); $t->string('username'); });
    $s->create('tblclients', function ($t) { $t->increments('id'); $t->string('firstname'); $t->string('lastname'); $t->string('companyname')->default(''); $t->string('email'); $t->integer('currency'); $t->string('status')->default('Active'); });
    $s->create('tblcurrencies', function ($t) { $t->increments('id'); $t->string('code'); $t->string('prefix')->default(''); $t->string('suffix')->default(''); $t->decimal('rate', 10, 5)->default(1); $t->integer('default')->default(0); });
    $s->create('tblhosting', function ($t) { $t->increments('id'); $t->integer('userid'); $t->integer('packageid'); $t->string('domain')->default(''); $t->string('billingcycle'); $t->decimal('amount', 10, 2); $t->string('domainstatus'); $t->date('regdate'); $t->date('nextduedate')->nullable(); $t->date('termination_date')->nullable(); });
    $s->create('tblhostingaddons', function ($t) { $t->increments('id'); $t->integer('hostingid'); $t->integer('addonid')->default(0); $t->string('name')->default(''); $t->decimal('recurring', 10, 2); $t->string('billingcycle'); $t->string('status'); });
    $s->create('tbldomains', function ($t) { $t->increments('id'); $t->integer('userid'); $t->string('domain'); $t->decimal('recurringamount', 10, 2); $t->integer('registrationperiod'); $t->string('status'); $t->date('expirydate')->nullable(); $t->date('nextduedate')->nullable(); });
    $s->create('tblaccounts', function ($t) { $t->increments('id'); $t->integer('userid'); $t->integer('currency')->default(0); $t->string('gateway'); $t->dateTime('date'); $t->string('description')->default(''); $t->decimal('amountin', 10, 2)->default(0); $t->decimal('fees', 10, 2)->default(0); $t->decimal('amountout', 10, 2)->default(0); $t->integer('invoiceid')->default(0); $t->string('transid')->default(''); });
    $s->create('tblinvoices', function ($t) { $t->increments('id'); $t->integer('userid'); $t->string('invoicenum')->default(''); $t->date('date'); $t->date('duedate'); $t->decimal('total', 10, 2); $t->string('status'); });
    $s->create('tblproductgroups', function ($t) { $t->increments('id'); $t->string('name'); $t->string('slug')->default(''); $t->text('headline')->nullable(); $t->text('tagline')->nullable(); $t->string('orderfrmtpl')->default(''); $t->text('disabledgateways'); $t->integer('hidden')->default(0); $t->integer('order')->default(0); $t->timestamps(); });
    $s->create('tblproducts', function ($t) {
        $t->increments('id'); $t->string('type'); $t->integer('gid'); $t->string('name'); $t->text('description')->nullable(); $t->integer('hidden')->default(0); $t->integer('retired')->default(0);
        $t->integer('is_featured')->default(0); $t->string('paytype')->default('free'); $t->string('autosetup')->default(''); $t->string('servertype')->default(''); $t->integer('servergroup')->default(0);
        $t->integer('welcomeemail')->default(0); $t->integer('stockcontrol')->default(0); $t->integer('qty')->default(0); $t->integer('tax')->default(0); $t->integer('order')->default(0);
        for ($i = 1; $i <= 24; $i++) { $t->text('configoption' . $i)->nullable(); }
        $t->timestamp('updated_at')->nullable();
    });
    $s->create('tblpricing', function ($t) {
        $t->increments('id'); $t->string('type'); $t->integer('currency'); $t->integer('relid');
        foreach (['msetupfee', 'qsetupfee', 'ssetupfee', 'asetupfee', 'bsetupfee', 'tsetupfee', 'monthly', 'quarterly', 'semiannually', 'annually', 'biennially', 'triennially'] as $c) { $t->decimal($c, 10, 2)->default(0); }
    });
    $s->create('tblproductconfiggroups', function ($t) { $t->increments('id'); $t->string('name'); $t->text('description'); });
    $s->create('tblproductconfiglinks', function ($t) { $t->increments('id'); $t->integer('gid'); $t->integer('pid'); });
    $s->create('tblproductconfigoptions', function ($t) { $t->increments('id'); $t->integer('gid'); $t->string('optionname'); $t->integer('optiontype'); $t->integer('qtyminimum'); $t->integer('qtymaximum'); $t->integer('order'); $t->integer('hidden'); });
    $s->create('tblproductconfigoptionssub', function ($t) { $t->increments('id'); $t->integer('configid'); $t->string('optionname'); $t->integer('sortorder'); $t->integer('hidden'); });

    Capsule::table('tblconfiguration')->insert(['setting' => 'SystemURL', 'value' => 'https://billing.example.com/']);
    Capsule::table('tbladdonmodules')->insert([['module' => 'xmarthost_mcp', 'setting' => 'version', 'value' => '1.0.0'], ['module' => 'xmarthost_mcp', 'setting' => 'access', 'value' => '1']]);
    Capsule::table('tbladmins')->insert(['username' => 'boss']);
    Capsule::table('tblcurrencies')->insert([['code' => 'USD', 'default' => 1], ['code' => 'PKR', 'default' => 0]]);
    Capsule::table('tblclients')->insert([
        ['firstname' => 'Ali', 'lastname' => 'Khan', 'email' => 'ali@example.com', 'currency' => 1],
        ['firstname' => 'Sara', 'lastname' => 'Ahmed', 'email' => 'sara@example.com', 'currency' => 2],
    ]);
    Capsule::table('tblproductgroups')->insert(['name' => 'Shared Hosting', 'slug' => 'shared-hosting', 'disabledgateways' => '', 'order' => 1]);
    Capsule::table('tblproducts')->insert(['type' => 'hostingaccount', 'gid' => 1, 'name' => 'Starter', 'paytype' => 'recurring']);
    $today = date('Y-m-d');
    Capsule::table('tblhosting')->insert([
        ['userid' => 1, 'packageid' => 1, 'billingcycle' => 'Monthly', 'amount' => 10, 'domainstatus' => 'Active', 'regdate' => '2026-01-01', 'termination_date' => null],
        ['userid' => 1, 'packageid' => 1, 'billingcycle' => 'Annually', 'amount' => 120, 'domainstatus' => 'Active', 'regdate' => '2026-01-01', 'termination_date' => null],
        ['userid' => 2, 'packageid' => 1, 'billingcycle' => 'Monthly', 'amount' => 1000, 'domainstatus' => 'Active', 'regdate' => $today, 'termination_date' => null],
        ['userid' => 1, 'packageid' => 1, 'billingcycle' => 'Monthly', 'amount' => 5, 'domainstatus' => 'Terminated', 'regdate' => '2025-01-01', 'termination_date' => date('Y-m-d', time() - 5 * 86400)],
    ]);
    Capsule::table('tbldomains')->insert(['userid' => 1, 'domain' => 'ali.com', 'recurringamount' => 24, 'registrationperiod' => 2, 'status' => 'Active', 'expirydate' => date('Y-m-d', time() + 10 * 86400)]);
    Capsule::table('tblinvoices')->insert([
        ['userid' => 1, 'date' => '2026-01-01', 'duedate' => date('Y-m-d', time() - 45 * 86400), 'total' => 50, 'status' => 'Unpaid'],
        ['userid' => 1, 'date' => '2026-01-01', 'duedate' => date('Y-m-d', time() + 5 * 86400), 'total' => 20, 'status' => 'Unpaid'],
        ['userid' => 2, 'date' => '2026-01-01', 'duedate' => date('Y-m-d', time() - 120 * 86400), 'total' => 3000, 'status' => 'Unpaid'],
    ]);
    Capsule::table('tblaccounts')->insert([
        ['userid' => 1, 'gateway' => 'paypal', 'date' => date('Y-m-d H:i:s', time() - 10 * 86400), 'amountin' => 100, 'fees' => 3.2, 'invoiceid' => 0],
        ['userid' => 1, 'gateway' => 'paypal', 'date' => date('Y-m-d H:i:s', time() - 9 * 86400), 'amountin' => 10, 'fees' => 0, 'invoiceid' => 1],
        ['userid' => 2, 'gateway' => 'banktransfer', 'date' => date('Y-m-d H:i:s', time() - 40 * 86400), 'amountin' => 5000, 'fees' => 0, 'invoiceid' => 0],
    ]);
}
