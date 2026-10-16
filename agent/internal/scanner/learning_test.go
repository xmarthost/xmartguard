package scanner

import "testing"

// From the AI Learning export (2026-10-15).
func TestBackupArchivesAreNotOpened(t *testing.T) {
	for _, p := range []string{
		"/home/u/public_html/wp-content/updraft/backup_2026-10-12-1325_Site_eaed9614365e-plugins2.zip",
		"/home/u/site.us/insurance/wp-content/backup-migration-gl4VOsuhBz/backups/BM_2026-10-12_11_28_20_x.zip",
		"/home/u/site.com/wp-content/ai1wm-backups/site-20261012.zip",
	} {
		if !backupArchive(p) {
			t.Errorf("%s opened", p)
		}
	}
	for _, p := range []string{
		"/home/u/public_html/wp-content/uploads/2026/10/bd-60c11765f07a.zip",
		"/home/u/public_html/index.zip",
		"/home/u/site.com/wp-content/backup-migration-x/other.zip",
	} {
		if backupArchive(p) {
			t.Errorf("%s skipped", p)
		}
	}
}

func TestFingerprintJSIsNotAMiner(t *testing.T) {
	fp := []byte(`!function(e){var t=new Client.Init({token:"x"});t.get()}(window);`)
	if v := analyzeJS(fp); v != nil && v.signature == "JS.Miner.Browser" {
		t.Fatal("FingerprintJS-style client flagged as a miner")
	}
	miner := []byte(`var m = new CoinHive.Anonymous('KEY'); m.start();`)
	if v := analyzeJS(miner); v == nil || v.signature != "JS.Miner.Browser" {
		t.Fatal("CoinHive miner not flagged")
	}
}

// A customer's own PHP application (a website backup zip, 2026-10-16):
// ordinary code the heuristics took for backdoors.
func TestOwnApplicationCode(t *testing.T) {
	clean := map[string]string{
		"variable before ( in a string": `<?php
$type = $_GET['type'] ?? 'attendance';
$name = trim($_POST['name'] ?? '');
audit_log('report.export', 'report', $type, "Exported $type (monthly) as CSV");
notify_admins($db, 'user.registered', "$name ($email) just created an account.");
`,
		"WebSocket client writing frames to a socket": `<?php
$symbol = preg_replace('/[^A-Za-z0-9_]/', '', (string)($_GET['symbol'] ?? 'R_100'));
$socket = stream_socket_client('tls://ws.example.com:443');
function ws_send($socket, $message) {
    $payload = json_encode($message); $length = strlen($payload); $frame = chr(0x81);
    if ($length < 126) $frame .= chr($length | 0x80); else $frame .= chr(126 | 0x80) . pack('n', $length);
    fwrite($socket, $frame . $payload);
}
$on = $_GET['cb'] ?? '';
$handler = function ($x) { return $x; };
echo $handler($symbol);
`,
		"Cloudflare email-protection decoder": `<?php
function cfemail_decode(string $hex): string {
    $k = hexdec(substr($hex, 0, 2)); $out = '';
    for ($i = 2; $i < strlen($hex); $i += 2) $out .= chr(hexdec(substr($hex, $i, 2)) ^ $k);
    return $out;
}
$q = $_GET['q'] ?? '';
$uniq = fn(array $a) => array_values(array_unique($a));
print_r($uniq([cfemail_decode($q)]));
`,
	}
	for name, src := range clean {
		if v := analyzePHP([]byte(src)); v != nil {
			t.Errorf("%s: flagged %s", name, v.signature)
		}
	}
	// The real thing stays flagged.
	if v := analyzePHP([]byte("<?php\n$f = $_GET['f'];\n$f($_GET['a']);\n")); v == nil || v.signature != "PHP.Backdoor.DynamicCall" {
		t.Errorf("request-named function call: %+v", v)
	}
	if v := analyzePHP([]byte("<?php\n$d = '';\nforeach (str_split($_POST['p']) as $c) $d .= chr(ord($c) ^ 7);\nfile_put_contents($_POST['n'], $d);\n")); v == nil {
		t.Error("decoder writing a request-named file not flagged")
	}
}
