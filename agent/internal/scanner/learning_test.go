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
		"ERP config with ZATCA QR codes and its own folders": `<?php
function get_db() {
    $db_dir = dirname(DB_PATH);
    if (!is_dir($db_dir)) { mkdir($db_dir, 0755, true); }
    if (!is_writable($db_dir)) json_error('The db/ folder is not writable.');
    foreach (scandir(UPLOAD_PATH) as $f) {}
}
function zatca_qr(array $fields) {
    $tlv = '';
    foreach ($fields as $tag => $value) { $tlv .= chr($tag); $tlv .= chr(strlen($value)); $tlv .= $value; }
    file_put_contents(UPLOAD_PATH . 'qr.txt', base64_encode($tlv));
    return base64_encode($tlv);
}
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

// A WHMCS License.php (2026-10-17): the licence holder's name is stored as
// hex2bin('<a href=…>Name</a>'), next to base64_decode of the licence
// signature. Hex that decodes to HTML is data; hex that decodes to code is not.
func TestHexDataIsNotAPayload(t *testing.T) {
	enc := func(s string) string {
		const digits = "0123456789abcdef"
		var b []byte
		for i := 0; i < len(s); i++ {
			b = append(b, digits[s[i]>>4], digits[s[i]&15])
		}
		return string(b)
	}
	link := enc("<a href='https://www.example.com/' class='text-danger font-weight-bold' style='text-decoration: none; font-weight: bold;'>Example Hosting</a>")
	lic := "<?php\nnamespace WHMCS;\nclass License {\n  private function parse($d) { return json_decode(base64_decode(strrev($d)), true); }\n" +
		"  protected function makeCall() { $r['registeredname'] = hex2bin('" + link + "'); return $r; }\n}\n"
	if v := analyzePHP([]byte(lic)); v != nil {
		t.Fatalf("licence file flagged %s", v.signature)
	}
	code := enc("<?php echo 'x'; system($_GET['c']); /* padding padding padding padding padding padding padding padding padding padding padding padding padding padding */ ?>")
	hidden := "<?php\n$p = hex2bin('" + code + "');\nfile_put_contents(__DIR__ . '/x.php', $p);\n"
	if v := analyzePHP([]byte(hidden)); v == nil {
		t.Fatal("PHP code hidden as hex not flagged")
	}
	// Encrypted (XOR) bytes in hex are binary, not readable text: still flagged.
	var x []byte
	for i := 0; i < 200; i++ {
		x = append(x, byte(i*37+11)^0x5a)
	}
	xored := "<?php\nfunction d($s, $k) { $r = ''; for ($i = 0; $i < strlen($s); $i++) $r .= chr(ord($s[$i]) ^ ord($k[$i % strlen($k)])); return $r; }\n" +
		"$cfg = json_decode(d(hex2bin('" + enc(string(x)) + "'), 'K3y'), true);\n"
	if v := analyzePHP([]byte(xored)); v == nil {
		t.Fatal("XOR-encrypted hex blob not flagged")
	}
}
