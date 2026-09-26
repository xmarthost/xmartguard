package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Test samples are assembled at runtime so this source file itself is not
// flagged by antivirus products.
func j(parts ...string) string { return strings.Join(parts, "") }

var malicious = map[string]string{
	"eicar.txt":    j(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR`, `-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`),
	"exec.php":     j("<?php sys", "tem($_GET['cmd']); ?>"),
	"eval.php":     j("<?php @ev", "al($_POST['x']); ?>"),
	"evalb64.php":  j("<?php ev", "al(stripslashes(base64_decode($_REQUEST['c']))); ?>"),
	"varfunc.php":  j("<?php @$_POST['a']", "(@$_POST['b']); ?>"),
	"obf.php":      j("<?php ev", "al(gzinflate(base64_decode('", strings.Repeat("QUJD", 80), "'))); ?>"),
	"wso.php":      j("<?php $default_action = 'Files", "Man'; ?>"),
	"uploader.php": j("<?php if(isset($_FILES['f'])){ move_uploaded_file", "($_FILES['f']['tmp_name'], $_FILES['f']['name']); } ?>"),
	"miner.js":     j("var m = new Coin", "Hive.Anonymous('key');"),
	"hexeval.php":  j(`<?php $f = "\x65\x76`, `\x61\x6c"; ?>`),
	"shell.jpg":    j("GIF89a<?", "php echo 1; ?>"),
}

var clean = map[string]string{
	"wp-config.php": "<?php define('DB_NAME', 'wp'); $table_prefix = 'wp_'; require_once ABSPATH . 'wp-settings.php';",
	"plugin.php":    "<?php function hello() { $name = sanitize_text_field($_POST['name']); echo esc_html($name); } add_action('init', 'hello');",
	"jquery.js":     "(function(a){a.fn.extend({toggle:function(){return this.each(function(){})}})})(jQuery);",
	"image.jpg":     "\xff\xd8\xff\xe0JFIF binary data here",
	"b64ok.php":     "<?php $icon = base64_decode('iVBORw0KGgo='); header('Content-Type: image/png'); echo $icon;",
}

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, err := settings.Load()
	if err != nil {
		t.Fatal(err)
	}
	// Tests choose actions explicitly; start from "report only".
	if _, err := st.Patch([]byte(`{"scanner":{"virus_action":"notify"}}`)); err != nil {
		t.Fatal(err)
	}
	return New(db, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "public_html")
	for name, content := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRulesDetectMaliciousSamples(t *testing.T) {
	for name, content := range malicious {
		if r := Match(extOf(name), []byte(content)); r == nil {
			t.Errorf("%s: not detected", name)
		}
	}
}

func TestRulesIgnoreCleanFiles(t *testing.T) {
	for name, content := range clean {
		if r := Match(extOf(name), []byte(content)); r != nil {
			t.Errorf("%s: false positive %s", name, r.Name)
		}
	}
}

func waitScan(t *testing.T, s *Scanner, id int64) Scan {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		scans, _ := s.ListScans(10)
		for _, sc := range scans {
			if sc.ID == id && sc.Status != "queued" && sc.Status != "running" {
				return sc
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return Scan{}
}

func TestPathScanFindsAllSamples(t *testing.T) {
	s := newScanner(t)
	files := map[string]string{}
	for k, v := range malicious {
		files["mal/"+k] = v
	}
	for k, v := range clean {
		files["ok/"+k] = v
	}
	root := writeTree(t, files)
	id, err := s.Start("path", root, "test")
	if err != nil {
		t.Fatal(err)
	}
	sc := waitScan(t, s, id)
	if sc.Status != "completed" || sc.Files != int64(len(files)) {
		t.Fatalf("scan: %+v", sc)
	}
	if sc.Infected != int64(len(malicious)) {
		fs, _, _ := s.ListFindings(FindingFilter{ScanID: id, Limit: 100})
		t.Fatalf("infected=%d want %d: %+v", sc.Infected, len(malicious), fs)
	}
	fs, total, lerr := s.ListFindings(FindingFilter{ScanID: id, Limit: 100})
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, f := range fs {
		if !strings.Contains(f.Path, "/mal/") {
			t.Errorf("false positive: %s (%s)", f.Path, f.Signature)
		}
		if f.Status != "detected" {
			t.Errorf("default action should only report, got %s", f.Status)
		}
	}
	if total != len(malicious) {
		t.Fatalf("total %d", total)
	}
	// Re-scanning the same unchanged files reports them in the new scan
	// without creating duplicate findings.
	id2, _ := s.Start("path", root, "test")
	if sc2 := waitScan(t, s, id2); sc2.Infected != int64(len(malicious)) {
		t.Fatalf("rescan infected=%d want %d", sc2.Infected, len(malicious))
	}
	if _, all, _ := s.ListFindings(FindingFilter{Limit: 100}); all != len(malicious) {
		t.Fatalf("rescan created duplicates: %d findings", all)
	}
	if _, inScan2, _ := s.ListFindings(FindingFilter{ScanID: id2, Limit: 100}); inScan2 != len(malicious) {
		t.Fatalf("rescan lists %d findings", inScan2)
	}
	// Switching to quarantine and scanning again quarantines the files that
	// were only reported before.
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	id3, _ := s.Start("path", root, "test")
	waitScan(t, s, id3)
	fs3, _, _ := s.ListFindings(FindingFilter{ScanID: id3, Limit: 100})
	for _, f := range fs3 {
		if f.Category == CatVirus && f.Status != "quarantined" {
			t.Errorf("%s still %s after switching to quarantine", f.Path, f.Status)
		}
		if _, err := os.Stat(f.Path); f.Category == CatVirus && err == nil {
			t.Errorf("%s still on disk", f.Path)
		}
	}
	// A quarantined file that comes back is a new finding (re-infection).
	var back string
	for _, f := range fs3 {
		if f.Category == CatVirus {
			back = f.Path
			break
		}
	}
	os.MkdirAll(filepath.Dir(back), 0o755)
	os.WriteFile(back, []byte(malicious[filepath.Base(back)]), 0o644)
	info, _ := os.Lstat(back)
	det, _ := s.CheckFile(back, info, s.Settings.Get().Scanner)
	if det == nil {
		t.Fatalf("%s not detected again", back)
	}
	if f, err := s.Record(0, "realtime", back, info, *det); err != nil || f.Status != "quarantined" {
		t.Fatalf("re-infection not handled: %+v %v", f, err)
	}
}

func TestQuarantineRestoreDeleteLifecycle(t *testing.T) {
	s := newScanner(t)
	root := writeTree(t, map[string]string{"x/exec.php": malicious["exec.php"]})
	file := filepath.Join(root, "x/exec.php")
	os.Chmod(file, 0o640)
	id, _ := s.Start("path", root, "test")
	waitScan(t, s, id)
	fs, _, _ := s.ListFindings(FindingFilter{ScanID: id})
	if len(fs) != 1 {
		t.Fatalf("findings: %+v", fs)
	}
	fid := fs[0].ID

	if err := s.Quarantine(fid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("file still present after quarantine")
	}
	q := filepath.Join(QuarantineDir(), "1.q")
	if st, err := os.Stat(q); err != nil || st.Mode().Perm() != 0 {
		t.Fatalf("quarantined copy: %v %v", st, err)
	}
	if err := s.Quarantine(fid); err == nil {
		t.Fatal("double quarantine should fail")
	}

	// Restore refuses to overwrite a file that reappeared.
	os.WriteFile(file, []byte("new"), 0o644)
	if err := s.Restore(fid); err == nil {
		t.Fatal("restore overwrote an existing file")
	}
	os.Remove(file)
	if err := s.Restore(fid); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("restored mode: %v %v", st, err)
	}
	if b, _ := os.ReadFile(file); string(b) != malicious["exec.php"] {
		t.Fatal("restored content differs")
	}

	if err := s.Disable(fid); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0 {
		t.Fatal("disable did not chmod 000")
	}
	if err := s.Delete(fid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("delete left the file")
	}
}

func TestAutoQuarantineAndWhitelist(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine","whitelist_paths":["eval.php"]}}`)); err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{"exec.php": malicious["exec.php"], "eval.php": malicious["eval.php"]})
	id, _ := s.Start("path", root, "test")
	sc := waitScan(t, s, id)
	if sc.Infected != 1 {
		t.Fatalf("infected %d, whitelist not applied", sc.Infected)
	}
	fs, _, _ := s.ListFindings(FindingFilter{ScanID: id})
	if fs[0].Status != "quarantined" {
		t.Fatalf("status %s", fs[0].Status)
	}
	if _, err := os.Stat(filepath.Join(root, "exec.php")); !os.IsNotExist(err) {
		t.Fatal("auto quarantine left the file")
	}
}

func TestBlacklistNameAndBinary(t *testing.T) {
	s := newScanner(t)
	s.Settings.Patch([]byte(`{"scanner":{"blacklist_names":["libworker.so"]}}`))
	root := writeTree(t, map[string]string{"libworker.so": "harmless", "bin/miner": "\x7fELF\x02\x01\x01rest-of-binary"})
	id, _ := s.Start("path", root, "test")
	fs, _, _ := s.ListFindings(FindingFilter{ScanID: id})
	waitScan(t, s, id)
	fs, _, _ = s.ListFindings(FindingFilter{ScanID: id})
	cats := map[string]bool{}
	for _, f := range fs {
		cats[f.Category] = true
	}
	if !cats[CatVirus] || !cats[CatBinary] {
		t.Fatalf("findings: %+v", fs)
	}
}

func TestValidateTarget(t *testing.T) {
	for _, bad := range []string{"relative/path", "/", "/proc/1", "/etc", "/usr/bin", "/does/not/exist"} {
		if _, err := ValidateTarget(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := ValidateTarget(t.TempDir()); err != nil {
		t.Error(err)
	}
}

func TestStopScan(t *testing.T) {
	s := newScanner(t)
	files := map[string]string{}
	for i := 0; i < 3000; i++ {
		files[filepath.Join("d", strings.Repeat("a", i%50+1), "f"+string(rune('a'+i%26))+".php")+string(rune('0'+i%10))] = "<?php echo 1;"
	}
	root := writeTree(t, files)
	id, _ := s.Start("path", root, "test")
	s.Stop(id)
	if sc := waitScan(t, s, id); sc.Status != "stopped" && sc.Status != "completed" {
		t.Fatalf("status %s", sc.Status)
	}
}

func TestRealtimeDetectsNewFile(t *testing.T) {
	s := newScanner(t)
	root := writeTree(t, map[string]string{"index.php": "<?php echo 'hi';"})
	rt := &Realtime{S: s}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Drive a session directly on our temp root.
	if err := rt.init([]string{root}); err != nil {
		t.Skip("inotify unavailable:", err)
	}
	go rt.loop(ctx)
	time.Sleep(300 * time.Millisecond)
	os.MkdirAll(filepath.Join(root, "wp-content/uploads"), 0o755)
	time.Sleep(300 * time.Millisecond)
	os.WriteFile(filepath.Join(root, "wp-content/uploads/x.php"), []byte(malicious["exec.php"]), 0o644)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		fs, _, _ := s.ListFindings(FindingFilter{})
		if len(fs) == 1 && fs[0].Source == "realtime" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("realtime did not detect the new file")
}

// Extracting an archive creates directories and fills them at once, before
// any watch on them exists; moving a finished folder in produces a single
// event for the folder. Every file must still be scanned.
func TestRealtimeCatchesExtractedAndMovedTrees(t *testing.T) {
	s := newScanner(t)
	root := t.TempDir()
	rt := &Realtime{S: s, Roots: func() []string { return []string{root} }}
	if err := rt.init([]string{root}); err != nil {
		t.Skip("inotify unavailable:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rt.loop(ctx)
	time.Sleep(100 * time.Millisecond)

	want := 0
	// "unzip": nested directories written immediately.
	for i := 0; i < 20; i++ {
		d := filepath.Join(root, "cpguard", "a", fmt.Sprint(i), "deep")
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "shell.php"), []byte(malicious["eval.php"]+fmt.Sprint(i)), 0o644)
		want++
	}
	// A folder prepared elsewhere and moved in.
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(outside, "pkg", "inc"), 0o755)
	os.WriteFile(filepath.Join(outside, "pkg", "inc", "x.php"), []byte(malicious["exec.php"]), 0o644)
	os.Rename(filepath.Join(outside, "pkg"), filepath.Join(root, "pkg"))
	want++

	deadline := time.Now().Add(15 * time.Second)
	got := 0
	for time.Now().Before(deadline) {
		_, got, _ = s.ListFindings(FindingFilter{Limit: 100})
		if got >= want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("realtime found %d of %d files", got, want)
	}
}
