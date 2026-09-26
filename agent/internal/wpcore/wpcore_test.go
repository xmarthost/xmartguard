package wpcore

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineCoversReleases(t *testing.T) {
	s := Default()
	if s.Count() < 13000 {
		t.Fatalf("baseline has %d files", s.Count())
	}
	// The official "Silence is golden." index.php shipped in wp-content.
	if !s.Known(md5.Sum([]byte("<?php\n// Silence is golden.\n"))) {
		t.Fatal("wp-content/index.php not known")
	}
	if s.Known(md5.Sum([]byte("<?php echo 1;"))) {
		t.Fatal("random content known")
	}
}

func TestUpdateMergesPortalList(t *testing.T) {
	t.Setenv("XG_STATE_DIR", t.TempDir())
	s := &Set{sums: decode(baseline)}
	extra := make([]byte, 0, 16*1200)
	var probe [16]byte
	for i := 0; i < 1200; i++ {
		d := md5.Sum([]byte{byte(i), byte(i >> 8), 'x'})
		if i == 7 {
			probe = d
		}
		extra = append(extra, d[:]...)
	}
	if err := s.Update(extra, "etag1"); err != nil {
		t.Fatal(err)
	}
	if !s.Known(probe) || s.ETag() != "etag1" || s.Count() < 13000+1200 {
		t.Fatalf("merge: known=%v count=%d", s.Known(probe), s.Count())
	}
	if err := s.Update(extra[:160], "small"); err == nil {
		t.Fatal("tiny list accepted")
	}
}

type fakeSource struct {
	sums  map[string]string
	files map[string][]byte
}

func (f fakeSource) Checksums(context.Context, string) (map[string]string, error) { return f.sums, nil }
func (f fakeSource) File(_ context.Context, _, rel string) ([]byte, error) {
	if b, ok := f.files[rel]; ok {
		return b, nil
	}
	return nil, errors.New("404")
}

func TestOfficialVerifiesChecksum(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755)
	os.MkdirAll(filepath.Join(root, "wp-admin", "includes"), 0o755)
	os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '7.1.2';\n"), 0o644)
	good := []byte("<?php // official file\n")
	sum := md5.Sum(good)
	src := fakeSource{sums: map[string]string{"wp-admin/includes/file.php": hex.EncodeToString(sum[:])}, files: map[string][]byte{"wp-admin/includes/file.php": good}}
	p := filepath.Join(root, "wp-admin", "includes", "file.php")
	os.WriteFile(p, []byte("<?php // infected\n"), 0o644)
	if r, rel := FindRoot(p); r != root || rel != "wp-admin/includes/file.php" || Version(r) != "7.1.2" {
		t.Fatalf("root %q rel %q", r, rel)
	}
	body, ver, rel, err := Official(context.Background(), src, p)
	if err != nil || string(body) != string(good) || ver != "7.1.2" || rel != "wp-admin/includes/file.php" {
		t.Fatalf("official: %q %s %s %v", body, ver, rel, err)
	}
	// A tampered download is refused.
	src.files["wp-admin/includes/file.php"] = []byte("<?php // tampered\n")
	if _, _, _, err := Official(context.Background(), src, p); err == nil {
		t.Fatal("tampered download accepted")
	}
	// Plugin files are not core.
	q := filepath.Join(root, "wp-content", "plugins", "x.php")
	os.MkdirAll(filepath.Dir(q), 0o755)
	os.WriteFile(q, []byte("<?php"), 0o644)
	if _, _, _, err := Official(context.Background(), src, q); !errors.Is(err, ErrNotCore) {
		t.Fatalf("plugin: %v", err)
	}
}

type fakePlugins map[string][]byte

func (f fakePlugins) PluginChecksums(_ context.Context, slug, version string) ([]byte, error) {
	if b, ok := f[slug+"@"+version]; ok {
		return b, nil
	}
	return nil, ErrNoChecksums
}

func TestPluginFilesVerifiedByOfficialChecksums(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "wp-content", "plugins", "contact-form-7")
	os.MkdirAll(filepath.Join(dir, "includes"), 0o755)
	os.WriteFile(filepath.Join(dir, "wp-contact-form-7.php"), []byte("<?php\n/*\n * Plugin Name: Contact Form 7\n * Version: 6.1.2\n */\n"), 0o644)
	good := []byte("<?php function wpcf7() {}\n")
	other := []byte("<?php // older build\n")
	g, o := md5.Sum(good), md5.Sum(other)
	// md5 may be a string or a list (several builds of one version).
	sums := fmt.Sprintf(`{"plugin":"contact-form-7","version":"6.1.2","files":{"includes/functions.php":{"md5":["%s","%s"],"sha256":"x"},"readme.txt":{"md5":"%s"}}}`,
		hex.EncodeToString(o[:]), hex.EncodeToString(g[:]), hex.EncodeToString(o[:]))
	p := &Plugins{Source: fakePlugins{"contact-form-7@6.1.2": []byte(sums)}, CacheDir: t.TempDir()}
	f := filepath.Join(dir, "includes", "functions.php")
	if !p.Known(f, md5.Sum(good)) {
		t.Fatal("official plugin file not recognised")
	}
	if p.Known(f, md5.Sum([]byte("<?php eval($_POST[1]);"))) {
		t.Fatal("modified plugin file trusted")
	}
	if p.Known(filepath.Join(dir, "includes", "evil.php"), md5.Sum(good)) {
		t.Fatal("file not in the plugin trusted")
	}
	// Premium plugin (no public checksums): never trusted, not asked twice.
	prem := filepath.Join(root, "wp-content", "plugins", "premium", "x.php")
	os.MkdirAll(filepath.Dir(prem), 0o755)
	os.WriteFile(filepath.Join(root, "wp-content", "plugins", "premium", "premium.php"), []byte("<?php /* Plugin Name: P\n Version: 1.0 */"), 0o644)
	if p.Known(prem, md5.Sum(good)) {
		t.Fatal("premium plugin trusted")
	}
}
