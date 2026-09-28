package clamdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func TestHexPatterns(t *testing.T) {
	cases := []struct {
		sig, data string
		want      bool
	}{
		{hx("marker-one"), "xx marker-one yy", true},
		{hx("mark") + "??" + hx("r-one"), "mark3r-one", true},
		{hx("mark") + "{2}" + hx("-one"), "markXY-one", true},
		{hx("mark") + "{2}" + hx("-one"), "markXYZ-one", false},
		{hx("abcd") + "*" + hx("wxyz"), "abcd...lots...wxyz", true},
		{hx("abcd") + "{1-3}" + hx("wxyz"), "abcd12wxyz", true},
		{hx("abcd") + "{1-3}" + hx("wxyz"), "abcd12345wxyz", false},
		{hx("abcd") + "(31|32)" + hx("zz"), "abcd2zz", true},
		{hx("abcd") + "!(31|32)" + hx("zz"), "abcd2zz", false},
		{hx("abcd") + "(" + hx("xy") + "|" + hx("pq") + ")" + hx("end"), "abcdpqend", true},
		{hx("abcd") + "3?" + hx("zz"), "abcd7zz", true},
		{hx("abcd") + "3?" + hx("zz"), "abcdAzz", false},
		{hx("abcd") + "[1-2]" + hx("zz"), "abcd-zz", true},
		// The long literal is indexed; the short prefix is matched backwards.
		{hx("ab") + "{1-3}" + hx("longliteral"), "xxab12longliteral", true},
		{hx("ab") + "{1-3}" + hx("longliteral"), "ab12345longliteral", false},
		{hx("ab") + "*" + hx("cd") + "{0-2}" + hx("longliteral"), "ab......cd.longliteral", true},
		{hx("ab") + "*" + hx("cd") + "{0-2}" + hx("longliteral"), "......cd.longliteral", false},
	}
	for _, c := range cases {
		pats, err := compileHex(c.sig)
		if err != nil {
			t.Fatalf("%s: %v", c.sig, err)
		}
		got := false
		for _, p := range pats {
			if p.count([]byte(c.data), 1) > 0 {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("sig %s on %q = %v, want %v", c.sig, c.data, got, c.want)
		}
	}
	if _, err := compileHex("??" + "{5}" + "41"); err == nil {
		t.Error("signature without a 2-byte anchor accepted")
	}
}

func writeDB(t *testing.T, dir, name, body string) string {
	p := filepath.Join(dir, name)
	os.WriteFile(p, []byte(body), 0o644)
	return p
}

func TestEngine(t *testing.T) {
	dir := t.TempDir()
	good := []byte("<?php echo 'known good file XGTEST-BODY';")
	bad := []byte("<?php /* XGTEST-HASHED-SAMPLE */")
	gs, bs := md5.Sum(good), md5.Sum(bad)
	writeDB(t, dir, "x.hdb", hex.EncodeToString(bs[:])+":"+itoa(len(bad))+":Test.Hash-1\n")
	writeDB(t, dir, "x.fp", hex.EncodeToString(gs[:])+":"+itoa(len(good))+":good\n")
	writeDB(t, dir, "x.ndb", strings.Join([]string{
		"Test.Body-1:0:*:" + hx("XGTEST-BODY"),
		"Test.Text-1:7:*:" + hx("xgtest normalized text"),
		"Test.Eof-1:0:EOF-5:" + hx("TAIL5"),
		"Test.Exe-1:1:EP+0:" + hx("MZMZ"), // executables: skipped
	}, "\n")+"\n")
	writeDB(t, dir, "x.ldb", strings.Join([]string{
		"Test.Logic-1;Engine:81-255,Target:0;0&1;" + hx("alpha-part") + ";" + hx("beta-part"),
		"Test.Count-1;Engine:81-255,Target:0;0>2;" + hx("again!"),
		"Test.Case-1;Engine:81-255,Target:0;0&1;" + hx("mixedcase") + "::i;0/eval\\(\\$_(POST|GET)/",
	}, "\n")+"\n")
	writeDB(t, dir, "x.ign2", "Test.Ignored-1\n")
	writeDB(t, dir, "y.ndb", "Test.Ignored-1:0:*:"+hx("ignored-marker")+"\n")

	e := Load(FindLocal([]string{dir}))
	if e.Stats.Hashes != 1 || e.Stats.Body != 3 || e.Stats.Logical != 3 {
		t.Fatalf("stats %+v", e.Stats)
	}
	cases := map[string]string{
		string(bad):                          "Test.Hash-1.UNOFFICIAL",
		"xx XGTEST-BODY yy":                  "Test.Body-1.UNOFFICIAL",
		string(good):                         "", // known good (.fp)
		"XGTEST   Normalized\n\tTEXT":        "Test.Text-1.UNOFFICIAL",
		"....TAIL5":                          "Test.Eof-1.UNOFFICIAL",
		"TAIL5....":                          "",
		"alpha-part and beta-part":           "Test.Logic-1.UNOFFICIAL",
		"alpha-part only":                    "",
		"again! again! again!":               "Test.Count-1.UNOFFICIAL",
		"again! again!":                      "",
		"MiXeDcAsE <?php eval($_POST['x']);": "Test.Case-1.UNOFFICIAL",
		"mixedcase without the call":         "",
		"ignored-marker":                     "",
		"MZMZ":                               "",
	}
	for data, want := range cases {
		if got := e.Scan([]byte(data)); got != want {
			t.Errorf("Scan(%q) = %q, want %q", data, got, want)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// An official archive (.cvd) is filtered to web signatures.
func TestCVD(t *testing.T) {
	dir := t.TempDir()
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	body := "Php.Test.Shell-1:0:*:" + hx("XG-CVD-PHP") + "\nWin.Test.Exe-1:0:*:" + hx("XG-CVD-WIN") + "\n"
	tw.WriteHeader(&tar.Header{Name: "daily.ndb", Mode: 0o644, Size: int64(len(body))})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	head := make([]byte, 512)
	copy(head, "ClamAV-VDB:28 Sep 2026 00-00 +0000:27800:10:90:x:x:x:0")
	os.WriteFile(filepath.Join(dir, "daily.cvd"), append(head, tb.Bytes()...), 0o644)
	e := Load(FindLocal([]string{dir}))
	if e.Scan([]byte("a XG-CVD-PHP b")) != "Php.Test.Shell-1" {
		t.Fatalf("cvd php sig: %+v", e.Stats)
	}
	if e.Scan([]byte("XG-CVD-WIN")) != "" {
		t.Fatal("non-web official signature loaded")
	}
}
