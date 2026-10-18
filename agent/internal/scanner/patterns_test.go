package scanner

import (
	"strings"
	"testing"
)

// Fixtures describe behaviour only: no working payloads.
func TestStreamWrapperIncludes(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"zip wrapper", `<?php include 'zip://' . __DIR__ . '/avatar.jpg#x.php';`, "PHP.Loader.StreamWrapperInclude"},
		{"zip literal", `<?php @include("zip://uploads/2024/a.zip#b");`, "PHP.Loader.StreamWrapperInclude"},
		{"request body", `<?php include "php://input";`, "PHP.Loader.StreamWrapperInclude"},
		{"data wrapper", `<?php require_once 'data://text/plain;base64,' . $_GET['p'];`, "PHP.Loader.StreamWrapperInclude"},
		{"small phar loader", `<?php require 'phar://' . __DIR__ . '/x.phar/run.php';`, "PHP.Suspicious.PharInclude"},
		{"phar stub", `<?php Phar::mapPhar('t.phar'); require 'phar://t.phar/autoload.php'; __HALT_COMPILER(); ?>`, ""},
		{"zip read, not include", `<?php $z = new ZipArchive(); $z->open('a.zip'); echo file_get_contents('zip://a.zip#readme.txt');`, ""},
	}
	for _, c := range cases {
		got := ""
		if d := analyze(".php", []byte(c.src)); d != nil {
			got = d.Signature
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDefacement(t *testing.T) {
	page := `<html><head><title>Hacked By Someone</title></head><body bgcolor=black><center><h1>Hacked By Someone</h1>
<marquee>security is an illusion</marquee><p>Greetz: team-a, team-b</p></center></body></html>`
	if d := analyze(".html", []byte(page)); d == nil || d.Signature != "HTML.Defacement" {
		t.Errorf("defacement page: %+v", d)
	}
	claim := `<html><head><title>Hacked by Someone</title></head><body><h1>bye</h1></body></html>`
	if d := analyze(".htm", []byte(claim)); d == nil || d.Signature != "HTML.Defacement.Claim" {
		t.Errorf("bare claim: %+v", d)
	}
	// A blog post about a hack is a long themed page without the furniture.
	article := `<html><head><title>How our store was hacked by a plugin bug</title></head><body>` +
		strings.Repeat(`<p>We restored the backup and updated every plugin.</p>`, 50) + `</body></html>`
	if d := analyze(".html", []byte(article)); d != nil {
		t.Errorf("article flagged as defacement: %+v", d)
	}
	if d := analyze(".html", []byte(`<html><title>Made by Ali</title><h1>Welcome</h1></html>`)); d != nil {
		t.Errorf("normal page flagged: %+v", d)
	}
	// Too large for a defacement page.
	big := page + strings.Repeat("<p>x</p>", 20000)
	if d := defacement(".html", []byte(big)); d != nil {
		t.Errorf("large page flagged: %+v", d)
	}
}

func TestHtaccessStorm(t *testing.T) {
	s := &Scanner{}
	var calls int
	s.OnHtaccessStorm = func(owner string, n int, sample string) { calls++ }
	for i := 0; i < 25; i++ {
		s.noteHtaccess("alice", "/home/alice/public_html/x/.htaccess", 1000+int64(i))
	}
	if calls != 1 {
		t.Errorf("one alert per storm, got %d", calls)
	}
	for i := 0; i < 9; i++ {
		s.noteHtaccess("bob", "/home/bob/.htaccess", 1000)
	}
	if calls != 1 {
		t.Errorf("nine files must not alert, got %d", calls)
	}
	// A new window counts again.
	for i := 0; i < 10; i++ {
		s.noteHtaccess("alice", "/home/alice/public_html/y/.htaccess", 5000)
	}
	if calls != 2 {
		t.Errorf("new window alerts again, got %d", calls)
	}
}

// A fully packed script (flipbook builds, libraries) is not flagged; a
// packed line added to an ordinary script is.
func TestPackedJS(t *testing.T) {
	packed := `eval(function(p,a,c,k,e,d){return p}('` + strings.Repeat("QUJD", 80) + `',62,0,''.split('|'),0,{}))`
	if d := analyze(".js", []byte(packed)); d != nil {
		t.Errorf("packed library flagged: %+v", d)
	}
	script := strings.Repeat("function step(n) { return n + 1; }\n", 80)
	if d := analyze(".js", []byte(script+packed+"\n")); d == nil || d.Signature != "JS.Obfuscated.EvalPacked" {
		t.Errorf("appended packed line: %+v", d)
	}
	if d := analyze(".js", []byte(packed+"\n"+script)); d == nil {
		t.Error("prepended packed line not flagged")
	}
}

func TestCapHeuristicPlaces(t *testing.T) {
	img := &Detection{CatSuspicious, "Disguised.MarkupInImage"}
	if capHeuristic("/home/u/public_html/wp-content/uploads/master_addons/templates/kit-thumb.jpg", ".jpg", img) != nil {
		t.Error("page builder thumbnail flagged")
	}
	if capHeuristic("/home/u/public_html/wp-content/uploads/2026/10/x.jpg", ".jpg", img) == nil {
		t.Error("markup in an ordinary upload not flagged")
	}
	phar := &Detection{CatSuspicious, "PHP.Suspicious.PharInclude"}
	if capHeuristic("/home/u/public_html/vendor/phpstan/phpstan/phpstan", "", phar) != nil {
		t.Error("composer phar loader flagged")
	}
}
