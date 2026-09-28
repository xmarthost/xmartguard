package scanner

import "testing"

func TestDisguisedAndBackupFiles(t *testing.T) {
	for _, ext := range []string{".dat", ".class", ".css", ".flv"} {
		if d := analyze(ext, []byte("<?php @eval($_POST['x']); ?>")); d == nil || d.Signature != "Disguised.PHPFile" || d.Category != CatVirus {
			t.Fatalf("php backdoor as %s: %+v", ext, d)
		}
	}
	if d := analyze(".css", []byte("body{color:red}\n/* <?php echo 1; ?> */")); d != nil && d.Category == CatVirus {
		t.Fatalf("css with harmless php as virus: %+v", d)
	}
	for name, want := range map[string]string{
		"fix.php.backup.20260318120936": ".php",
		"wp-config.php.bak":             ".php",
		"index.php.suspected":           ".suspected",
		"style.css":                     ".css",
		"jquery.min.js":                 ".js",
		"archive.tar.gz":                ".gz",
	} {
		if got := extOf(name); got != want {
			t.Errorf("extOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPhishingKit(t *testing.T) {
	collector := `<?php $ip=$_SERVER['REMOTE_ADDR']; $m="u ".$_POST['user']." p ".$_POST['password']." c ".$_POST['ccnum']." v ".$_POST['cvv']." s ".$_POST['ssn']; mail($to, "rezult", $m); header("Location: https://example.com");`
	if d := analyze(".php", []byte(collector)); d == nil || d.Signature != "Phishing.Collector" || d.Category != CatVirus {
		t.Fatalf("collector: %+v", d)
	}
	contact := `<?php $ip=$_SERVER['REMOTE_ADDR']; $m=$_POST['name']."\n".$_POST['email']."\n".$_POST['message']; mail($to, "Contact form", $m);`
	if d := analyze(".php", []byte(contact)); d != nil {
		t.Fatalf("contact form flagged: %+v", d)
	}
	page := `<html><head><title>Chase Online - Sign in</title></head><body><form action="next.php" method="post"><input name="u"><input type="password" name="p"></form></body></html>`
	if d := analyze(".html", []byte(page)); d == nil || d.Signature != "Phishing.CloneLoginPage" {
		t.Fatalf("bank clone page: %+v", d)
	}
	wp := `<html><head><title>Log In &lsaquo; My Blog</title></head><body><form action="wp-login.php" method="post"><input type="password" name="pwd"></form></body></html>`
	if d := analyze(".html", []byte(wp)); d != nil {
		t.Fatalf("normal login page flagged: %+v", d)
	}
}
