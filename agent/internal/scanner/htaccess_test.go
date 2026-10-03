package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// .htaccess files written into every folder of hacked sites (reported from
// live servers).
var hackedHtaccess = map[string]string{
	"lock list": `<FilesMatch ".(py|exe|php)$">
Order allow,deny
Deny from all
</FilesMatch>
<FilesMatch "^(lock360.php|wp-l0gin.php|wp-the1me.php|wp-scr1pts.php|radio.php|index.php|content.php|about.php|wp-login.php|admin.php)$">
Order allow,deny
Allow from all
</FilesMatch>`,
	"cgi handler": `#Coded By PHOENIX TEAM
Options FollowSymLinks MultiViews Indexes ExecCGI
AddType application/x-httpd-cgi .alfa
AddHandler cgi-script .alfa`,
	"mixed case with rewrite": `<FilesMatch '.(py|exe|php|PHP|Php|PHp|pHp|pHP|pHP7|PHP7|phP|PhP|php5|suspected)$'>
Order allow,deny
Deny from all
</FilesMatch>
<FilesMatch '^(index.php|wp-ffj085r.php|wp-4hzgnd.php|wp-login.php|admin.php|plugins.php)$'>
Order allow,deny
Allow from all
</FilesMatch>
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
DirectoryIndex index.php
RewriteRule ^index.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>`,
	"short list": `<FilesMatch ".(py|exe|php)$">
 Order allow,deny
 Deny from all
</FilesMatch>
<FilesMatch "^(22.php|xannyanaxium_s.php|coffexium.php|cyb01.php|cyl1.php)$">
 Order allow,deny
 Allow from all
</FilesMatch>`,
	"deny only": `<FilesMatch ".(py|exe|phtml|php|PHP|Php|PHp|pHp|pHP|phP|PhP|php5|suspected)$">
Order allow,deny
Deny from all
</FilesMatch>`,
	"lock with Require": `<FilesMatch "\.php$">
Require all denied
</FilesMatch>
<FilesMatch "^(index\.php|x7shell\.php|wp-blog\.php)$">
Require all granted
</FilesMatch>`,
}

// .htaccess files of real sites, hosting panels and security plugins.
var cleanHtaccess = map[string]string{
	"wordpress": `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress`,
	"uploads hardening": `# BEGIN Wordfence code execution protection
<IfModule mod_php5.c>
php_flag engine 0
</IfModule>
<FilesMatch "\.(?i:php|phtml|php[0-9])$">
Order allow,deny
Deny from all
</FilesMatch>
# END Wordfence code execution protection`,
	"wp-includes hardening": `<FilesMatch "\.(?i:php)$">
  <IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
  </IfModule>
  <IfModule mod_authz_core.c>
    Require all denied
  </IfModule>
</FilesMatch>
<Files wp-tinymce.php>
  Require all granted
</Files>
<Files ms-files.php>
  Require all granted
</Files>`,
	"secrets": `<FilesMatch "^(\.env|wp-config\.php|readme\.html|license\.txt)$">
Order allow,deny
Deny from all
</FilesMatch>`,
	"cpanel php and cgi": `# php -- BEGIN cPanel-generated handler, do not edit
<IfModule mime_module>
  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml
</IfModule>
# php -- END cPanel-generated handler, do not edit
Options +ExecCGI
AddHandler cgi-script .cgi .pl`,
	"magento media": `Options -Indexes
<IfModule mod_php5.c>
php_flag engine 0
</IfModule>
AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi
Options -ExecCGI
<FilesMatch ".*\.(ph(p[3457]?|t|tml)|[aj]sp|p[ly]|sh|cgi|shtml?|html?)$">
SetHandler default-handler
</FilesMatch>`,
}

func TestHackedHtaccessDetected(t *testing.T) {
	for name, c := range hackedHtaccess {
		if d := analyze(".htaccess", []byte(c)); d == nil || d.Category != CatVirus {
			t.Errorf("%s: not detected (%+v)", name, d)
		}
	}
	for name, c := range cleanHtaccess {
		if d := analyze(".htaccess", []byte(c)); d != nil {
			t.Errorf("%s: flagged as %+v", name, d)
		}
	}
}

func TestCleanHtaccess(t *testing.T) {
	// The kit's blocks go; the site's rules stay; WordPress rules are added
	// when none are left.
	site := "# BEGIN LSCACHE\n<IfModule LiteSpeed>\nCacheLookup on\n</IfModule>\n# END LSCACHE\n\n" + cleanHtaccess["wordpress"]
	out := string(CleanHtaccess([]byte(hackedHtaccess["lock list"]+"\n"+site), "/"))
	if strings.Contains(out, "FilesMatch") || strings.Contains(out, "lock360") || !strings.Contains(out, "CacheLookup on") || strings.Count(out, "RewriteRule . /index.php") != 1 {
		t.Fatalf("cleaned:\n%s", out)
	}
	out = string(CleanHtaccess([]byte(hackedHtaccess["cgi handler"]), siteBase("/home/u/public_html/blog")))
	if strings.Contains(out, ".alfa") || strings.Contains(out, "PHOENIX") || strings.Contains(out, "ExecCGI") || !strings.Contains(out, "RewriteRule . /blog/index.php [L]") {
		t.Fatalf("cleaned:\n%s", out)
	}
	// A hardening plugin's block in the same file is kept.
	out = string(CleanHtaccess([]byte(hackedHtaccess["deny only"]+"\n"+cleanHtaccess["secrets"]), "/"))
	if !strings.Contains(out, `wp-config\.php`) || strings.Contains(out, "suspected") {
		t.Fatalf("cleaned:\n%s", out)
	}
	for name, c := range cleanHtaccess {
		if strings.Contains(c, "Deny") && analyze(".htaccess", CleanHtaccess([]byte(c), "/")) != nil {
			t.Errorf("%s: cleaning made it a detection", name)
		}
	}
}

// In a WordPress root the hacked .htaccess is cleaned in place (the copy
// stays in quarantine); in any other folder it is quarantined.
func TestHackedHtaccessActions(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "public_html")
	os.MkdirAll(filepath.Join(root, "wp-content", "uploads", "2026"), 0o755)
	os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php // config"), 0o644)
	top := filepath.Join(root, ".htaccess")
	sub := filepath.Join(root, "wp-content", "uploads", "2026", ".htaccess")
	os.WriteFile(top, []byte(hackedHtaccess["mixed case with rewrite"]), 0o644)
	os.WriteFile(sub, []byte(hackedHtaccess["lock list"]), 0o644)
	s.ScanFile(top)
	s.ScanFile(sub)

	if _, err := os.Stat(sub); err == nil {
		t.Fatal("hacked .htaccess in a sub folder not quarantined")
	}
	got, err := os.ReadFile(top)
	if err != nil || strings.Contains(string(got), "FilesMatch") || !strings.Contains(string(got), "RewriteRule . /index.php") {
		t.Fatalf("root .htaccess: %v\n%s", err, got)
	}
	list, _, _ := s.ListFindings(FindingFilter{Limit: 10})
	status := map[string]Finding{}
	for _, f := range list {
		status[f.Path] = f
	}
	if f := status[top]; f.Status != "cleaned" || f.Note != NoteHtaccess {
		t.Fatalf("root finding: %+v", f)
	}
	if f := status[sub]; f.Status != "quarantined" {
		t.Fatalf("sub folder finding: %+v", f)
	}
	// The cleaned file is not flagged again.
	s.ScanFile(top)
	if _, n, _ := s.ListFindings(FindingFilter{Limit: 10}); n != 2 {
		t.Fatalf("%d findings after a rescan", n)
	}
	// Restore brings the hacked copy back.
	if err := s.Restore(status[top].ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(top); string(got) != hackedHtaccess["mixed case with rewrite"] {
		t.Fatalf("restore: %s", got)
	}
}
