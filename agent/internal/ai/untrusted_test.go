package ai

import (
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// From the AI Learning export: the AI called these clean; they are where
// (or what) malware is, so an administrator decides.
func TestUntrustedCleanVerdicts(t *testing.T) {
	risky := map[string]string{
		"/home/u/site.com/wp-content/plugins/helix-config-mod/helix-config-mod.php": "PHP.Backdoor.GlobalsDispatch",
		"/home/u/site.com/wp-content/.sc_1d91536f/4cf27233.php":                     "PHP.Backdoor.SomethingElse",
		"/home/u/site.com/wp-content/object-cache.php":                              "PHP.Backdoor.SomethingElse",
		"/home/u/site.com/wp-admin/user/cgi.php":                                    "PHP.Backdoor.FileDropper",
		"/home/u/public_html/wp-content/uploads/2026/10/bd-60c11765f07a.zip":        "Archive.PHP.Obfuscated.CharDecoder",
	}
	for p, sig := range risky {
		if Untrusted(p, sig) == "" {
			t.Errorf("%s (%s) trusted", p, sig)
		}
	}
	ok := map[string]string{
		"/home/u/public_html/erp/core/lib/functions.lib.php":               "PHP.WebShell.ExecAlternatives",
		"/home/u/app/controllers/Users.php":                                "Phishing.Collector",
		"/home/u/public_html/.well-known/acme-challenge/x.php":             "PHP.Suspicious.EncodedPayload",
		"/home/u/public_html/.htaccess":                                    "PHP.Config.AutoPrepend",
		"/home/u/public_html/wp-content/plugins/wordfence/lib/wfUtils.php": "PHP.Obfuscated.CharEncoded",
		"/home/u/.local/share/psysh/php_manual.php":                        "PHP.Obfuscated.HaltCompilerPayload",
	}
	for p, sig := range ok {
		if why := Untrusted(p, sig); why != "" {
			t.Errorf("%s (%s) untrusted: %s", p, sig, why)
		}
	}
}

func TestUntrustedSignatureStaysFlagged(t *testing.T) {
	a, _ := setup(t, "")
	db := a.DB
	if _, err := db.Exec(`INSERT INTO findings (source, path, sha256, signature, category, status, created_at, updated_at) VALUES
		('scheduled', '/x/helix.php', 'aa', 'PHP.Backdoor.GlobalsDispatch', 'virus', 'ai_restored', 1, 1),
		('scheduled', '/x/ok.php', 'bb', 'PHP.Obfuscated.CharEncoded', 'suspicious', 'ai_restored', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{"aa", "bb"} {
		Save(db, Verdict{SHA256: sha, Verdict: Clean, Confidence: 100, Source: "fleet", Model: "admin", At: store.Now()})
	}
	// Another server's AI alone does not clear a file here.
	Save(db, Verdict{SHA256: "cc", Verdict: Clean, Confidence: 100, Source: "fleet", Model: "groq", At: store.Now()})
	if IsCleared(db, "cc") {
		t.Fatal("a fleet AI verdict cleared a file")
	}
	if IsCleared(db, "aa") {
		t.Fatal("a GlobalsDispatch file the fleet called clean is not flagged again")
	}
	if !IsCleared(db, "bb") {
		t.Fatal("an ordinary false positive is not cleared")
	}
	Save(db, Verdict{SHA256: "aa", Verdict: Clean, Confidence: 100, Source: SourceAdmin, At: store.Now()})
	if !IsCleared(db, "aa") || !AdminCleared(db, "aa") {
		t.Fatal("an administrator's decision does not stand")
	}
}
