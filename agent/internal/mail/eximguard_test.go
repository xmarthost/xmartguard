package mail

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func cpanelRoot(t *testing.T, opts string) string {
	t.Helper()
	root := t.TempDir()
	eximRoot = root
	t.Cleanup(func() { eximRoot = "" })
	os.MkdirAll(filepath.Join(root, "usr/local/cpanel"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/local/cpanel/cpanel"), nil, 0o755)
	os.MkdirAll(filepath.Join(root, rblDir), 0o755)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, eximLocalOpt), []byte(opts), 0o644)
	if _, err := EnsureEximRBLs(); err != nil {
		t.Fatal(err)
	}
	return root
}

// fakeDNS answers like the real lists: answers maps a zone to its test
// entry's answer ("" = no answer).
func fakeDNS(t *testing.T, answers map[string]string) {
	old := LookupHost
	LookupHost = func(_ context.Context, host string) ([]string, error) {
		for zone, a := range answers {
			if host == "2.0.0.127."+zone && a != "" {
				return []string{a}, nil
			}
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { LookupHost = old })
}

func TestEximGuardRBLs(t *testing.T) {
	root := cpanelRoot(t, "acl_mailspike_rbl=1\nsystemfilter=/etc/cpanel_exim_system_filter\n")
	rebuilds := 0
	old := RebuildExim
	RebuildExim = func() error {
		rebuilds++
		// cPanel builds the system filter from the switched-on options.
		b, _ := os.ReadFile(filepath.Join(root, eximLocalOpt))
		f := ""
		if strings.Contains(string(b), "filter_xpguard_phishing=1") {
			x, _ := os.ReadFile(filepath.Join(root, sysfilterDir, phishFilterName))
			f = string(x)
		}
		return os.WriteFile(filepath.Join(root, defaultSysFile), []byte(f), 0o644)
	}
	defer func() { RebuildExim = old }()
	// Spamhaus refuses this resolver (public DNS), Barracuda needs a
	// registration; the others answer.
	fakeDNS(t, map[string]string{"zen.spamhaus.org": "127.255.255.254", "bl.spamcop.net": "127.0.0.2", "psbl.surriel.com": "127.0.0.2", "bl.mailspike.net": "127.0.0.2"})
	st, ours := ApplyEximGuard(context.Background(), true, true, nil)
	opts, _ := os.ReadFile(filepath.Join(root, eximLocalOpt))
	o := string(opts)
	for key, want := range map[string]string{"acl_spamhaus_rbl": "", "acl_spamcop_rbl": "1", "acl_psbl_rbl": "1", "acl_barracuda_rbl": "0", "acl_mailspike_rbl": "1", "filter_xpguard_phishing": "1"} {
		if got := optValue(o, key); got != want {
			t.Errorf("%s = %q, want %q\n%s", key, got, want, o)
		}
	}
	if strings.Join(ours, ",") != "psbl,spamcop" || rebuilds != 1 || st.Phishing != "active" || st.Error != "" {
		t.Fatalf("ours %v rebuilds %d status %+v", ours, rebuilds, st)
	}
	for _, r := range st.RBLs {
		switch r.Name {
		case "spamhaus":
			if r.Enabled || !strings.Contains(r.Problem, "refuses") {
				t.Errorf("spamhaus %+v", r)
			}
		case "mailspike":
			if r.By != "admin" {
				t.Errorf("mailspike %+v", r)
			}
		}
	}
	// Nothing changed: no rebuild.
	if _, again := ApplyEximGuard(context.Background(), true, true, ours); rebuilds != 1 || strings.Join(again, ",") != "psbl,spamcop" {
		t.Fatalf("rebuilt again (%d) %v", rebuilds, again)
	}
	// SpamCop stops answering: xPGuard switches it off again.
	fakeDNS(t, map[string]string{"psbl.surriel.com": "127.0.0.2", "bl.mailspike.net": "127.0.0.2"})
	_, ours = ApplyEximGuard(context.Background(), true, true, ours)
	opts, _ = os.ReadFile(filepath.Join(root, eximLocalOpt))
	if optValue(string(opts), "acl_spamcop_rbl") != "0" || strings.Join(ours, ",") != "psbl" {
		t.Fatalf("spamcop not switched off: %v\n%s", ours, opts)
	}
	// Both off: what xPGuard switched on goes off, the admin's list stays.
	st, ours = ApplyEximGuard(context.Background(), false, false, ours)
	opts, _ = os.ReadFile(filepath.Join(root, eximLocalOpt))
	o = string(opts)
	if optValue(o, "acl_psbl_rbl") != "0" || optValue(o, "acl_mailspike_rbl") != "1" || optValue(o, "filter_xpguard_phishing") != "0" || len(ours) != 0 || st.Phishing != "off" {
		t.Fatalf("off: %v %+v\n%s", ours, st, o)
	}
	if _, err := os.Stat(filepath.Join(root, sysfilterDir, phishFilterName)); err == nil {
		t.Fatal("filter option file left behind")
	}
}

func TestRBLTest(t *testing.T) {
	fakeDNS(t, map[string]string{"ok.example": "127.0.0.2", "err.example": "127.255.255.254", "odd.example": "10.0.0.1"})
	for zone, ok := range map[string]bool{"ok.example": true, "err.example": false, "odd.example": false, "none.example": false} {
		if got := RBLTest(context.Background(), zone) == ""; got != ok {
			t.Errorf("%s: ok=%v", zone, got)
		}
	}
	old := LookupHost
	LookupHost = func(context.Context, string) ([]string, error) { return []string{"127.0.0.2"}, nil }
	defer func() { LookupHost = old }()
	if RBLTest(context.Background(), "all.example") == "" {
		t.Error("a list that lists 127.0.0.1 passed")
	}
}

// The filter, run by a real Exim (when installed): the phishing of the
// support ticket is tagged, ordinary mail is not. Exim's test mode has no
// remote host and its authenticated user depends on how it is called, so
// those two conditions are left out of the test.
func TestPhishingFilterWithExim(t *testing.T) {
	exim, err := exec.LookPath("exim4")
	if err != nil {
		if exim, err = exec.LookPath("exim"); err != nil {
			t.Skip("exim not installed")
		}
	}
	f := strings.Replace(phishFilter, `$sender_host_address is not ""`, `$sender_host_address is ""`, 1)
	f = strings.Replace(f, `$authenticated_id is ""`, `first_delivery`, 1)
	path := filepath.Join(t.TempDir(), "filter")
	os.WriteFile(path, []byte(f), 0o644)
	for _, c := range []struct {
		from, subject string
		tagged        bool
	}{
		{`"cPanel" <noreply@evil.example>`, "[ almoizz.com ] Credential Validation For [ info ]", true},
		{`"Webmail Admin" <x@evil.example>`, "Your mailbox is full", true},
		{`"Mail Server" <a@evil.example>`, "3 pending incoming messages", true},
		{`"Ali Khan" <ali@gmail.com>`, "Please verify the invoice", false},
		{`"cPanel" <news@cpanel.net>`, "Upgrade to cPanel 132", false},
		{`"Mail Delivery System" <MAILER-DAEMON@mx.example>`, "Undelivered Mail Returned to Sender", false},
		{`"Microsoft account team" <account-security-noreply@accountprotection.microsoft.com>`, "Microsoft account security alert", false},
		{`"cPanel" <noreply@evil.example>`, "[PHISHING WARNING] Credential Validation", false},
	} {
		sender := c.from[strings.Index(c.from, "<")+1 : len(c.from)-1]
		msg := "From: " + c.from + "\nTo: info@almoizz.com\nSubject: " + c.subject + "\n\nhello\n"
		cmd := exec.Command(exim, "-d+filter", "-bF", path, "-f", sender)
		cmd.Stdin = strings.NewReader(msg)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.subject, err, out)
		}
		if got := strings.Contains(string(out), `Headers add "Subject: [PHISHING WARNING] `+c.subject); got != c.tagged {
			t.Errorf("%s / %s: tagged=%v\n%s", c.from, c.subject, got, out)
		}
	}
}

// Spamhaus refuses public resolvers; with a DQS key the DQS list is defined
// and switched on instead, and goes again when the key is removed.
func TestEximGuardSpamhausDQS(t *testing.T) {
	root := cpanelRoot(t, "")
	old := RebuildExim
	RebuildExim = func() error { return nil }
	defer func() { RebuildExim = old }()
	key := "abcdefghijklmnopqrstuvwxyz"
	fakeDNS(t, map[string]string{"zen.spamhaus.org": "127.255.255.254", key + ".zen.dq.spamhaus.net": "127.0.0.2"})
	st, ours := ApplyEximGuardDQS(context.Background(), true, false, key, nil)
	opts, _ := os.ReadFile(filepath.Join(root, eximLocalOpt))
	y, err := os.ReadFile(filepath.Join(root, rblDir, DQSName+".yaml"))
	if err != nil || !strings.Contains(string(y), "'"+key+".zen.dq.spamhaus.net'") || optValue(string(opts), "acl_spamhausdqs_rbl") != "1" || optValue(string(opts), "acl_spamhaus_rbl") != "" {
		t.Fatalf("DQS not on: %v\n%s\n%s", err, y, opts)
	}
	for _, r := range st.RBLs {
		if strings.Contains(r.Zone, key) {
			t.Fatal("the key is shown in the status")
		}
	}
	// A wrong key: Spamhaus does not answer, the list stays off.
	_, _ = ApplyEximGuardDQS(context.Background(), true, false, "wrongkeywrongkeywrongkey", ours)
	opts, _ = os.ReadFile(filepath.Join(root, eximLocalOpt))
	if optValue(string(opts), "acl_spamhausdqs_rbl") != "0" {
		t.Fatalf("wrong key switched on:\n%s", opts)
	}
	// Key removed: definition and option go.
	_, ours = ApplyEximGuardDQS(context.Background(), true, false, "", []string{DQSName})
	opts, _ = os.ReadFile(filepath.Join(root, eximLocalOpt))
	if _, err := os.Stat(filepath.Join(root, rblDir, DQSName+".yaml")); err == nil || optValue(string(opts), "acl_spamhausdqs_rbl") != "0" {
		t.Fatalf("DQS left behind:\n%s", opts)
	}
	for _, n := range ours {
		if n == DQSName {
			t.Fatal("still counted as ours")
		}
	}
}
