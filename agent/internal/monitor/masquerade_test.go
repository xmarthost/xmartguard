package monitor

import (
	"os"
	"path/filepath"
	"testing"
)

// The botnet of murtajez.com (2026-10-17): programs in an addon domain's
// WordPress posing as system services, and sh watchdogs whose script was
// deleted.
func TestMasqueradingProcesses(t *testing.T) {
	home := t.TempDir()
	site := filepath.Join(home, "murtajez.com")
	os.MkdirAll(filepath.Join(site, "wp-content"), 0o755)
	live := filepath.Join(site, "cron.sh")
	os.WriteFile(live, []byte("#!/bin/sh\n"), 0o644)
	mal := []ProcInfo{
		{Exe: site + "/wp-content/plugins/woocommerce/.x/polkitd", Cmdline: "polkitd --no-debug"},
		{Exe: site + "/wp-includes/sodium_compat/.y/gdm3", Cmdline: "gdm3"},
		{Exe: site + "/wp-content/.z/a1b2 (deleted)", Cmdline: "systemd-resolved"},
		{Exe: site + "/bridgemgr (deleted)", Cmdline: site + "/bridgemgr -c data.json"},
		{Exe: "/usr/bin/perl", Cmdline: "[kworker/0:1]"},
		{Exe: "/usr/bin/bash", Cmdline: "sh " + site + "/wp-content/.tmp"},
	}
	for _, p := range mal {
		if r, l := Assess(p, home); l != Malicious {
			t.Errorf("%s (%s): %v %q", p.Exe, p.Cmdline, l, r)
		}
	}
	ok := []ProcInfo{
		{Exe: "/opt/alt/php82/usr/bin/lsphp", Cmdline: "lsphp"},
		{Exe: "/usr/bin/bash", Cmdline: "sh " + live},
		{Exe: "/usr/bin/php", Cmdline: "php " + site + "/artisan-gone.php"}, // php is not judged by a missing file
		{Exe: home + "/.nvm/versions/node/v20/bin/node", Cmdline: "node server.js"},
		{Exe: "/usr/bin/bash", Cmdline: "bash -c cd " + site},
	}
	for _, p := range ok {
		if r, l := Assess(p, home); l == Malicious {
			t.Errorf("%s (%s) killed: %q", p.Exe, p.Cmdline, r)
		}
	}
	// A plain program in the addon domain's folder is reported, not killed outright.
	if _, l := Assess(ProcInfo{Exe: site + "/ffmpeg", Cmdline: "ffmpeg -i a.mp4"}, home); l != Suspicious {
		t.Errorf("program in an addon domain folder: %v", l)
	}
}
