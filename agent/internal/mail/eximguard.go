package mail

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Exim guard: inbound mail protection on cPanel servers.
//
// Blocklists: a DNS blocklist is only switched on when it answers correctly
// from this server's resolver: its test entry 127.0.0.2 is listed and
// 127.0.0.1 is not. Spamhaus refuses queries from public resolvers (Google,
// Cloudflare) with 127.255.255.x answers; a list switched on there would
// refuse every message, so it stays off. A list xPGuard switched on is
// switched off again when its test starts failing; lists the administrator
// switched on are left alone.
//
// Phishing filter: an Exim system filter option (WHM » Exim Configuration
// Manager » Filters) that tags mail from outside, without SMTP login, whose
// sender name claims to be cPanel, Webmail or the mail administrator and
// whose subject asks to verify, log in, or warns of deletion, suspension or
// a full mailbox. The subject gets "[PHISHING WARNING]" and the header
// X-xPGuard-Phishing; the message is still delivered.

// AutoRBL is a blocklist the guard may switch on.
type AutoRBL struct {
	Name string // cPanel option acl_<Name>_rbl
	Zone string
}

// AutoRBLs: cPanel's built-in Spamhaus ZEN and SpamCop, and the extra lists
// with few false positives (abuseat is part of ZEN; spameatingmonkey is
// strict and stays for the administrator to choose).
var AutoRBLs = []AutoRBL{
	{"spamhaus", "zen.spamhaus.org"},
	{"spamcop", "bl.spamcop.net"},
	{"psbl", "psbl.surriel.com"},
	{"mailspike", "bl.mailspike.net"},
	{"barracuda", "b.barracudacentral.org"},
}

const (
	phishFilterName = "xpguard_phishing"
	phishMarker     = "# xPGuard phishing filter"
	sysfilterDir    = "/usr/local/cpanel/etc/exim/sysfilter/options"
	defaultSysFile  = "/etc/cpanel_exim_system_filter"
)

// phishFilter is Exim filter language; "matches" is case-independent.
const phishFilter = phishMarker + ` (added by xPGuard; switch off in the xPGuard portal)
if first_delivery
   and $sender_host_address is not ""
   and $authenticated_id is ""
   and $h_from: matches "(c-?panel|web ?mail|(e-?)?mail ?(server|admin|administrator|support|team|service|security)|mailbox ?(admin|administrator|support|team|service|security))"
   and $sender_address_domain is not "cpanel.net"
   and $sender_address_domain is not "cpanel.com"
   and $h_subject: matches "(credential|verif|validat|deactivat|reactivat|suspen|terminat|delet|password|expir|quota|storage|mailbox (is )?full|pending (incoming )?(e-?mails|messages)|on hold|upgrade|sign.?in|log.?in|security alert|unusual)"
   and $h_subject: does not begin "[PHISHING"
then
   headers add "X-xPGuard-Phishing: likely (sender name pretends to be the mail provider)"
   headers add "Old-Subject: $h_subject:"
   headers remove "Subject"
   headers add "Subject: [PHISHING WARNING] $h_old-subject:"
   headers remove "Old-Subject"
endif
`

// LookupHost resolves names (tests replace it).
var LookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// RebuildExim rebuilds Exim's configuration and restarts it (tests replace it).
var RebuildExim = func() error {
	for _, c := range [][]string{{"/scripts/buildeximconf"}, {"/scripts/restartsrv_exim"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		out, err := exec.CommandContext(ctx, c[0], c[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			return errors.New(c[0] + ": " + strings.TrimSpace(lastLine(string(out))) + " (" + err.Error() + ")")
		}
	}
	return nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// RBLTest checks a blocklist from this server's resolver: "" when it works.
func RBLTest(ctx context.Context, zone string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := LookupHost(ctx, "2.0.0.127."+zone)
	if err != nil || len(addrs) == 0 {
		return "no answer for its test entry (the list may need a registered resolver)"
	}
	for _, a := range addrs {
		ip := net.ParseIP(a).To4()
		if ip == nil || ip[0] != 127 || (ip[1] == 255 && ip[2] == 255) {
			return "refuses this server's DNS resolver (answer " + a + "); use a local resolver"
		}
	}
	if addrs, err := LookupHost(ctx, "1.0.0.127."+zone); err == nil && len(addrs) > 0 {
		return "lists every address (answer " + addrs[0] + ")"
	}
	return ""
}

// EximGuardRBL is the state of one blocklist.
type EximGuardRBL struct {
	Name    string `json:"name"`
	Zone    string `json:"zone"`
	Enabled bool   `json:"enabled"`
	By      string `json:"by,omitempty"`      // xpguard | admin
	Problem string `json:"problem,omitempty"` // why it is not on
}

// EximGuardStatus is the result of the last run.
type EximGuardStatus struct {
	Supported bool           `json:"supported"`
	RBLs      []EximGuardRBL `json:"rbls"`
	Phishing  string         `json:"phishing"` // off | active | added (not in the system filter)
	Rebuilt   bool           `json:"rebuilt"`
	Error     string         `json:"error,omitempty"`
	At        int64          `json:"at"`
}

// ApplyEximGuard brings Exim in line with the settings. ours are the lists
// xPGuard switched on before; the new list is returned.
func ApplyEximGuard(ctx context.Context, rbls, phishing bool, ours []string) (EximGuardStatus, []string) {
	st := EximGuardStatus{At: time.Now().Unix()}
	if !cpanelExim() {
		return st, ours
	}
	st.Supported = true
	raw, _ := os.ReadFile(eximPath(eximLocalOpt))
	opts := string(raw)
	mine := map[string]bool{}
	for _, n := range ours {
		mine[n] = true
	}
	for _, r := range AutoRBLs {
		key := "acl_" + r.Name + "_rbl"
		on := optValue(opts, key) == "1"
		e := EximGuardRBL{Name: r.Name, Zone: r.Zone, Enabled: on}
		switch {
		case on && !mine[r.Name]:
			e.By = "admin"
		case !rbls:
			if mine[r.Name] {
				opts = setOpt(opts, key, "0")
				delete(mine, r.Name)
				e.Enabled = false
			}
		case !builtinRBL(r.Name) && !fileExists(eximPath(filepath.Join(rblDir, r.Name+".yaml"))):
			e.Problem = "not defined in WHM » Exim Configuration Manager » RBLs"
		default:
			if p := RBLTest(ctx, r.Zone); p != "" {
				e.Problem = p
				if mine[r.Name] {
					opts = setOpt(opts, key, "0")
					delete(mine, r.Name)
					e.Enabled = false
				}
			} else {
				opts = setOpt(opts, key, "1")
				mine[r.Name] = true
				e.Enabled, e.By = true, "xpguard"
			}
		}
		st.RBLs = append(st.RBLs, e)
	}
	changed := opts != string(raw)
	// The phishing filter option.
	fpath := eximPath(filepath.Join(sysfilterDir, phishFilterName))
	fkey := "filter_" + phishFilterName
	if phishing {
		if b, err := os.ReadFile(fpath); err != nil || string(b) != phishFilter {
			if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err == nil {
				if err := os.WriteFile(fpath, []byte(phishFilter), 0o644); err != nil {
					st.Error = err.Error()
				} else {
					changed = true
				}
			}
		}
		if optValue(opts, fkey) != "1" {
			opts = setOpt(opts, fkey, "1")
			changed = true
		}
	} else if fileExists(fpath) || optValue(opts, fkey) == "1" {
		_ = os.Remove(fpath)
		opts = setOpt(opts, fkey, "0")
		changed = true
	}
	if opts != string(raw) {
		if err := os.WriteFile(eximPath(eximLocalOpt), []byte(opts), 0o644); err != nil {
			st.Error = err.Error()
			return st, ours
		}
	}
	if changed {
		if err := RebuildExim(); err != nil {
			st.Error = err.Error()
		} else {
			st.Rebuilt = true
		}
	}
	st.Phishing = "off"
	if phishing {
		st.Phishing = "added"
		if b, err := os.ReadFile(eximPath(systemFilterPath(opts))); err == nil && strings.Contains(string(b), phishMarker) {
			st.Phishing = "active"
		}
	}
	out := make([]string, 0, len(mine))
	for n := range mine {
		out = append(out, n)
	}
	sort.Strings(out)
	return st, out
}

func builtinRBL(name string) bool { return name == "spamhaus" || name == "spamcop" }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// systemFilterPath is the system filter Exim uses (cPanel builds it from
// the filter options).
func systemFilterPath(opts string) string {
	if v := optValue(opts, "systemfilter"); strings.HasPrefix(v, "/") {
		return v
	}
	return defaultSysFile
}

// optValue reads key=value from exim.conf.localopts.
func optValue(opts, key string) string {
	for _, l := range strings.Split(opts, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// setOpt sets key=value, replacing an existing line or appending one.
func setOpt(opts, key, val string) string {
	lines := strings.Split(strings.TrimRight(opts, "\n"), "\n")
	if opts == "" {
		lines = nil
	}
	found := false
	for i, l := range lines {
		if k, _, ok := strings.Cut(strings.TrimSpace(l), "="); ok && k == key {
			lines[i] = key + "=" + val
			found = true
		}
	}
	if !found {
		lines = append(lines, key+"="+val)
	}
	return strings.Join(lines, "\n") + "\n"
}
