package mail

import (
	"os"
	"path/filepath"
	"strings"
)

// Extra DNS blocklists for Exim on cPanel. cPanel lists every YAML file in
// /var/cpanel/rbl_info in WHM » Exim Configuration Manager » RBLs; each
// is added switched off (acl_<name>_rbl=0) for the administrator to turn on.
// Spamhaus ZEN and SpamCop are built into cPanel and not repeated.

// EximRBL is one blocklist definition.
type EximRBL struct {
	Name string // cPanel option name (acl_<Name>_rbl)
	Zone string
	URL  string // lookup/removal page shown in WHM
}

// EximRBLs are well-known public blocklists usable without a subscription
// (Barracuda asks for a free registration of the querying DNS server).
var EximRBLs = []EximRBL{
	{"barracuda", "b.barracudacentral.org", "https://www.barracudacentral.org/lookups"},
	{"spameatingmonkey", "bl.spameatingmonkey.net", "https://spameatingmonkey.com/lookup"},
	{"abuseat", "cbl.abuseat.org", "https://www.abuseat.org/lookup/"},
	{"psbl", "psbl.surriel.com", "https://psbl.org/"},
	{"mailspike", "bl.mailspike.net", "https://mailspike.org/"},
}

// eximRoot prefixes paths (tests).
var eximRoot = ""

const (
	rblDir       = "/var/cpanel/rbl_info"
	eximLocalOpt = "/etc/exim.conf.localopts"
	rblMarker    = "# Added by xPGuard"
	legacyMarker = "# Added by XMart Guard" // versions before the xPGuard name
)

func eximPath(p string) string { return filepath.Join(eximRoot, p) }

// cpanelExim reports a cPanel server (where the RBL files mean something).
func cpanelExim() bool {
	_, err := os.Stat(eximPath("/usr/local/cpanel/cpanel"))
	return err == nil
}

func rblYAML(r EximRBL) string {
	return rblMarker + "\n---\n\"dnslists\":\n  - '" + r.Zone + "'\n\"name\": '" + r.Name + "'\n\"url\": '" + r.URL + "'\n"
}

// EnsureEximRBLs adds the blocklists that are not defined yet. A definition
// that already exists (added by the administrator or another product) is
// left as it is. Returns the names added.
func EnsureEximRBLs() ([]string, error) {
	if !cpanelExim() {
		return nil, nil
	}
	if err := os.MkdirAll(eximPath(rblDir), 0o755); err != nil {
		return nil, err
	}
	opts, _ := os.ReadFile(eximPath(eximLocalOpt))
	var added, newOpts []string
	for _, r := range EximRBLs {
		p := eximPath(filepath.Join(rblDir, r.Name+".yaml"))
		if b, err := os.ReadFile(p); err == nil {
			// A definition from before the xPGuard name gets the new marker.
			if strings.HasPrefix(string(b), legacyMarker) {
				_ = os.WriteFile(p, []byte(rblYAML(r)), 0o644)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(rblYAML(r)), 0o644); err != nil {
			return added, err
		}
		added = append(added, r.Name)
		key := "acl_" + r.Name + "_rbl="
		if !hasOptLine(string(opts), key) {
			newOpts = append(newOpts, key+"0")
		}
	}
	if len(newOpts) > 0 {
		f, err := os.OpenFile(eximPath(eximLocalOpt), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return added, err
		}
		if len(opts) > 0 && !strings.HasSuffix(string(opts), "\n") {
			_, _ = f.WriteString("\n")
		}
		_, err = f.WriteString(strings.Join(newOpts, "\n") + "\n")
		f.Close()
		if err != nil {
			return added, err
		}
	}
	return added, nil
}

func hasOptLine(opts, key string) bool {
	for _, l := range strings.Split(opts, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), key) {
			return true
		}
	}
	return false
}

// RemoveEximRBLs deletes the definitions xPGuard added (uninstall).
// An RBL the administrator switched on is removed from exim's options too,
// so Exim never queries a list whose definition is gone.
func RemoveEximRBLs() []string {
	var removed []string
	for _, r := range EximRBLs {
		p := eximPath(filepath.Join(rblDir, r.Name+".yaml"))
		b, err := os.ReadFile(p)
		if err != nil || !ownRBLFile(b) {
			continue
		}
		if os.Remove(p) == nil {
			removed = append(removed, r.Name)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if b, err := os.ReadFile(eximPath(eximLocalOpt)); err == nil {
		var keep []string
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			drop := false
			for _, n := range removed {
				if strings.HasPrefix(strings.TrimSpace(l), "acl_"+n+"_rbl=") {
					drop = true
				}
			}
			if !drop {
				keep = append(keep, l)
			}
		}
		_ = os.WriteFile(eximPath(eximLocalOpt), []byte(strings.Join(keep, "\n")+"\n"), 0o644)
	}
	return removed
}

// EximRBLStatus reports each list: defined, and whether Exim uses it.
type EximRBLState struct {
	Name    string `json:"name"`
	Zone    string `json:"zone"`
	Defined bool   `json:"defined"`
	Enabled bool   `json:"enabled"`
}

// EximRBLStatus reads the current state (empty on servers without cPanel).
func EximRBLStatus() []EximRBLState {
	if !cpanelExim() {
		return nil
	}
	opts, _ := os.ReadFile(eximPath(eximLocalOpt))
	var out []EximRBLState
	for _, r := range EximRBLs {
		_, err := os.Stat(eximPath(filepath.Join(rblDir, r.Name+".yaml")))
		out = append(out, EximRBLState{Name: r.Name, Zone: r.Zone, Defined: err == nil, Enabled: hasOptLine(string(opts), "acl_"+r.Name+"_rbl=1")})
	}
	return out
}

// ownRBLFile reports a definition written by this package (either name).
func ownRBLFile(b []byte) bool {
	return strings.HasPrefix(string(b), rblMarker) || strings.HasPrefix(string(b), legacyMarker)
}
