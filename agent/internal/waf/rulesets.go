package waf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// RuleSets is the fleet-wide ModSecurity configuration made in the portal
// (WAF Rule Sets): XMart Guard's own rules, the OWASP Core Rule Set, cPanel
// ModSecurity vendors (Malware.Expert, Comodo, …) and custom rules.
type RuleSets struct {
	Version    int64 `json:"version"`
	XMartGuard *struct {
		Enabled bool `json:"enabled"`
	} `json:"xmartguard,omitempty"`
	CRS struct {
		Enabled           bool   `json:"enabled"`
		Version           string `json:"version"` // installed release, e.g. 4.29.0
		Paranoia          int    `json:"paranoia"`
		InboundThreshold  int    `json:"inbound_threshold"`
		OutboundThreshold int    `json:"outbound_threshold"`
	} `json:"crs"`
	Vendors []Vendor `json:"vendors"`
	Custom  struct {
		Enabled bool   `json:"enabled"`
		Rules   string `json:"rules"`
	} `json:"custom"`
}

// Vendor is a cPanel ModSecurity vendor, added from its configuration
// (YAML) URL like WHM » ModSecurity Vendors » Add Vendor does.
type Vendor struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// RuleSetState is how one rule set is doing on this server.
type RuleSetState struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"` // active | off | skipped | error | unsupported
	Detail  string `json:"detail,omitempty"`
	Version string `json:"version,omitempty"`
}

// SetRuleSets stores the portal's configuration for the next Apply.
func (m *Manager) SetRuleSets(rs RuleSets) {
	m.mu.Lock()
	m.ruleSets = rs
	m.mu.Unlock()
}

func (m *Manager) crsDir(version string) string {
	return filepath.Join(m.RulesDir, "crs", version)
}

var reCRSFile = regexp.MustCompile(`^(crs-setup\.conf\.example|rules/[A-Za-z0-9._-]+\.(?:conf|data))$`)

// InstallCRS writes an OWASP CRS release (files the portal took from the
// official GitHub release) to the rules directory.
func (m *Manager) InstallCRS(version string, files map[string]string) error {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		return fmt.Errorf("invalid CRS version %q", version)
	}
	if _, ok := files["crs-setup.conf.example"]; !ok {
		return errors.New("the CRS release has no crs-setup.conf.example")
	}
	dir := m.crsDir(version)
	tmp := dir + ".new"
	_ = os.RemoveAll(tmp)
	n := 0
	for name, body := range files {
		if !reCRSFile.MatchString(name) {
			continue
		}
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			return err
		}
		if strings.HasSuffix(name, ".conf") {
			n++
		}
	}
	if n == 0 {
		return errors.New("the CRS release has no rule files")
	}
	_ = os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	// Keep only this release.
	old, _ := filepath.Glob(filepath.Join(m.RulesDir, "crs", "*"))
	for _, o := range old {
		if o != dir {
			_ = os.RemoveAll(o)
		}
	}
	return nil
}

// CRSInstalled reports whether a CRS release is on disk.
func (m *Manager) CRSInstalled(version string) bool {
	return version != "" && exists(filepath.Join(m.crsDir(version), "crs-setup.conf.example"))
}

// systemCRS reports whether the web server already loads an OWASP CRS of
// its own (cPanel's OWASP vendor, Debian's modsecurity-crs, RHEL's
// mod_security_crs): loading CRS twice fails on duplicate rule ids.
func systemCRS(t Target) string {
	active := func(file, marker string) bool {
		b, err := os.ReadFile(file)
		if err != nil {
			return false
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "#") && strings.Contains(l, marker) {
				return true
			}
		}
		return false
	}
	switch t.Name {
	case "cpanel":
		if active("/etc/apache2/conf.d/modsec/modsec2.cpanel.conf", "modsec_vendor_configs/OWASP") {
			return "cPanel's OWASP ModSecurity vendor"
		}
	case "debian":
		if exists(SystemCRSRoot+"/owasp-crs.load") && active("/etc/apache2/mods-enabled/security2.conf", "modsecurity-crs/") {
			return "the modsecurity-crs package"
		}
	case "rhel":
		if m, _ := filepath.Glob("/etc/httpd/modsecurity.d/activated_rules/*.conf"); len(m) > 0 || exists("/etc/httpd/modsecurity.d/crs-setup.conf") {
			return "the mod_security_crs package"
		}
	}
	return ""
}

// SystemCRSRoot is Debian's CRS package directory (a variable for tests).
var SystemCRSRoot = "/usr/share/modsecurity-crs"

// extras renders the includes for the OWASP CRS and custom rules, the
// files they need, and their state.
func (m *Manager) extras(t Target) (string, map[string]string, []RuleSetState) {
	m.mu.Lock()
	rs := m.ruleSets
	m.mu.Unlock()
	var inc strings.Builder
	files := map[string]string{}
	var states []RuleSetState

	crs := RuleSetState{ID: "owasp_crs", Name: "OWASP Core Rule Set", Version: rs.CRS.Version}
	switch {
	case !rs.CRS.Enabled:
		crs.State = "off"
	case systemCRS(t) != "":
		crs.State, crs.Detail = "skipped", "already loaded by "+systemCRS(t)+" on this server"
	case !m.CRSInstalled(rs.CRS.Version):
		crs.State, crs.Detail = "error", "the rule files have not been downloaded from the portal yet"
	default:
		pl := clampInt(rs.CRS.Paranoia, 1, 4, 1)
		in := clampInt(rs.CRS.InboundThreshold, 3, 1000, 5)
		out := clampInt(rs.CRS.OutboundThreshold, 2, 1000, 4)
		dir := m.crsDir(rs.CRS.Version)
		setup := filepath.Join(m.RulesDir, "crs-setup.conf")
		plVar := "blocking_paranoia_level" // CRS 4
		if strings.HasPrefix(rs.CRS.Version, "3.") {
			plVar = "paranoia_level"
		}
		files[setup] = fmt.Sprintf("# OWASP CRS %s set up by XMart Guard (WAF Rule Sets in the portal).\nInclude %s\n"+
			"SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.%s=%d\"\n"+
			"SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
			rs.CRS.Version, filepath.Join(dir, "crs-setup.conf.example"), plVar, pl, in, out)
		fmt.Fprintf(&inc, "\n# OWASP Core Rule Set %s\nInclude %s\nInclude %s\n", rs.CRS.Version, setup, filepath.Join(dir, "rules", "*.conf"))
		crs.State, crs.Detail = "active", fmt.Sprintf("paranoia level %d, anomaly threshold %d", pl, in)
	}
	states = append(states, crs)

	custom := RuleSetState{ID: "custom", Name: "Custom rules"}
	switch {
	case !rs.Custom.Enabled || strings.TrimSpace(rs.Custom.Rules) == "":
		custom.State = "off"
	default:
		if err := ValidateCustomRules(rs.Custom.Rules); err != nil {
			custom.State, custom.Detail = "error", err.Error()
			break
		}
		p := filepath.Join(m.RulesDir, "custom.conf")
		files[p] = "# Custom rules from the XMart Guard portal (WAF Rule Sets).\n" + rs.Custom.Rules + "\n"
		fmt.Fprintf(&inc, "\n# Custom rules\nInclude %s\n", p)
		custom.State = "active"
	}
	states = append(states, custom)
	return inc.String(), files, states
}

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Custom rules may only use ModSecurity rule directives: an Apache
// directive (CustomLog "|cmd", LoadModule …) or an exec action would let a
// portal user run commands on every server.
var (
	allowedDirectives = map[string]bool{
		"secrule": true, "secaction": true, "secmarker": true, "secruleremovebyid": true, "secruleremovebytag": true,
		"secruleremovebymsg": true, "secruleupdatetargetbyid": true, "secruleupdatetargetbytag": true,
		"secruleupdatetargetbymsg": true, "secruleupdateactionbyid": true,
	}
	reForbiddenAction = regexp.MustCompile(`(?i)(?:\bexec\s*:|@inspectfile\b|@\w+fromfile\b|\bsetenv\s*:)`)
)

// ValidateCustomRules checks custom rules before they are installed.
func ValidateCustomRules(text string) error {
	if len(text) > 200_000 {
		return errors.New("custom rules are longer than 200 KB")
	}
	var logical []string
	cur := ""
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if strings.HasSuffix(l, "\\") {
			cur += strings.TrimSuffix(l, "\\") + " "
			continue
		}
		logical = append(logical, cur+l)
		cur = ""
	}
	if cur != "" {
		logical = append(logical, cur)
	}
	for i, l := range logical {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		word := strings.ToLower(strings.Fields(t)[0])
		if !allowedDirectives[word] {
			return fmt.Errorf("rule %d: only SecRule, SecAction, SecMarker and SecRuleRemove…/SecRuleUpdate… directives are allowed (found %q)", i+1, strings.Fields(t)[0])
		}
		if m := reForbiddenAction.FindString(t); m != "" {
			return fmt.Errorf("rule %d: %q is not allowed in custom rules", i+1, m)
		}
		if id := regexp.MustCompile(`\bid\s*:\s*'?(\d+)`).FindStringSubmatch(t); id != nil {
			if n := atoi(id[1]); n >= 7700000 && n <= 7709999 {
				return fmt.Errorf("rule %d: ids 7700000-7709999 are reserved for XMart Guard", i+1)
			}
		}
	}
	return nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			break
		}
	}
	return n
}

// ---- cPanel ModSecurity vendors

// WHMAPI is the whmapi1 binary (a variable for tests).
var WHMAPI = "/usr/local/cpanel/bin/whmapi1"

// VendorInfo is a vendor as WHM lists it.
type VendorInfo struct {
	ID          string `json:"vendor_id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Updates     bool   `json:"update"`
	InstalledOn string `json:"installed_from"`
}

func whmapi(ctx context.Context, fn string, args ...string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, WHMAPI, append([]string{"--output=json", fn}, args...)...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("whmapi1 %s: %v", fn, err)
	}
	var r struct {
		Metadata struct {
			Result int    `json:"result"`
			Reason string `json:"reason"`
		} `json:"metadata"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("whmapi1 %s: unexpected output", fn)
	}
	if r.Metadata.Result != 1 {
		return nil, fmt.Errorf("whmapi1 %s: %s", fn, r.Metadata.Reason)
	}
	return r.Data, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	}
	return false
}

// CPanelVendors lists the ModSecurity vendors installed in WHM.
func CPanelVendors(ctx context.Context) ([]VendorInfo, error) {
	d, err := whmapi(ctx, "modsec_get_vendors")
	if err != nil {
		return nil, err
	}
	list, _ := d["vendors"].([]any)
	out := []VendorInfo{}
	for _, it := range list {
		v, _ := it.(map[string]any)
		if v == nil {
			continue
		}
		s := func(k string) string { x, _ := v[k].(string); return x }
		out = append(out, VendorInfo{ID: s("vendor_id"), Name: s("name"), Enabled: truthy(v["enabled"]), Updates: truthy(v["update"]), InstalledOn: s("installed_from")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// vendorURL picks the LiteSpeed variant of a vendor where one exists.
func vendorURL(url string, liteSpeed bool) string {
	if liteSpeed && strings.Contains(url, "meta_comodo_apache.yaml") {
		return strings.Replace(url, "meta_comodo_apache.yaml", "meta_comodo_litespeed.yaml", 1)
	}
	return url
}

// ApplyVendors adds and enables the portal's vendors in WHM (with rule
// updates on) and disables the ones the portal turned off. managed maps
// vendor URLs the agent added to their WHM vendor ids and is updated.
func ApplyVendors(ctx context.Context, t Target, vendors []Vendor, managed map[string]string) []RuleSetState {
	var states []RuleSetState
	if len(vendors) == 0 && len(managed) == 0 {
		return nil
	}
	if t.Name != "cpanel" || !exists(WHMAPI) {
		for _, v := range vendors {
			if v.Enabled {
				states = append(states, RuleSetState{ID: "vendor:" + v.ID, Name: v.Name, State: "unsupported",
					Detail: "ModSecurity vendors are a cPanel/WHM feature; this server has no WHM"})
			}
		}
		return states
	}
	installed, err := CPanelVendors(ctx)
	if err != nil {
		for _, v := range vendors {
			states = append(states, RuleSetState{ID: "vendor:" + v.ID, Name: v.Name, State: "error", Detail: err.Error()})
		}
		return states
	}
	byURL := map[string]VendorInfo{}
	byID := map[string]VendorInfo{}
	for _, iv := range installed {
		byURL[iv.InstalledOn] = iv
		byID[iv.ID] = iv
	}
	want := map[string]bool{}
	for _, v := range vendors {
		url := vendorURL(v.URL, t.LiteSpeed)
		st := RuleSetState{ID: "vendor:" + v.ID, Name: v.Name}
		if !v.Enabled {
			st.State = "off"
			if id, ok := managed[url]; ok {
				if iv, ok := byID[id]; ok && iv.Enabled {
					if _, err := whmapi(ctx, "modsec_disable_vendor", "vendor_id="+id); err != nil {
						st.State, st.Detail = "error", err.Error()
					}
				}
			}
			states = append(states, st)
			continue
		}
		want[url] = true
		iv, ok := byURL[url]
		if !ok {
			d, err := whmapi(ctx, "modsec_add_vendor", "url="+url)
			if err != nil {
				st.State, st.Detail = "error", err.Error()
				states = append(states, st)
				continue
			}
			id, _ := d["vendor_id"].(string)
			if id == "" {
				if l, err := CPanelVendors(ctx); err == nil {
					for _, x := range l {
						if x.InstalledOn == url {
							id = x.ID
						}
					}
				}
			}
			if id == "" {
				st.State, st.Detail = "error", "WHM added the vendor but did not report its id"
				states = append(states, st)
				continue
			}
			iv = VendorInfo{ID: id}
		}
		managed[url] = iv.ID
		var errs []string
		if !iv.Enabled {
			if _, err := whmapi(ctx, "modsec_enable_vendor", "vendor_id="+iv.ID); err != nil {
				errs = append(errs, err.Error())
			}
			if _, err := whmapi(ctx, "modsec_enable_vendor_configs", "vendor_id="+iv.ID); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if !iv.Updates {
			if _, err := whmapi(ctx, "modsec_enable_vendor_updates", "vendor_id="+iv.ID); err != nil {
				errs = append(errs, err.Error())
			}
		}
		st.Version = iv.ID
		if len(errs) > 0 {
			st.State, st.Detail = "error", strings.Join(errs, "; ")
		} else {
			st.State, st.Detail = "active", "WHM vendor "+iv.ID+", automatic rule updates on"
		}
		states = append(states, st)
	}
	// Vendors the portal no longer lists at all: disable the ones we added.
	for url, id := range managed {
		if want[url] {
			continue
		}
		listed := false
		for _, v := range vendors {
			if vendorURL(v.URL, t.LiteSpeed) == url {
				listed = true
			}
		}
		if !listed {
			if iv, ok := byID[id]; ok && iv.Enabled {
				_, _ = whmapi(ctx, "modsec_disable_vendor", "vendor_id="+id)
			}
			delete(managed, url)
		}
	}
	return states
}
