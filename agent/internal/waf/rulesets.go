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
// (WAF Rule Sets): xPGuard's own rules, the OWASP Core Rule Set, cPanel
// ModSecurity vendors (Malware.Expert, Comodo, …) and custom rules.
type RuleSets struct {
	Version  int64 `json:"version"`
	OwnRules *struct {
		Enabled bool `json:"enabled"`
		// ReplacedBy names the rule set used instead of xPGuard's own
		// blocking rules on this server (the portal sets it where
		// Malware.Expert is linked, so the same attacks are not handled by
		// two rule sets).
		ReplacedBy string `json:"replaced_by,omitempty"`
	} `json:"xmartguard,omitempty"`
	CRS     CRSConfig `json:"crs"`
	Vendors []Vendor  `json:"vendors"`
	// Remote rule feeds loaded with SecRemoteRules (e.g. Malware.Expert
	// with your own license key), for servers without WHM vendors.
	Remote []RemoteRules `json:"remote"`
	Custom struct {
		Enabled bool   `json:"enabled"`
		Rules   string `json:"rules"`
	} `json:"custom"`
}

// CRSConfig is the OWASP Core Rule Set part of the rule sets.
type CRSConfig struct {
	Enabled           bool   `json:"enabled"`
	Version           string `json:"version"` // installed release, e.g. 4.29.0
	Paranoia          int    `json:"paranoia"`
	InboundThreshold  int    `json:"inbound_threshold"`
	OutboundThreshold int    `json:"outbound_threshold"`
	// SoftBlock: a GET request with a weak signal (score below twice the
	// threshold) from a visitor with a clean reputation gets the portal's
	// CAPTCHA page instead of a 403 ("" or "captcha", the default); "off"
	// blocks it like any other.
	SoftBlock string `json:"soft_block,omitempty"`
	// ReplacedBy names the rule set used instead on this server
	// (the portal turns CRS off where Malware.Expert is linked).
	ReplacedBy string `json:"replaced_by,omitempty"`
}

// Vendor is a cPanel ModSecurity vendor, added from its configuration
// (YAML) URL like WHM » ModSecurity Vendors » Add Vendor does.
type Vendor struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// RemoteRules is a rule feed ModSecurity downloads itself.
type RemoteRules struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// RBL is an optional DNS blocklist from the same vendor (for example
	// rbl.malware.expert): POST requests from listed addresses are dropped.
	RBL string `json:"rbl,omitempty"`
}

// vendorHasRBL reports a Malware.Expert feed with its "rbl" extra module,
// whose rule 400010 already drops POSTs from rbl.malware.expert.
func vendorHasRBL(url, rbl string) bool {
	return rbl == "rbl.malware.expert" && strings.Contains(url, "malware.expert/") && urlExtra(url, "rbl")
}

// VendorLoginCaptcha names the rule feed that brings its own login-page
// CAPTCHA to this server ("" = none): Malware.Expert's "recaptcha" extra
// sends bots on WordPress/Joomla logins to recaptcha.cloud, and xPGuard's
// login-page CAPTCHA would stop every visitor before it.
func (m *Manager) VendorLoginCaptcha() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.ruleSets.Remote {
		if r.Enabled && strings.Contains(r.URL, "malware.expert/") && urlExtra(r.URL, "recaptcha") {
			return r.Name
		}
	}
	return ""
}

// urlExtra reports a module in a Malware.Expert feed's extra= list.
func urlExtra(url, module string) bool {
	i := strings.Index(url, "extra=")
	if i < 0 {
		return false
	}
	extra := url[i+6:]
	if j := strings.IndexByte(extra, '&'); j >= 0 {
		extra = extra[:j]
	}
	for _, e := range strings.Split(extra, ",") {
		if e == module {
			return true
		}
	}
	return false
}

// IDRemoteRBL is the first rule id for remote feed blocklists.
const IDRemoteRBL = 7700801

var (
	reRemoteRBL = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	reRemoteKey = regexp.MustCompile(`^[A-Za-z0-9_.:-]{4,200}$`)
	reRemoteURL = regexp.MustCompile(`^https://[^\s"'<>\\]+$`)
)

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
		if rs.CRS.ReplacedBy != "" {
			crs.Detail = "replaced by " + rs.CRS.ReplacedBy + " on this server"
		}
	case systemCRS(t) != "":
		crs.State, crs.Detail = "skipped", "already loaded by "+systemCRS(t)+" on this server"
	case !m.CRSInstalled(rs.CRS.Version):
		crs.State, crs.Detail = "error", "the rule files have not been downloaded from the portal yet"
	default:
		pl := clampInt(rs.CRS.Paranoia, 1, 4, 1)
		in := m.crsThreshold(rs.CRS)
		out := clampInt(rs.CRS.OutboundThreshold, 2, 1000, 4)
		dir := m.crsDir(rs.CRS.Version)
		setup := filepath.Join(m.RulesDir, "crs-setup.conf")
		plVar := "blocking_paranoia_level" // CRS 4
		if strings.HasPrefix(rs.CRS.Version, "3.") {
			plVar = "paranoia_level"
		}
		setupText := fmt.Sprintf("# OWASP CRS %s set up by xPGuard (WAF Rule Sets in the portal).\nInclude %s\n"+
			"SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.%s=%d\"\n"+
			"SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
			rs.CRS.Version, filepath.Join(dir, "crs-setup.conf.example"), plVar, pl, in, out)
		crs.Detail = fmt.Sprintf("paranoia level %d, anomaly threshold %d", pl, in)
		post := ""
		if sb, ok := m.softBlock(rs.CRS, in); ok {
			setupText += sb.setup
			post = sb.post
			for k, v := range sb.files {
				files[k] = v
			}
			crs.Detail += "; weak signals from clean visitors get the CAPTCHA page"
		}
		if lv := m.level(); lv != "strict" {
			setupText += editorSetup()
			crs.Detail += "; WAF level " + lv + ": logged-in WordPress users are not blocked while editing"
		}
		files[setup] = setupText
		fmt.Fprintf(&inc, "\n# OWASP Core Rule Set %s\nInclude %s\nInclude %s\n", rs.CRS.Version, setup, filepath.Join(dir, "rules", "*.conf"))
		if post != "" {
			p := filepath.Join(m.RulesDir, "crs-after.conf")
			files[p] = post
			fmt.Fprintf(&inc, "Include %s\n", p)
		}
		crs.State = "active"
	}
	states = append(states, crs)

	first := true
	rblID := IDRemoteRBL
	for _, r := range rs.Remote {
		st := RuleSetState{ID: "remote:" + r.ID, Name: r.Name}
		switch {
		case !r.Enabled:
			st.State = "off"
		case !reRemoteKey.MatchString(r.Key) || !reRemoteURL.MatchString(r.URL):
			st.State, st.Detail = "error", "invalid license key or URL"
		default:
			if first {
				inc.WriteString("\n# Remote rule feeds (downloaded by ModSecurity at start)\nSecRemoteRulesFailAction Warn\n")
				first = false
			}
			fmt.Fprintf(&inc, "SecRemoteRules \"%s\" \"%s\"\n", r.Key, r.URL)
			st.State, st.Detail = "active", "loaded by ModSecurity from "+r.URL
			if strings.Contains(r.URL, "malware.expert/") && urlExtra(r.URL, "recaptcha") {
				st.Detail += "; login CAPTCHA by Malware.Expert (recaptcha.cloud) replaces xPGuard's"
			}
			rbl := strings.ToLower(strings.TrimSpace(r.RBL))
			if rbl != "" && vendorHasRBL(r.URL, rbl) {
				// The feed's own "rbl" module already drops these POSTs.
				st.Detail += "; POST blocklist " + rbl + " by the feed's own rbl rule"
				rbl = ""
			}
			if rbl != "" && reRemoteRBL.MatchString(rbl) && rblID < IDRemoteRBL+10 {
				fmt.Fprintf(&inc, "SecRule REQUEST_METHOD \"@streq POST\" \"id:%d,phase:2,drop,log,msg:'POST from an address listed on %s',tag:'xpguard/rbl',chain\"\n  SecRule REMOTE_ADDR \"@rbl %s\"\n", rblID, rbl, rbl)
				rblID++
				st.Detail += "; POST blocklist " + rbl
			}
		}
		states = append(states, st)
	}

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
		files[p] = "# Custom rules from the xPGuard portal (WAF Rule Sets).\n" + rs.Custom.Rules + "\n"
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
				return fmt.Errorf("rule %d: ids 7700000-7709999 are reserved for xPGuard", i+1)
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
