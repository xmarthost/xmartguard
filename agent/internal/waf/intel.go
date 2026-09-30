package waf

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Fleet intelligence from the portal: web shell file names the scanners of
// all servers found (and the portal accepted), and virtual patches for
// plugin vulnerabilities published after this agent was built. Patches
// come as data, never as rule text: the agent writes the rules itself and
// drops anything that does not validate.

// IDFleetNames blocks the fleet-learned web shell names.
const IDFleetNames = 7700605

// Portal virtual patch ids.
const (
	IDPortalPatchMin = 7703000
	IDPortalPatchMax = 7703999
)

// Intel is the portal's fleet intelligence for the WAF.
type Intel struct {
	ETag    string        `json:"etag"`
	Names   []string      `json:"names"`
	Patches []PortalPatch `json:"patches"`
}

// PortalPatch describes one virtual patch; every condition set must match.
type PortalPatch struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	CVE   string `json:"cve,omitempty"`
	// Path: regular expression for the requested file (lowercase).
	Path string `json:"path,omitempty"`
	// URI: regular expression for the decoded address with its query
	// (lowercase), e.g. REST routes given as ?rest_route=.
	URI    string       `json:"uri,omitempty"`
	Method string       `json:"method,omitempty"` // GET | POST
	Args   []PatchMatch `json:"args,omitempty"`
	Header *PatchMatch  `json:"header,omitempty"`
	// LoggedOut applies the patch only to visitors not logged in to WordPress.
	LoggedOut bool `json:"logged_out,omitempty"`
}

// PatchMatch is a request argument or header condition.
type PatchMatch struct {
	Name  string `json:"name"`
	Op    string `json:"op"` // present | equals | contains | rx
	Value string `json:"value,omitempty"`
}

var (
	reFleetName  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,78}\.(?:php[0-9]?|phtml|phar|pht)$`)
	rePatchName  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,60}$`)
	rePatchTitle = regexp.MustCompile(`^[A-Za-z0-9 .,:;()/+#&-]{3,160}$`)
	rePatchCVE   = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	// Rule text may not break out of its quotes.
	reUnsafe = regexp.MustCompile(`["'\x00-\x1f` + "`" + `]`)
)

// GenericNames are file names that legitimate software uses everywhere;
// they are never blocked by name.
var GenericNames = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`index admin config configuration settings setting functions function header footer sidebar
		style styles init load loader ajax api upload uploader uploads login logout signin signup user users main home db database
		connect connection cache class common core global globals helper helpers install installer update updater upgrade cron search
		page pages post posts test tests info about contact mail mailer form forms cart checkout product products category image images
		media file files download downloads template templates theme themes plugin plugins widget widgets options option default base
		app application bootstrap autoload router route routes controller model view server client session auth register account
		profile dashboard error errors 404 license readme uninstall activate deactivate xmlrpc wp-config wp-load wp-settings wp-login
		wp-cron wp-blog-header wp-mail wp-signup wp-activate wp-trackback wp-comments-post wp-links-opml functions.inc config.inc
		constants define defines version lang language languages locale redirect proxy feed rss sitemap robots export import backup
		restore payment ipn notify callback webhook webhooks order orders invoice report reports stats status health ping sync
		process handler handlers action actions include includes lib library vendor module modules block blocks data item items
		color colors sapp-wp-signon`) {
		GenericNames[n+".php"] = true
	}
}

// FleetNameOK reports whether a file name may be blocked fleet-wide.
func FleetNameOK(name string) bool {
	name = strings.ToLower(name)
	if !reFleetName.MatchString(name) || GenericNames[name] {
		return false
	}
	stem := name[:strings.LastIndexByte(name, '.')]
	return len(stem) >= 3 && !GenericNames[stem+".php"]
}

// validRegex checks a pattern for a SecRule: it compiles and cannot break
// out of the rule's quotes.
func validRegex(p string) bool {
	if p == "" || len(p) > 300 || reUnsafe.MatchString(p) || strings.HasSuffix(p, `\`) {
		return false
	}
	_, err := regexp.Compile(p)
	return err == nil
}

func (m PatchMatch) valid(header bool) bool {
	if !rePatchName.MatchString(m.Name) {
		return false
	}
	switch m.Op {
	case "present":
		return true
	case "equals", "contains":
		return m.Value != "" && len(m.Value) <= 200 && !reUnsafe.MatchString(m.Value) && !strings.ContainsAny(m.Value, `\ `)
	case "rx":
		return validRegex(m.Value)
	}
	return false
}

// Valid reports whether the patch can be turned into rules safely.
func (p PortalPatch) Valid() error {
	switch {
	case p.ID < IDPortalPatchMin || p.ID > IDPortalPatchMax:
		return fmt.Errorf("patch id %d outside %d-%d", p.ID, IDPortalPatchMin, IDPortalPatchMax)
	case !rePatchTitle.MatchString(p.Title):
		return fmt.Errorf("patch %d: invalid title", p.ID)
	case p.CVE != "" && !rePatchCVE.MatchString(p.CVE):
		return fmt.Errorf("patch %d: invalid CVE", p.ID)
	case p.Path != "" && !validRegex(p.Path), p.URI != "" && !validRegex(p.URI):
		return fmt.Errorf("patch %d: invalid pattern", p.ID)
	case p.Method != "" && p.Method != "GET" && p.Method != "POST":
		return fmt.Errorf("patch %d: invalid method", p.ID)
	case p.Header != nil && !p.Header.valid(true):
		return fmt.Errorf("patch %d: invalid header condition", p.ID)
	case len(p.Args) > 5:
		return fmt.Errorf("patch %d: too many conditions", p.ID)
	}
	for _, a := range p.Args {
		if !a.valid(false) {
			return fmt.Errorf("patch %d: invalid argument condition", p.ID)
		}
	}
	// A patch must target something specific.
	if p.Path == "" && p.URI == "" && p.Header == nil && len(p.Args) == 0 {
		return fmt.Errorf("patch %d: no condition", p.ID)
	}
	return nil
}

// Clean keeps the valid names and patches (unique, sorted).
func (in *Intel) Clean() *Intel {
	if in == nil {
		return nil
	}
	out := &Intel{ETag: in.ETag}
	seen := map[string]bool{}
	for _, n := range in.Names {
		n = strings.ToLower(strings.TrimSpace(n))
		if FleetNameOK(n) && !seen[n] && len(out.Names) < 3000 {
			seen[n] = true
			out.Names = append(out.Names, n)
		}
	}
	sort.Strings(out.Names)
	ids := map[int]bool{}
	for _, p := range in.Patches {
		if p.Valid() == nil && !ids[p.ID] && len(out.Patches) < 500 {
			ids[p.ID] = true
			out.Patches = append(out.Patches, p)
		}
	}
	sort.Slice(out.Patches, func(i, j int) bool { return out.Patches[i].ID < out.Patches[j].ID })
	return out
}

// renderPatch writes one portal patch as a rule chain.
func renderPatch(w func(string, ...any), p PortalPatch) {
	msg := "xPGuard - Virtual patch: " + p.Title
	if p.CVE != "" {
		msg += " (" + p.CVE + ")"
	}
	var conds []string
	if p.Method != "" {
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_METHOD "@streq %s" "t:none`, p.Method))
	}
	if p.Path != "" {
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx %s" "t:none,t:urlDecodeUni,t:lowercase`, p.Path))
	}
	if p.URI != "" {
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_URI "@rx %s" "t:none,t:urlDecodeUni,t:lowercase`, p.URI))
	}
	match := func(target string, m PatchMatch) string {
		switch m.Op {
		case "present":
			return fmt.Sprintf(`SecRule &%s "@gt 0" "t:none`, target)
		case "equals":
			return fmt.Sprintf(`SecRule %s "@streq %s" "t:none`, target, m.Value)
		case "contains":
			return fmt.Sprintf(`SecRule %s "@contains %s" "t:none,t:urlDecodeUni`, target, m.Value)
		}
		return fmt.Sprintf(`SecRule %s "@rx %s" "t:none,t:urlDecodeUni`, target, m.Value)
	}
	for _, a := range p.Args {
		conds = append(conds, match("ARGS:"+a.Name, a))
	}
	if p.Header != nil {
		conds = append(conds, match("REQUEST_HEADERS:"+p.Header.Name, *p.Header))
	}
	if p.LoggedOut {
		conds = append(conds, `SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@eq 0" "t:none`)
	}
	for i, c := range conds {
		switch {
		case i == 0 && len(conds) == 1:
			w(`%s,id:%d,phase:2,deny,status:403,log,msg:'%s',tag:'xpguard/vpatch'"`, c, p.ID, msg)
		case i == 0:
			w(`%s,id:%d,phase:2,deny,status:403,log,msg:'%s',tag:'xpguard/vpatch',chain"`, c, p.ID, msg)
		case i < len(conds)-1:
			w(`  %s,chain"`, c)
		default:
			w(`  %s"`, c)
		}
	}
}
