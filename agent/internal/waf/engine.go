package waf

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The engine report: which rules and which ways of writing rules do not
// work on this server's ModSecurity engine, and why. LiteSpeed runs its
// own engine; its documentation says it "is not possible to be 100%
// compatible with Apache" and that rules it cannot read are skipped with
// an error-log line that "can simply be ignored". Skipped silently, such a
// rule is a hole nobody sees. The agent reads those lines after each
// configuration load, names each rule (CRS, xPGuard or a vendor's) with
// the reason, and adds what the self-test's probes found the engine does
// differently. A new LiteSpeed version or CRS release is checked again on
// its next load, on every server.

// EngineIssue is one thing that does not work on this engine.
type EngineIssue struct {
	// Rule is the rule id (the chain's first rule), 0 when not known.
	Rule int `json:"rule,omitempty"`
	// Source: "owasp_crs", "xpguard" or "other" (a vendor's rule file).
	Source string `json:"source,omitempty"`
	File   string `json:"file,omitempty"`
	// What the engine logged it could not read (variable, operator, macro).
	What   string `json:"what"`
	Reason string `json:"reason"`
	// Kind: "unsupported" (from the error log) or "probe" (self-test).
	Kind string `json:"kind"`
	// Effect of the skipped rule on this fleet, when known: "none" (it
	// does nothing with xPGuard's settings), "covered" (something else
	// does its job), "gap" (protection is missing), "kept" (a rule CRS
	// would switch off stays on, on purpose). Note says why.
	Effect string `json:"effect,omitempty"`
	Note   string `json:"note,omitempty"`
}

// crsRuleNotes: what a CRS rule LiteSpeed skips costs (CRS 4.30, PL 1,
// xPGuard's crs-setup; business100 and s1.cobuildhost, 2026-10-31).
var crsRuleNotes = map[int]struct{ effect, note string }{
	901340: {"covered", "only for request bodies of a type CRS has no parser for; xPGuard's content type policy refuses other types"},
	901410: {"none", "only used to sample a share of requests; xPGuard has CRS check every request"},
	920400: {"none", "only with tx.max_file_size, which xPGuard does not set"},
	920240: {"none", "paranoia level 2; xPGuard runs level 1"},
	920539: {"kept", "CRS turns 920540 (\\uXXXX escapes) off for JSON because Apache's JSON parser decodes them; LiteSpeed's leaves them in ARGS (920540 matched JSON posts on business100), so 920540 stays on there as the guard against escaped attacks: a JSON post with \\u escapes scores 5"},
	922100: {"gap", "multipart charset tricks are not checked; uploaded files are still scanned (7700101)"},
	922110: {"gap", "multipart part content types are not checked; uploaded files are still scanned (7700101)"},
	922120: {"gap", "multipart Content-Transfer-Encoding is not checked; uploaded files are still scanned (7700101)"},
	922130: {"gap", "multipart header characters are not checked; uploaded files are still scanned (7700101)"},
	922140: {"none", "counter for 922110"},
	922150: {"none", "collects part content types for 922110"},
	922160: {"none", "counter for 922100"},
	920390: {"gap", "the total size of all arguments is not limited"},
	920410: {"gap", "the total size of uploaded files is not limited by the WAF (PHP's own limits still apply)"},
}

// EngineReport is shown in the portal with the WAF status.
type EngineReport struct {
	// Format: a report of an older agent is built again at once.
	Format    int    `json:"format,omitempty"`
	Engine    string `json:"engine"`
	CheckedAt int64  `json:"checked_at"`
	// LoadAt is when the engine loaded the configuration the log lines are
	// from (0: no load in the part of the log read).
	LoadAt  int64         `json:"load_at,omitempty"`
	Issues  []EngineIssue `json:"issues"`
	Summary string        `json:"summary"`
}

const kvEngineReport = "waf_engine_report"

// engineFormat: 2 since 0.24.18 (short rule text, effects).
const engineFormat = 2

// engineLogTail: how much of the end of the error log is read.
const engineLogTail = 8 << 20

var (
	reLSTime      = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)`)
	reLSUnknown   = regexp.MustCompile(`\[ModSecurity\] unknown server variable while parsing: (\S+)`)
	reLSMacro     = regexp.MustCompile(`\[ModSecurity\] failed to parse a modsec variable\. while parsing: (\S+)`)
	reLSRule      = regexp.MustCompile(`\[ModSecurity\] (.+): Rule not supported\.?\s*$`)
	reLSDirective = regexp.MustCompile(`Directive '([^']+)' is not allowed in current context`)
	reLSConfFile  = regexp.MustCompile(`Processing config file: (\S+)`)
	reActionID    = regexp.MustCompile(`(?:^|[",\s])id:'?(\d+)`)
)

// engineHints explain what a variable the engine does not know costs.
var engineHints = map[string]string{
	"ARGS_COMBINED_SIZE":  "the limit on the total size of all arguments (CRS 920390) is not enforced",
	"FILES_COMBINED_SIZE": "the limit on the total size of uploaded files (CRS 920410) is not enforced",
	"REQBODY_ERROR":       "a request body the engine cannot parse is not refused",
	"MATCHED_VARS_NAMES":  "rules that look at the names of what matched before do not run",
	"FILES":               "upload field checks on file names do not run",
	"XML":                 "LiteSpeed does not parse XML bodies (its documentation: XML parsing not yet supported)",
	"TIME_EPOCH":          "rules that use the current time do not run",
}

type logLine struct {
	at   time.Time
	text string
}

// readEngineLog returns the ModSecurity load lines of the newest
// configuration load in the tail of the log: the lines within two minutes
// of the newest one (a load logs them all at once, every worker process
// alike).
func readEngineLog(paths []string) (time.Time, []logLine) {
	var all []logLine
	for _, p := range uniqueFiles(paths) {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && st.Size() > engineLogTail {
			_, _ = f.Seek(-engineLogTail, io.SeekEnd)
		}
		b, _ := io.ReadAll(io.LimitReader(f, engineLogTail))
		f.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "[ModSecurity]") && !strings.Contains(line, "Processing config file") && !strings.Contains(line, "is not allowed in current context") {
				continue
			}
			m := reLSTime.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			at, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
			if err != nil {
				continue
			}
			all = append(all, logLine{at, line})
		}
	}
	if len(all) == 0 {
		return time.Time{}, nil
	}
	newest := all[0].at
	for _, l := range all {
		if l.at.After(newest) {
			newest = l.at
		}
	}
	var out []logLine
	for _, l := range all {
		if !l.at.Before(newest.Add(-2 * time.Minute)) {
			out = append(out, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return newest, out
}

// indexedRule is a SecRule as written in a rule file.
type indexedRule struct {
	head int    // id of the chain's first rule
	text string // after "SecRule ", spaces collapsed
	file string
}

var (
	reSpaces      = regexp.MustCompile(`\s+`)
	reChainAction = regexp.MustCompile(`[",]\s*chain\s*[",]`)
	reVarsOp      = regexp.MustCompile(`^\S+ "(?:[^"\\]|\\.)*"`)
)

// indexRules reads the SecRule lines of the files (continuations joined),
// each with the id of the chain it belongs to.
func indexRules(files []string) []indexedRule {
	var out []indexedRule
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := strings.ReplaceAll(string(b), "\\\n", " ")
		head, inChain := 0, false
		for _, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			if !strings.HasPrefix(l, "SecRule ") && !strings.HasPrefix(l, "SecAction ") {
				continue
			}
			id := 0
			if m := reActionID.FindStringSubmatch(l); m != nil {
				fmt.Sscan(m[1], &id)
			}
			if !inChain || id != 0 {
				head = id
			}
			out = append(out, indexedRule{head: head, text: reSpaces.ReplaceAllString(strings.TrimPrefix(l, "SecRule "), " "), file: p})
			inChain = reChainAction.MatchString(l)
		}
	}
	return out
}

// ruleSource names whose rule a file holds.
func (m *Manager) ruleSource(file string) string {
	switch {
	case strings.Contains(file, string(filepath.Separator)+"crs"+string(filepath.Separator)) || strings.HasSuffix(file, "crs-setup.conf") || strings.Contains(file, "owasp"):
		return "owasp_crs"
	case m.RulesDir != "" && strings.HasPrefix(file, m.RulesDir):
		return "xpguard"
	}
	return "other"
}

// unsupportedIssues turns the load's log lines into issues.
func (m *Manager) unsupportedIssues(lines []logLine, files []string) []EngineIssue {
	var issues []EngineIssue
	seen := map[string]bool{}
	var idx []indexedRule
	indexed := false
	curFile := ""
	lastVar := ""
	for _, l := range lines {
		if mm := reLSConfFile.FindStringSubmatch(l.text); mm != nil {
			curFile = mm[1]
			continue
		}
		if mm := reLSDirective.FindStringSubmatch(l.text); mm != nil {
			key := "directive " + mm[1]
			if !seen[key] {
				seen[key] = true
				issues = append(issues, EngineIssue{What: "directive " + mm[1], Kind: "unsupported", File: filepath.Base(curFile),
					Reason: "the engine refuses this directive where it is written (LiteSpeed allows audit and debug log settings only at server level)"})
			}
			continue
		}
		if mm := reLSUnknown.FindStringSubmatch(l.text); mm != nil {
			lastVar = mm[1]
			continue
		}
		if mm := reLSMacro.FindStringSubmatch(l.text); mm != nil {
			key := "macro " + mm[1]
			if !seen[key] {
				seen[key] = true
				issues = append(issues, EngineIssue{What: mm[1], Kind: "unsupported", File: filepath.Base(curFile),
					Reason: "the engine cannot expand " + mm[1] + ": the rule using it is skipped" + hintFor(mm[1])})
			}
			continue
		}
		mm := reLSRule.FindStringSubmatch(l.text)
		if mm == nil {
			continue
		}
		what := strings.TrimSpace(mm[1])
		if seen[what] {
			lastVar = ""
			continue
		}
		seen[what] = true
		is := EngineIssue{What: what, Kind: "unsupported"}
		if lastVar != "" && strings.HasPrefix(strings.TrimLeft(what, "&!"), strings.TrimLeft(lastVar, "&!")) {
			is.Reason = "the engine does not know the variable " + lastVar + ": the rule never runs" + hintFor(lastVar)
		} else {
			is.Reason = "the engine does not support this rule (an operator, action or variable it cannot read): the rule never runs"
		}
		lastVar = ""
		// Which rule: its own id when the line shows the actions, else
		// found by its text in the rule files.
		if a := reActionID.FindStringSubmatch(what); a != nil {
			fmt.Sscan(a[1], &is.Rule)
		}
		if !indexed {
			fs := files
			if curFile != "" {
				fs = append([]string{curFile}, fs...)
			}
			idx, indexed = indexRules(fs), true
		}
		// Variables and operator only: the engine shortens the actions.
		key := reSpaces.ReplaceAllString(what, " ")
		if mm := reVarsOp.FindString(key); mm != "" {
			key = mm
		}
		for _, r := range idx {
			if strings.HasPrefix(r.text, key) && (is.Rule == 0 || r.head == is.Rule) {
				is.Rule, is.File, is.Source = r.head, filepath.Base(r.file), m.ruleSource(r.file)
				break
			}
		}
		if is.File == "" && curFile != "" {
			is.File, is.Source = filepath.Base(curFile), m.ruleSource(curFile)
		}
		// Shown short: variables and operator (the engine logs the actions too).
		is.What = key
		if n, ok := crsRuleNotes[is.Rule]; ok && is.Source == "owasp_crs" {
			is.Effect, is.Note = n.effect, n.note
		}
		// One issue per rule and text (each chain link logs its own line).
		dup := false
		for _, o := range issues {
			if o.Rule == is.Rule && o.What == is.What {
				dup = true
			}
		}
		if dup {
			continue
		}
		issues = append(issues, is)
	}
	return issues
}

func hintFor(v string) string {
	name := strings.Trim(v, "%{}")
	if i := strings.IndexAny(name, ":."); i > 0 {
		name = name[:i]
	}
	if h := engineHints[strings.ToUpper(name)]; h != "" {
		return " (" + h + ")"
	}
	return ""
}

// probeIssues: what the self-test found this engine does differently.
// Apache passes every way and every score probe (business700); a probe
// refused here is a difference.
func probeIssues(st *SelfTest) []EngineIssue {
	if st == nil {
		return nil
	}
	var out []EngineIssue
	why := map[string]string{
		"remove_xss_tag":      "ctl:ruleRemoveTargetByTag does nothing here: exclusions written that way (in CRS plugins and vendor rules) do not apply; xPGuard's relaxations remove rules by id instead",
		"cond_args_get":       "a phase-1 rule does not see ARGS_GET of a POST request (GET requests are seen); xPGuard reads such values from REQUEST_URI",
		"cond_query_string":   "a phase-1 rule does not see QUERY_STRING of a POST request; xPGuard reads it from REQUEST_URI",
		"cond_args_names":     "ARGS_NAMES (form field names) is not filled: the Joomla form-token relaxation cannot apply",
		"cond_request_uri":    "REQUEST_URI conditions do not match: the WooCommerce API key relaxation cannot apply",
		"cond_tx_count":       "counting a TX variable (&TX:x) does not work: reputation checks in relaxations cannot apply",
		"cond_tx_lt":          "comparing a TX variable does not work",
		"cond_filename_end":   "a REQUEST_FILENAME pattern ending in $ does not match",
		"thr_single":          "setting the anomaly threshold in phase 1 does nothing",
		"thr_chain":           "setting the anomaly threshold from a chained rule does nothing",
		"thr_phase2":          "setting the anomaly threshold in phase 2 does nothing",
		"remove_949110":       "ctl:ruleRemoveById does nothing: no relaxation can work on this engine",
		"detection_only":      "ctl:ruleEngine=DetectionOnly does nothing",
		"allow":               "the allow action does not stop the CRS",
		"remove_range":        "ctl:ruleRemoveById with a range of ids does nothing: xPGuard's exclusions also set family flags whose rules name each id, and a whitelisted domain keeps every xPGuard rule (stricter, not looser)",
		"remove_by_tag":       "ctl:ruleRemoveByTag does nothing: xPGuard's exclusions also set family flags whose rules name each id",
		"family_flag":         "the family flags do not take rules out: xPGuard's relaxations and exclusions do not work on this engine",
		"remove_target_range": "ctl:ruleRemoveTargetById with a range of ids does nothing: no field can be taken out of a rule here; xPGuard's comment exclusion takes SQL injection out of the whole comment post instead, password fields stay checked for PHP injection",
		"remove_target_ids":   "ctl:ruleRemoveTargetById with single ids does nothing: no field can be taken out of a rule here (see remove_target_range)",
	}
	var ways []string
	for k := range st.Ways {
		ways = append(ways, k)
	}
	sort.Strings(ways)
	for _, k := range ways {
		v := st.Ways[k]
		if k == "none" || !strings.HasPrefix(v, "refused") {
			continue
		}
		r := why[k]
		if r == "" {
			r = "this way of relaxing a rule does not work here"
		}
		out = append(out, EngineIssue{Kind: "probe", What: "way " + k, Reason: r + " (self-test: " + v + ")"})
	}
	// Score probes: the lowest threshold each test save passes under.
	for _, b := range scoreProbeBodies {
		var refused []int
		passFrom := 0
		for _, t := range scoreProbeThresholds {
			v := st.Scores[fmt.Sprintf("%s_%d", b, t)]
			if strings.HasPrefix(v, "refused") {
				refused = append(refused, t)
			} else if v == "passes" && passFrom == 0 {
				passFrom = t
			}
		}
		if len(refused) == 0 || refused[len(refused)-1] < 30 {
			continue
		}
		pass := "no threshold tested"
		if passFrom > 0 {
			pass = fmt.Sprintf("from %d", passFrom)
		}
		out = append(out, EngineIssue{Kind: "probe", What: "score " + b,
			Reason: fmt.Sprintf("a test save Apache scores under 20 was refused here at threshold %d and passes %s: this engine scores a request again after it passed the first check, so a raised threshold is not reliable; xPGuard's relaxations take whole rule families out instead", refused[len(refused)-1], pass)})
	}
	// Upload forms: what Apache shows rules and this engine does not.
	mpWhy := map[string]string{
		"args":        "form fields of an upload form (ARGS) are not shown to rules: injections in upload forms are not checked",
		"files":       "uploaded file names (FILES) are not shown to rules: CRS checks of upload names do not run",
		"files_names": "upload field names (FILES_NAMES) are not shown to rules",
	}
	for _, k := range []string{"args", "files", "files_names"} {
		if v, ok := st.Multipart[k]; ok && v != "seen" {
			out = append(out, EngineIssue{Kind: "probe", What: "upload " + k, Reason: mpWhy[k] + " (self-test: " + v + ")"})
		}
	}
	var lifts []string
	for k := range st.Lifts {
		lifts = append(lifts, k)
	}
	sort.Strings(lifts)
	for _, k := range lifts {
		if v := st.Lifts[k]; strings.HasPrefix(v, "refused") {
			out = append(out, EngineIssue{Kind: "probe", What: "relaxation " + k, Reason: "the save this relaxation is for is still refused on this server (self-test: " + v + ")"})
		}
	}
	return out
}

// checkEngine builds the report after an apply (and its self-test). A
// load not in the log tail keeps the previous load's findings.
func (m *Manager) checkEngine(t Target, crsVersion string, st *SelfTest) *EngineReport {
	r := &EngineReport{Format: engineFormat, Engine: t.WebServer, CheckedAt: time.Now().Unix()}
	if t.LiteSpeed {
		files, _ := filepath.Glob(filepath.Join(m.RulesDir, "*.conf"))
		if crsVersion != "" {
			crs, _ := filepath.Glob(filepath.Join(m.crsDir(crsVersion), "rules", "*.conf"))
			files = append(files, crs...)
		}
		prev := m.EngineReport()
		var at time.Time
		var lines []logLine
		// The log at most every 10 minutes (applies come often; a load's
		// lines stay in the tail read).
		if prev != nil && prev.Format != engineFormat {
			prev = nil
		}
		if prev == nil || time.Since(time.Unix(prev.CheckedAt, 0)) >= 10*time.Minute || prev.Engine != t.WebServer {
			at, lines = readEngineLog(t.ErrorLogs)
		} else {
			r.CheckedAt = prev.CheckedAt
		}
		if at.IsZero() && prev != nil {
			for _, is := range prev.Issues {
				if is.Kind == "unsupported" {
					r.Issues = append(r.Issues, is)
				}
			}
			r.LoadAt = prev.LoadAt
		} else if !at.IsZero() {
			r.LoadAt = at.Unix()
			r.Issues = m.unsupportedIssues(lines, files)
		}
	}
	r.Issues = append(r.Issues, probeIssues(st)...)
	if r.Issues == nil {
		r.Issues = []EngineIssue{}
	}
	n, p, gaps, unknown := 0, 0, 0, 0
	for _, is := range r.Issues {
		switch {
		case is.Kind != "unsupported":
			p++
		case is.Effect == "gap":
			n++
			gaps++
		case is.Effect == "":
			n++
			unknown++
		default:
			n++
		}
	}
	switch {
	case !t.LiteSpeed:
		r.Summary = "Apache's ModSecurity reads every rule (its configuration test refuses one it cannot read)."
	case n == 0:
		r.Summary = "The error log shows no rule the engine skipped."
	default:
		r.Summary = fmt.Sprintf("%d rule(s) the engine skips", n)
		var parts []string
		if gaps > 0 {
			parts = append(parts, fmt.Sprintf("%d leave a protection gap", gaps))
		}
		if unknown > 0 {
			parts = append(parts, fmt.Sprintf("%d not reviewed yet", unknown))
		}
		if rest := n - gaps - unknown; rest > 0 {
			parts = append(parts, fmt.Sprintf("%d do nothing with xPGuard's settings or are covered", rest))
		}
		r.Summary += ": " + strings.Join(parts, ", ") + "."
	}
	if p == 0 {
		r.Summary += " The self-test found no difference in how rules are relaxed."
	} else {
		r.Summary += fmt.Sprintf(" The self-test found %d difference(s) from Apache.", p)
	}
	if b, err := json.Marshal(r); err == nil && m.DB != nil {
		_ = store.SetKV(m.DB, kvEngineReport, string(b))
	}
	return r
}

// EngineReport is the last report (kept across agent restarts).
func (m *Manager) EngineReport() *EngineReport {
	if m.DB == nil {
		return nil
	}
	s := store.GetKV(m.DB, kvEngineReport)
	if s == "" {
		return nil
	}
	var r EngineReport
	if json.Unmarshal([]byte(s), &r) != nil {
		return nil
	}
	return &r
}
