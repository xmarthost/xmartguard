package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEngineReportFromLiteSpeedLog: the rules LiteSpeed's engine skips at a
// configuration load ("Rule not supported", lines its documentation says
// "can simply be ignored") are named with their rule id, owner and reason;
// an older load's lines are not.
func TestEngineReportFromLiteSpeedLog(t *testing.T) {
	dir := t.TempDir()
	crs := filepath.Join(dir, "crs", "4.30.0", "rules")
	os.MkdirAll(crs, 0o755)
	// Inert rule files in the shape of CRS and of xPGuard's own.
	os.WriteFile(filepath.Join(crs, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"), []byte(`
SecRule &TX:TOTAL_ARG_LENGTH "@eq 1" \
    "id:920390,\
    phase:2,\
    block,\
    t:none,\
    chain"
    SecRule ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule FILES_COMBINED_SIZE "@gt %{tx.combined_file_sizes}" "id:920410,phase:2,block,t:none"
SecRule &MULTIPART_PART_HEADERS:_charset_ "!@eq 0" \
    "id:922100,\
    phase:2,\
    block,\
    chain"
    SecRule REQBODY_PROCESSOR "@streq MULTIPART" "t:none"
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
    "id:901340,\
    phase:1,\
    pass,\
    nolog,\
    chain"
    SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
        "ctl:requestBodyProcessor=URLENCODED"
`), 0o644)
	os.WriteFile(filepath.Join(dir, "xpguard-rules.conf"), []byte(`SecRule REQUEST_FILENAME "@rx /x$" "id:7700999,phase:1,pass,nolog,chain"
  SecRule MATCHED_VARS_NAMES "@rx ^ARGS:x" "t:none"
`), 0o644)
	now := time.Now()
	ts := func(d time.Duration) string { return now.Add(d).Format("2006-01-02 15:04:05.000000") }
	log := filepath.Join(dir, "error.log")
	os.WriteFile(log, []byte(strings.Join([]string{
		// An older load: a rule fixed since.
		ts(-3*time.Hour) + ` ERROR   [ModSecurity] unknown server variable while parsing: FILES:import_file`,
		ts(-3*time.Hour) + ` ERROR   [ModSecurity] FILES:import_file "@rx <": Rule not supported.`,
		ts(-10*time.Second) + ` [INFO] Processing config file: ` + filepath.Join(dir, "xpguard-rules.conf"),
		ts(-10*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: MATCHED_VARS_NAMES`,
		ts(-10*time.Second) + ` ERROR   [ModSecurity] MATCHED_VARS_NAMES "@rx ^ARGS:x" "t:none": Rule not supported.`,
		ts(-9*time.Second) + ` [INFO] Processing config file: ` + filepath.Join(crs, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"),
		ts(-9*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: ARGS_COMBINED_SIZE`,
		ts(-9*time.Second) + ` ERROR   [ModSecurity] ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}" "t:none": Rule not supported.`,
		ts(-9*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: FILES_COMBINED_SIZE`,
		ts(-9*time.Second) + ` ERROR   [ModSecurity] FILES_COMBINED_SIZE "@gt %{tx.combined_file_sizes}" "t:none": Rule not supported.`,
		ts(-8*time.Second) + ` ERROR   [ModSecurity] failed to parse a modsec variable. while parsing: %{TIME_EPOCH}`,
		// Every worker logs the load: counted once.
		ts(-8*time.Second) + ` ERROR   [ModSecurity] ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}" "t:none": Rule not supported.`,
		ts(-7*time.Second) + ` Directive 'SecAuditLog' is not allowed in current context.`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: MULTIPART_PART_HEADERS:_charset_`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] &MULTIPART_PART_HEADERS:_charset_ "!@eq 0"     "id:922100,    phase:2,    block,    chain": Rule not supported.`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: REQBODY_PROCESSOR`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)"     "id:901340,    phase:1,    pass,    nolog,    chain": Rule not supported.`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] unknown server variable while parsing: REQBODY_PROCESSOR`,
		ts(-7*time.Second) + ` ERROR   [ModSecurity] REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)"         "ctl:requestBodyProcessor=URLENCODED": Rule not supported.`,
		ts(-5*time.Second) + ` [NOTICE] [1234] [T0] [HTTP:x] not ModSecurity`,
	}, "\n")), 0o644)
	m := &Manager{RulesDir: dir}
	r := m.checkEngine(Target{WebServer: "LiteSpeed (cPanel)", LiteSpeed: true, ErrorLogs: []string{log}}, "4.30.0", nil)
	by := map[string]EngineIssue{}
	for _, is := range r.Issues {
		by[is.What] = is
	}
	if _, old := by[`FILES:import_file "@rx <"`]; old {
		t.Fatal("an older load's line is reported")
	}
	want := []struct {
		what   string
		rule   int
		source string
		reason string
	}{
		{`ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}"`, 920390, "owasp_crs", "920390) is not enforced"},
		{`FILES_COMBINED_SIZE "@gt %{tx.combined_file_sizes}"`, 920410, "owasp_crs", "920410) is not enforced"},
		{`MATCHED_VARS_NAMES "@rx ^ARGS:x"`, 7700999, "xpguard", "does not know the variable MATCHED_VARS_NAMES"},
		// As business100 logged them (0.24.17): a counted variable, and a
		// chain whose first rule and link both log a line.
		{`&MULTIPART_PART_HEADERS:_charset_ "!@eq 0"`, 922100, "owasp_crs", "does not know the variable MULTIPART_PART_HEADERS:_charset_"},
		{`REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)"`, 901340, "owasp_crs", "does not know the variable REQBODY_PROCESSOR"},
		{`%{TIME_EPOCH}`, 0, "", "cannot expand %{TIME_EPOCH}"},
		{`directive SecAuditLog`, 0, "", "only at server level"},
	}
	for _, w := range want {
		is, ok := by[w.what]
		if !ok {
			t.Errorf("missing %q in %+v", w.what, r.Issues)
			continue
		}
		if is.Rule != w.rule || is.Source != w.source || !strings.Contains(is.Reason, w.reason) || is.Kind != "unsupported" {
			t.Errorf("%q: got %+v", w.what, is)
		}
	}
	if by[`&MULTIPART_PART_HEADERS:_charset_ "!@eq 0"`].Effect != "gap" || by[`REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)"`].Effect != "covered" || by[`MATCHED_VARS_NAMES "@rx ^ARGS:x"`].Effect != "" {
		t.Errorf("effects: %+v", r.Issues)
	}
	if len(r.Issues) != len(want) || r.LoadAt == 0 || !strings.HasPrefix(r.Summary, "7 rule(s) the engine skips: 3 leave a protection gap, 3 not reviewed yet, 1 do nothing with xPGuard's settings or are covered.") {
		t.Fatalf("report: %+v", r)
	}
	// Apache: no log reading; the configuration test refuses what it
	// cannot read.
	if a := (&Manager{RulesDir: dir}).checkEngine(Target{WebServer: "Apache", ErrorLogs: []string{log}}, "4.30.0", nil); len(a.Issues) != 0 {
		t.Fatalf("Apache report: %+v", a.Issues)
	}
}

// TestEngineReportProbes: the self-test's findings on LiteSpeed
// (business600, 2026-10-31) become reasons; Apache's (business700, every
// probe passes) none.
func TestEngineReportProbes(t *testing.T) {
	ls := &SelfTest{
		Ways: map[string]string{"none": "HTTP 403", "remove_949110": "passes", "remove_xss_tag": "refused (HTTP 403)",
			"cond_args_get": "refused (HTTP 403)", "cond_query_string": "refused (HTTP 403)", "cond_args_names": "passes"},
		Scores: map[string]string{"wc_20": "refused (HTTP 403)", "wc_30": "refused (HTTP 403)", "wc_45": "refused (HTTP 403)", "wc_60": "passes", "wc_100": "passes",
			"joomla_20": "refused (HTTP 403)", "joomla_30": "refused (HTTP 403)", "joomla_45": "passes", "joomla_60": "passes", "joomla_100": "passes",
			"xss_20": "refused (HTTP 403)", "xss_30": "passes", "xss_45": "passes", "xss_60": "passes", "xss_100": "passes"},
		Lifts: map[string]string{"joomla_admin_save": "passes", "woocommerce_api_write": "refused (HTTP 403)"},
	}
	got := probeIssues(ls)
	text := ""
	for _, is := range got {
		if is.Kind != "probe" {
			t.Fatalf("kind: %+v", is)
		}
		text += is.What + ": " + is.Reason + "\n"
	}
	for _, w := range []string{
		"way remove_xss_tag: ctl:ruleRemoveTargetByTag does nothing",
		"way cond_args_get: a phase-1 rule does not see ARGS_GET of a POST request (GET requests are seen)",
		"way cond_query_string:",
		"score wc: a test save Apache scores under 20 was refused here at threshold 45 and passes from 60",
		"score joomla: a test save Apache scores under 20 was refused here at threshold 30 and passes from 45",
		"relaxation woocommerce_api_write: the save this relaxation is for is still refused",
	} {
		if !strings.Contains(text, w) {
			t.Errorf("missing %q in:\n%s", w, text)
		}
	}
	if strings.Contains(text, "score xss") || strings.Contains(text, "remove_949110") || strings.Contains(text, "joomla_admin_save") || len(got) != 6 {
		t.Errorf("unexpected:\n%s", text)
	}
	ap := &SelfTest{Ways: map[string]string{"none": "HTTP 403", "remove_xss_tag": "passes"}, Scores: map[string]string{"wc_20": "passes"}, Lifts: map[string]string{"joomla_admin_save": "passes"}}
	if got := probeIssues(ap); len(got) != 0 {
		t.Fatalf("Apache: %+v", got)
	}
}

// TestEngineReportMapsRealCRS: lines in the form LiteSpeed logs map to the
// rules of a real CRS release (chained links to their chain's id).
func TestEngineReportMapsRealCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	files, _ := filepath.Glob(filepath.Join(src, "rules", "*.conf"))
	idx := indexRules(files)
	find := func(what string) int {
		key := reVarsOp.FindString(reSpaces.ReplaceAllString(what, " "))
		for _, r := range idx {
			if strings.HasPrefix(r.text, key) {
				return r.head
			}
		}
		return 0
	}
	for what, id := range map[string]int{
		`ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}" "t:none"`:     920390,
		`FILES_COMBINED_SIZE "@gt %{tx.combined_file_sizes}" "t:none"`: 920410,
		// An operator with an escaped quote.
		`REQUEST_HEADERS:Content-Type "!@rx ^[\w/.+*-]+(?:\s?;\s*(?:action|boundary|charset|component|start(?:-info)?|type|version)\s?=\s?['\"\w.()+,/:=?<>@#*-]+)*$" "t:none"`: 920470,
		`TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}"`:                                                                                         949111,
	} {
		if got := find(what); got != id {
			t.Errorf("%s: got %d, want %d", what, got, id)
		}
	}
	for _, r := range idx {
		if r.head == 0 && !strings.HasPrefix(r.text, "SecAction") {
			t.Errorf("rule without an id: %s (%s)", r.text[:min(80, len(r.text))], filepath.Base(r.file))
		}
	}
}
