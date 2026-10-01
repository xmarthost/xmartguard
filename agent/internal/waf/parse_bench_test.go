package waf

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// A CRS warning as Apache writes it: busy servers log many of these per
// request, so parsing must stay cheap.
var benchLine = `[Wed Oct 01 10:00:00.123456 2026] [:error] [pid 12345:tid 140000] [client 203.0.113.7:51234] [client 203.0.113.7] ModSecurity: Warning. Matched "Operator ` + "`" + `Rx' with parameter ` + "`" + `(?i)(?:\\b(?:s(?:tdin|ystem)|...)' against variable ` + "`" + `ARGS:q' (Value: ` + "`" + strings.Repeat("a", 300) + `' ) [file "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf"] [line "496"] [id "932150"] [msg "Remote Command Execution: Direct Unix Command Execution"] [data "Matched Data: system found within ARGS:q: aaaa"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.5"] [tag "application-multi"] [tag "language-shell"] [tag "platform-unix"] [tag "attack-rce"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [hostname "example.com"] [uri "/index.php"] [unique_id "ZxYabc123"], referer: https://example.com/`

func BenchmarkParseLine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseLine(benchLine)
	}
}

func BenchmarkParseLineOther(b *testing.B) {
	l := `[Wed Oct 01 10:00:00.123456 2026] [php:warn] [pid 1] [client 1.2.3.4:5] PHP Warning:  Undefined variable $x in /home/u/public_html/a.php on line 3`
	for i := 0; i < b.N; i++ {
		ParseLine(l)
	}
}

// oldParse is the earlier whole-line regexp parser, kept as the reference.
func oldParse(line string) (Event, bool) {
	if !strings.Contains(line, "ModSecurity") && !strings.Contains(line, "mod_security") {
		return Event{}, false
	}
	if !strings.Contains(line, `[id "`) {
		return Event{}, false
	}
	var e Event
	if c := reClient.FindStringSubmatch(line); c != nil {
		e = Event{IP: c[1]}
	} else if c := reLSClient.FindStringSubmatch(line); c != nil {
		e = Event{IP: c[1], Host: strings.TrimPrefix(c[2], "www.")}
	} else {
		return Event{}, false
	}
	for _, f := range reField.FindAllStringSubmatch(line, -1) {
		val := strings.ReplaceAll(f[2], `\"`, `"`)
		switch f[1] {
		case "msg":
			e.Msg = val
		case "id":
			e.RuleID, _ = strconv.Atoi(val)
		case "hostname":
			e.Host = val
		case "uri":
			e.URI = val
		}
	}
	if mm := reMethod.FindStringSubmatch(line); mm != nil {
		e.Method = mm[1]
	}
	if u := reUniqueID.FindStringSubmatch(line); u != nil {
		e.UID = u[1]
	}
	if m := reMatch.FindStringSubmatch(line); m != nil {
		e.Detail = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m[1]), `\\\\`, `\`), `\\`, `\`)
		if len(e.Detail) > 300 {
			e.Detail = e.Detail[:300] + "…"
		}
	}
	if d := reDenied.FindStringSubmatch(line); d != nil && d[1] != "" {
		e.Action = "Access denied with code " + d[1]
	} else {
		e.Action = "Logged"
	}
	return e, true
}

func parseCorpus(t *testing.T) []string {
	lines := []string{
		benchLine,
		`2026-10-01 10:00:00.123456 [NOTICE] [1234] [T0] [203.0.113.9:51234-3#APVH_www.example.com:443] [Module:mod_security] [id "7700501"] [msg "Webshell upload"] [uri "/up.php"] Access denied with code 403 (phase 2). Pattern match "x" at ARGS:f. [file "/x.conf"] [unique_id "abc"]`,
		`[Wed Oct 01 10:00:00 2026] [:error] [client 2001:db8::1] ModSecurity: Warning. Pattern match "a" at REQUEST_COOKIES:x. [file "/r.conf"] [line "1"] [id "942100"] [msg "SQL \"Injection\""] [hostname "a.b"] [uri "/"] [unique_id "u1"] denied by server Access denied with code 406 (phase 2).`,
		`[client 1.2.3.4] [client 5.6.7.8:99] ModSecurity: Access denied with code 403 (phase 1). [file "/f"] [id "1"] [method "POST"]`,
		`[x] ModSecurity: Access denied with code 403 (bad) Warning. something [file "/f"] [id "2"] [client 9.9.9.9]`,
		`[x] ModSecurity: Warning. no file here [id "3"] [client 9.9.9.9]`,
	}
	b, err := os.ReadFile("/var/log/apache2/error.log")
	if err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, `[id "`) {
				lines = append(lines, l)
			}
		}
	}
	return lines
}

func TestFastParseMatchesRegexp(t *testing.T) {
	lines := parseCorpus(t)
	for _, l := range lines {
		want, ok1 := oldParse(l)
		got, ok2 := ParseLine(l)
		got.At, got.Category, got.User = 0, "", ""
		if ok1 != ok2 || (ok1 && got != want) {
			t.Errorf("line %q\n got %+v %v\nwant %+v %v", l, got, ok2, want, ok1)
		}
	}
	t.Logf("%d lines compared", len(lines))
}
