package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- Panel, web server and mail releases with known exploited holes ----

// The 2026 attacks on shared hosting went for the panel and the web server
// (root on the whole server), not only the websites: CVE-2026-41940 (WHM
// authentication bypass, exploited from February, in KEV) and
// CVE-2026-58048 (a cPanel user gets database root) are fixed in cPanel
// 11.136.0.32; LiteSpeed Enterprise before 6.3.7 lets a tenant leave
// CageFS (6.3.5 fixed CVE-2026-31386); Exim 4.99.2 fixes CVE-2026-40685;
// Roundcube 1.6.11 and 1.5.10 fix CVE-2025-49113 (in KEV). Read-only.
type stackFix struct {
	name, fixed, why string
	branchFix        map[string]string // per major.minor branch, when one is older
}

var (
	cpanelFix   = stackFix{name: "cPanel & WHM", fixed: "11.136.0.32", why: "CVE-2026-41940 (WHM login bypass, exploited) and CVE-2026-58048 (database root for a cPanel user)"}
	lswsFix     = stackFix{name: "LiteSpeed Web Server", fixed: "6.3.7", why: "a tenant can leave CageFS and reach root (fixed in 6.3.7; CVE-2026-31386 in 6.3.5)"}
	eximFix     = stackFix{name: "Exim", fixed: "4.99.2", why: "CVE-2026-40685"}
	roundcubeFx = stackFix{name: "Roundcube", fixed: "1.6.11", why: "CVE-2025-49113 (remote code execution after login, exploited)", branchFix: map[string]string{"1.5": "1.5.10"}}

	reVersion    = regexp.MustCompile(`\b(\d+(?:\.\d+){1,3})\b`)
	reRCMail     = regexp.MustCompile(`RCMAIL_VERSION['"]\s*,\s*['"](\d+(?:\.\d+)+)`)
	reEximBanner = regexp.MustCompile(`(?m)^Exim version (\d+(?:\.\d+)+)`)
)

func (a *Auditor) stackFile(p string) string {
	b, err := os.ReadFile(filepath.Join(a.StackRoot, p))
	if err != nil {
		return ""
	}
	return string(b)
}

func eximBanner() string {
	if _, err := exec.LookPath("exim"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "exim", "-bV").Output()
	return string(out)
}

func (a *Auditor) stackCVEs() []Item {
	var out []Item
	check := func(f stackFix, ver string) {
		if ver == "" {
			return
		}
		fixed := f.fixed
		if parts := strings.SplitN(ver, ".", 3); len(parts) >= 2 {
			if b, ok := f.branchFix[parts[0]+"."+parts[1]]; ok {
				fixed = b
			}
		}
		if cmpVersion(ver, fixed) < 0 {
			out = append(out, Item{Check: "stack_cve", Severity: "high", Title: f.name + " " + ver + " has exploited holes",
				Detail: "Update to " + fixed + " or newer: " + f.why + "."})
		}
	}
	if m := reVersion.FindString(a.stackFile("usr/local/cpanel/version")); m != "" {
		check(cpanelFix, m)
	}
	// (OpenLiteSpeed keeps its 1.x version in the same file.)
	if m := reVersion.FindString(a.stackFile("usr/local/lsws/VERSION")); m != "" && cmpVersion(m, "5") >= 0 {
		check(lswsFix, m)
	}
	banner := a.EximVersion
	if banner == nil {
		banner = eximBanner
	}
	if m := reEximBanner.FindStringSubmatch(banner()); m != nil {
		check(eximFix, m[1])
	}
	if m := reRCMail.FindStringSubmatch(a.stackFile("usr/local/cpanel/base/3rdparty/roundcube/program/include/iniset.php")); m != nil {
		check(roundcubeFx, m[1])
	}
	return out
}

// cmpVersion compares dotted numeric versions (-1, 0, 1).
func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
