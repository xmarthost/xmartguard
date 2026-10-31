package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A relaxation that knows who sends a request (a Joomla administrator save
// with its form token, a WooCommerce REST write with the shop's API keys)
// used to raise the anomaly threshold only. LiteSpeed's engine scores such
// a request again after it passed the first check (self-test score probes,
// business600 and s1.cobuildhost, 2026-10-31: a save Apache scores under
// 20 reached 39 and 54; CJdropshipping's product write went from 13 to
// 39), so no threshold is safe there. The relaxation now also names the
// CRS attack families its saves set off (tx.xg_no_<family>=1) and the
// rules below take those families out of that request by rule id
// (ctl:ruleRemoveById, which every engine honours, self-test way
// "remove_949110"). A rule that does not run scores nothing, on any
// engine. The other families (SQL injection above all) still check the
// request under the raised threshold.

// IDFamilyRemove: the family removal rules (7700941-7700980, five per
// family), and IDFamilyStrict the rule before them that withdraws the
// flags for an address with a bad reputation. (0.24.17 used 7700879-
// 7700899; eight families did not fit below the CAPTCHA gate's 7700900.)
const (
	IDFamilyRemove = 7700941
	IDFamilyStrict = 7700940
)

// familyChunk is how many rule ids one removal rule carries.
const familyChunk = 20

// crsFamilies: the CRS files (REQUEST-<file>-*.conf) a flag takes out.
var crsFamilies = []struct{ flag, file, name string }{
	{"xg_no_lfi", "930", "path traversal and OS file access"},
	{"xg_no_rce", "932", "remote command execution"},
	{"xg_no_php", "933", "PHP injection"},
	{"xg_no_xss", "941", "cross-site scripting"},
	// The rest of the injection families xPGuard's exclusions take out
	// (removeTags), for engines that ignore removal by tag or range.
	{"xg_no_rfi", "931", "remote file inclusion"},
	{"xg_no_gen", "934", "generic injection"},
	{"xg_no_sqli", "942", "SQL injection"},
	{"xg_no_fix", "943", "session fixation"},
}

// allFamilyFlags: every family, for the exclusions that take all the
// injection rules out (removeTags).
func allFamilyFlags() string {
	var s []string
	for _, f := range crsFamilies {
		s = append(s, "setvar:tx."+f.flag+"=1")
	}
	return strings.Join(s, ",")
}

var reCRSRuleID = regexp.MustCompile(`["',\s]id:(\d+)`)

// crsFamilyIDs reads the rule ids of one CRS family from the installed
// release (a new CRS release brings its new ids along).
func crsFamilyIDs(dir, file string) []int {
	paths, _ := filepath.Glob(filepath.Join(dir, "rules", "REQUEST-"+file+"-*.conf"))
	seen := map[int]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range reCRSRuleID.FindAllStringSubmatch(line, -1) {
				id, _ := strconv.Atoi(m[1])
				// Only the family's own ids (a comment or msg could name others).
				if strings.HasPrefix(m[1], file) && len(m[1]) == 6 {
					seen[id] = true
				}
			}
		}
	}
	ids := make([]int, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// familyRemoveSetup writes the removal rules for the CRS release in dir.
// They come after the relaxations (which set the flags in phase 1 or 2)
// and before the CRS rules (included after the setup).
func familyRemoveSetup(dir string) string {
	var b strings.Builder
	b.WriteString("# CRS families a relaxation vouched for are taken out of that request (xPGuard).\n")
	var unset []string
	for _, f := range crsFamilies {
		unset = append(unset, "setvar:tx."+f.flag+"=0")
	}
	fmt.Fprintf(&b, `SecRule &TX:xg_strict "@ge 1" "id:%d,phase:2,pass,t:none,nolog,%s"`+"\n", IDFamilyStrict, strings.Join(unset, ","))
	for fi, f := range crsFamilies {
		ids := crsFamilyIDs(dir, f.file)
		for c := 0; c*familyChunk < len(ids) && c < 5; c++ {
			end := (c + 1) * familyChunk
			if end > len(ids) || c == 4 {
				end = len(ids)
			}
			var ctl []string
			for _, id := range ids[c*familyChunk : end] {
				ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
			}
			fmt.Fprintf(&b, `SecRule TX:%s "@eq 1" "id:%d,phase:2,pass,t:none,nolog,%s"`+"\n", f.flag, IDFamilyRemove+fi*5+c, strings.Join(ctl, ","))
		}
	}
	return b.String()
}

// familyFlags sets the flags of the named CRS files.
func familyFlags(files ...string) string {
	var s []string
	for _, f := range crsFamilies {
		for _, want := range files {
			if f.file == want {
				s = append(s, "setvar:tx."+f.flag+"=1")
			}
		}
	}
	return strings.Join(s, ",")
}
