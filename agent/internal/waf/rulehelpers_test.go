package waf

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// rxOf returns the @rx pattern of a rendered rule line.
func rxOf(t *testing.T, line string) *regexp.Regexp {
	t.Helper()
	m := regexp.MustCompile(`"!?@rx (.*?)" "`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("no @rx in %q", line)
	}
	return regexp.MustCompile(m[1])
}

// chainOf returns the rendered lines of the rule with this id (the first
// line and its chained links).
func chainOf(out string, id int) []string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "SecRule ") && strings.Contains(l, fmt.Sprintf("id:%d,", id)) {
			c := []string{l}
			for j := i; strings.HasSuffix(lines[j], `,chain"`) && j+1 < len(lines); j++ {
				c = append(c, strings.TrimSpace(lines[j+1]))
			}
			return c
		}
	}
	return nil
}
