package scanner

import (
	"fmt"
	"strings"
	"testing"
)

// A literal before a choice of literals joins them ("$_" + POST).
func TestPrefilterLiteralsBacktick(t *testing.T) {
	got := fmt.Sprintf("%s", literalsOf(reBacktickExec))
	if got != "[$_post $_get $_request $_cookie]" {
		t.Fatalf("literals %s", got)
	}
}

func TestQuickChecks(t *testing.T) {
	yes := []string{"$a = f( 12 ) (", "x(7)(1)", strings.Repeat("A", 130)}
	no := []string{"f(a)(b)", "f(1) + g", strings.Repeat("A", 100) + " " + strings.Repeat("A", 100)}
	check := func(s string) bool { return numberedCall([]byte(s)) || b64Run([]byte(s), 120) }
	for _, s := range yes {
		if !check(s) {
			t.Errorf("%q should pass", s)
		}
	}
	for _, s := range no {
		if check(s) {
			t.Errorf("%q should not pass", s)
		}
	}
}
