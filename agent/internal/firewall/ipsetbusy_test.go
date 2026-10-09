package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A set listed by another program at the moment of the swap is busy for a
// moment: the restore is tried again instead of failing the firewall.
func TestRestoreIPSetRetriesBusy(t *testing.T) {
	old := ipsetBusyWait
	ipsetBusyWait = 0
	defer func() { ipsetBusyWait = old }()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ipset")
	count := filepath.Join(dir, "count")
	script := `#!/bin/sh
n=$(cat ` + count + ` 2>/dev/null || echo 0); n=$((n+1)); echo $n > ` + count + `
cat > ` + filepath.Join(dir, "stdin") + `
if [ $n -le 2 ]; then echo "ipset v7.1: Error in line 13360: Kernel error received: Device or resource busy" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := restoreIPSet(context.Background(), bin, "create xg_allow4 hash:net\n"); err != nil {
		t.Fatalf("not retried: %v", err)
	}
	if b, _ := os.ReadFile(count); strings.TrimSpace(string(b)) != "3" {
		t.Fatalf("tries: %s", b)
	}
	// Other errors are reported at once.
	os.WriteFile(bin, []byte("#!/bin/sh\necho 'ipset v7.1: Error in line 1: Syntax error' >&2\nexit 1\n"), 0o755)
	if err := restoreIPSet(context.Background(), bin, "x\n"); err == nil || !strings.Contains(err.Error(), "Syntax error") {
		t.Fatalf("err %v", err)
	}
}
