package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The agent runs as /opt/xpguard/bin/xpguard-agent under xpguard-agent.service,
// so process lists (ps, WHM » Process Manager) show the product's name.
// Installs from before the xPGuard name run the same program as
// /opt/xmartguard/bin/xmartguard-agent under xmartguard-agent.service; they
// are moved once, the first time the new version starts. Configuration and
// data stay where they are (web server configuration points at them).
const (
	NewBinPath   = "/opt/xpguard/bin/xpguard-agent"
	NewUnitName  = "xpguard-agent.service"
	OldBinPath   = "/opt/xmartguard/bin/xmartguard-agent"
	OldUnitName  = "xmartguard-agent.service"
	unitDir      = "/etc/systemd/system"
	moveKVKey    = "unit_move_tried"
	moveCooldown = 24 * time.Hour
)

// unitMoveRoot prefixes the paths above (tests).
var unitMoveRoot = ""

func umPath(p string) string { return unitMoveRoot + p }

// runSwitch starts the switch-over outside this service (tests replace it).
var runSwitch = func(script string) error {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return fmt.Errorf("systemd-run not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-run", "--unit=xpguard-rename-"+fmt.Sprint(time.Now().Unix()),
		"--no-block", "--collect", "/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// maybeMoveUnit moves an old install to the new binary and service name.
// The new service is started by a transient systemd job (outside this
// service, which it stops); if the new service is not active 20 seconds
// later the old one is started again, so the server never stays without
// its agent.
func (a *Agent) maybeMoveUnit(self string) {
	if os.Geteuid() != 0 && unitMoveRoot == "" {
		return
	}
	if self != umPath(OldBinPath) {
		return // already moved, a custom install or a development build
	}
	oldUnit := umPath(filepath.Join(unitDir, OldUnitName))
	unit, err := os.ReadFile(oldUnit)
	if err != nil || !strings.Contains(string(unit), OldBinPath) {
		return
	}
	if t := store.GetKV(a.DB, moveKVKey); t != "" {
		if at, err := time.Parse(time.RFC3339, t); err == nil && time.Since(at) < moveCooldown {
			return
		}
	}
	_ = store.SetKV(a.DB, moveKVKey, time.Now().UTC().Format(time.RFC3339))

	// 1. The program at its new path (a copy: the old file stays until the
	//    new service runs).
	if err := copyFile(self, umPath(NewBinPath), 0o755); err != nil {
		a.Log.Warn("service rename: could not copy the agent", "err", err)
		return
	}
	// 2. The new unit, same settings, new program path and description.
	nu := strings.ReplaceAll(string(unit), OldBinPath, NewBinPath)
	if err := os.WriteFile(umPath(filepath.Join(unitDir, NewUnitName)), []byte(nu), 0o644); err != nil {
		a.Log.Warn("service rename: could not write the new unit", "err", err)
		return
	}
	// 3. CSF/LFD must not report the renamed process.
	lfd := ""
	if p := umPath("/etc/csf/csf.pignore"); fileExists(p) {
		if b, _ := os.ReadFile(p); !strings.Contains(string(b), "exe:"+NewBinPath) {
			if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.WriteString("exe:" + NewBinPath + "\n")
				f.Close()
				lfd = "(command -v lfd >/dev/null 2>&1 && service lfd restart >/dev/null 2>&1) || true; "
			}
		}
	}
	// 4. Switch over; roll back if the new service does not come up.
	script := fmt.Sprintf(`sleep 3
systemctl daemon-reload
systemctl stop %[1]s
if systemctl enable --now %[2]s && sleep 20 && systemctl is-active -q %[2]s; then
  systemctl disable %[1]s >/dev/null 2>&1
  rm -f %[3]s
  systemctl daemon-reload
  rm -f %[4]s && ln -s %[5]s %[4]s
  for l in /usr/local/bin/xmartguard-agent /usr/local/bin/xmartguard /usr/local/bin/xgcli; do [ -L "$l" ] && ln -sfn %[5]s "$l"; done
  ln -sfn %[5]s /usr/local/bin/xpguard-agent
  %[6]s
else
  systemctl disable --now %[2]s >/dev/null 2>&1
  systemctl enable --now %[1]s
fi
`, OldUnitName, NewUnitName, filepath.Join(unitDir, OldUnitName), OldBinPath, NewBinPath, lfd)
	if err := runSwitch(script); err != nil {
		a.Log.Warn("service rename: switch not started; staying on the old service", "err", err)
		_ = os.Remove(umPath(filepath.Join(unitDir, NewUnitName)))
		return
	}
	a.Log.Info("service rename: switching to " + NewUnitName + " (" + NewBinPath + ")")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// copyFile writes src to dst atomically.
func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
