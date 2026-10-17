package core

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// The agent and its scan engine yield to the websites: a low CPU and disk
// weight (systemd, cgroup v1 and v2) gives them a small share only when
// the server is busy; an idle server still lets a scan finish quickly.
// The setting is a drop-in next to the unit, applied at once.
const weightsDropIn = "10-xpguard-weights.conf"

const weightsBody = `# Managed by the xPGuard agent: yield CPU and disk to the websites.
[Service]
CPUWeight=20
IOWeight=20
Nice=5
`

// runSystemctl is replaced in tests.
var runSystemctl = func(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", args...).Run()
}

// ensureServiceWeights writes the drop-in once and applies it to the
// running service.
func ensureServiceWeights() {
	if os.Geteuid() != 0 && unitMoveRoot == "" {
		return
	}
	if _, err := os.Stat(umPath(filepath.Join(unitDir, NewUnitName))); err != nil {
		return // not installed as a service (tests, manual runs)
	}
	dir := umPath(filepath.Join(unitDir, NewUnitName+".d"))
	file := filepath.Join(dir, weightsDropIn)
	if cur, err := os.ReadFile(file); err == nil && string(cur) == weightsBody {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if err := os.WriteFile(file, []byte(weightsBody), 0o644); err != nil {
		return
	}
	_ = runSystemctl("daemon-reload")
	// Live, without restarting the agent.
	_ = runSystemctl("set-property", "--runtime", NewUnitName, "CPUWeight=20", "IOWeight=20")
}
