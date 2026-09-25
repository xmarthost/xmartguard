// Package updater replaces the agent binary with a newer build from the
// portal. The caller exits afterwards so systemd restarts the new binary.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Update downloads the agent for this architecture, verifies it against
// the published checksum (and the expected one, when given), checks that it
// runs, and atomically replaces the running executable.
func Update(ctx context.Context, hc *http.Client, portal, expectSHA string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	name := "xmartguard-agent-linux-" + runtime.GOARCH
	get := func(u string, limit int64) ([]byte, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		res, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s: %s", u, res.Status)
		}
		return io.ReadAll(io.LimitReader(res.Body, limit))
	}
	sumRaw, err := get(portal+"/downloads/"+name+".sha256", 1024)
	if err != nil {
		return "", err
	}
	published := strings.Fields(string(sumRaw))
	if len(published) == 0 {
		return "", errors.New("empty checksum file")
	}
	bin, err := get(portal+"/downloads/"+name, 200<<20)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(bin)
	got := hex.EncodeToString(h[:])
	if got != published[0] || (expectSHA != "" && got != expectSHA) {
		return "", errors.New("checksum mismatch; update aborted")
	}
	tmp := self + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", err
	}
	vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, tmp, "version").Output()
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("new agent does not run: %w", err)
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
