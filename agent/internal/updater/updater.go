// Package updater replaces the agent binary with a newer build from the
// portal. The caller exits afterwards so systemd restarts the new binary.
//
// The binary it replaces is kept next to it (".prev"). The new one counts
// its starts until it reaches the portal (or has run for a while); when it
// keeps failing to start, the previous binary is put back (see Started).
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// MaxStarts is how many times an updated binary may start without
// reaching the portal before the previous binary comes back.
const MaxStarts = 3

// idleTimeout cancels a download that receives nothing for this long (the
// whole download has no fixed limit: a busy portal serves slowly).
var idleTimeout = 60 * time.Second

// retryDelay spreads the retries of a failed download.
var retryDelay = func() time.Duration { return time.Duration(5+rand.IntN(25)) * time.Second }

// Update downloads the agent for this architecture, verifies it against
// the published checksum (and the expected one, when given), checks that it
// runs and is not older than this agent, and atomically replaces the
// running executable, keeping the old one for a rollback.
func Update(ctx context.Context, hc *http.Client, portal, expectSHA string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	return update(ctx, hc, portal, expectSHA, self)
}

func update(ctx context.Context, hc *http.Client, portal, expectSHA, self string) (string, error) {
	// The binary runs as root on the server: never fetched in clear text
	// or from a portal whose certificate is not checked (a portal on this
	// machine itself is reached without a network, as install.sh allows).
	u, err := url.Parse(portal)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return "", errors.New("updates are only taken from an https portal address")
	}
	if tr, ok := hc.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		return "", errors.New("updates are not taken from a portal whose certificate is not verified (enrolled with --insecure)")
	}
	c := *hc
	c.Timeout = 0 // the download is bounded by ctx and idleTimeout
	// A redirect is never followed: the portal serves the files itself.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	name := "xpguard-agent-linux-" + runtime.GOARCH
	get := func(u string, limit int64) ([]byte, error) {
		gctx, cancel := context.WithCancel(ctx)
		defer cancel()
		req, _ := http.NewRequestWithContext(gctx, http.MethodGet, u, nil)
		idle := time.AfterFunc(idleTimeout, cancel)
		defer idle.Stop()
		res, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, &statusError{fmt.Sprintf("GET %s: %s", u, res.Status)}
		}
		return io.ReadAll(&idleReader{r: io.LimitReader(res.Body, limit), t: idle})
	}
	// After a portal release every agent downloads at once: a failed
	// download is tried again a few times, spread out.
	retry := func(u string, limit int64) (b []byte, err error) {
		for i := 0; i < 3; i++ {
			if i > 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(retryDelay()):
				}
			}
			var se *statusError
			if b, err = get(u, limit); err == nil || errors.As(err, &se) {
				return b, err
			}
		}
		return nil, err
	}
	sumRaw, err := retry(portal+"/downloads/"+name+".sha256", 1024)
	if err != nil {
		return "", err
	}
	published := strings.Fields(string(sumRaw))
	if len(published) == 0 {
		return "", errors.New("empty checksum file")
	}
	bin, err := retry(portal+"/downloads/"+name, 200<<20)
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
	newV := strings.TrimSpace(string(out))
	if Older(newV, version.Version) {
		os.Remove(tmp)
		return "", fmt.Errorf("refusing to replace agent %s with the older %s", version.Version, newV)
	}
	// Keep the running binary for a rollback (a hard link: the rename
	// below leaves it in place).
	prev := self + ".prev"
	os.Remove(prev)
	if err := os.Link(self, prev); err != nil {
		if err := copyFile(self, prev); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("cannot keep the current agent for a rollback: %w", err)
		}
	}
	if err := writeMarker(self, marker{From: version.Version, To: newV}); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		os.Remove(markerPath(self))
		return "", err
	}
	return newV, nil
}

// statusError is the portal's answer (not a broken download): not retried.
type statusError struct{ msg string }

func (e *statusError) Error() string { return e.msg }

// idleReader pushes the idle deadline back on every read that gets data.
type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.t.Reset(idleTimeout)
	}
	return n, err
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// Older reports whether version a is lower than b, comparing the numeric
// dotted parts ("0.22.26-dev" equals "0.22.26").
func Older(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		x, y := -1, -1
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func parts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = -1
		}
		out = append(out, n)
	}
	return out
}

// marker says an update was installed and not yet confirmed.
type marker struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Starts int    `json:"starts"`
}

func markerPath(self string) string { return self + ".update" }

func writeMarker(self string, m marker) error {
	b, _ := json.Marshal(m)
	return os.WriteFile(markerPath(self), b, 0o600)
}

// Started is called first by the running agent. After an update it counts
// the new binary's starts; once it has started more than MaxStarts times
// without Confirm, the previous binary is put back and Started returns a
// note: the caller exits non-zero so systemd starts the previous build.
func Started() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	return started(self, version.Version)
}

func started(self, running string) (string, error) {
	raw, err := os.ReadFile(markerPath(self))
	if err != nil {
		return "", nil
	}
	var m marker
	if json.Unmarshal(raw, &m) != nil || m.To != running {
		// Not this build's update (replaced by hand since): nothing to do.
		os.Remove(markerPath(self))
		return "", nil
	}
	m.Starts++
	if m.Starts <= MaxStarts {
		return "", writeMarker(self, m)
	}
	prev := self + ".prev"
	if _, err := os.Stat(prev); err != nil {
		os.Remove(markerPath(self))
		return "", fmt.Errorf("agent %s failed to start %d times and no previous binary is kept", running, MaxStarts)
	}
	if err := os.Rename(prev, self); err != nil {
		return "", fmt.Errorf("rollback to %s failed: %w", m.From, err)
	}
	os.Remove(markerPath(self))
	return fmt.Sprintf("agent %s failed to start %d times; previous agent %s put back", running, MaxStarts, m.From), nil
}

// Confirm marks the running build as good (it reached the portal or has
// run for a while): it is kept from now on.
func Confirm() {
	if self, err := os.Executable(); err == nil {
		self, _ = filepath.EvalSymlinks(self)
		os.Remove(markerPath(self))
	}
}

// loopback reports a portal on this machine (localhost, 127.0.0.0/8, ::1).
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
