// Package client implements enrollment and the persistent WebSocket session
// between the agent and the xPGuard portal.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/identity"
	"github.com/xmarthost/xmartguard/agent/internal/protocol"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// HTTPClient builds the HTTP client used for all portal calls.
func HTTPClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for test portals
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func postJSON(ctx context.Context, hc *http.Client, u string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xpguard-agent/"+version.Version)
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("portal returned %d: %s", res.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Enroll exchanges a one-time token for a server ID.
func Enroll(ctx context.Context, serverURL, token string, insecure bool, id *identity.Identity) (string, error) {
	var out struct {
		ServerID string `json:"server_id"`
	}
	err := postJSON(ctx, HTTPClient(insecure), serverURL+"/api/agent/enroll", map[string]any{
		"token":         token,
		"public_key":    id.PublicKeyB64(),
		"agent_version": version.Version,
		"inventory":     sysinfo.Collect(),
	}, &out)
	if err != nil {
		return "", err
	}
	if out.ServerID == "" {
		return "", errors.New("portal did not return a server id")
	}
	return out.ServerID, nil
}

// Unenroll tells the portal this server is being removed.
func Unenroll(ctx context.Context, cfg *config.Config, id *identity.Identity) error {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return postJSON(ctx, HTTPClient(cfg.InsecureTLS), cfg.ServerURL+"/api/agent/unenroll", map[string]any{
		"server_id": cfg.ServerID,
		"ts":        ts,
		"signature": id.SignB64(protocol.UnenrollPayload(cfg.ServerID, ts)),
	}, nil)
}

// Handler executes a portal command and returns its result data.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

// Session maintains the agent's connection to the portal.
type Session struct {
	Cfg       *config.Config
	ID        *identity.Identity
	Log       *slog.Logger
	Collector *sysinfo.Collector
	Handlers  map[string]Handler
	// Security, when set, is attached to every metrics sample.
	Security func() any
	// OnConnected, when set, runs after each completed handshake.
	OnConnected func()

	mu        sync.Mutex
	liveUntil time.Time
	active    int            // commands running
	running   map[string]int // commands running, by action
}

func wsURL(base, serverID string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/agent/ws"
	u.RawQuery = url.Values{"server_id": {serverID}}.Encode()
	return u.String(), nil
}

// errNotFound: the WebSocket request was answered with 404 or 410.
var errNotFound = errors.New("the portal answered that it does not know this server")

// ServerIDHeader carries the server id next to the query string.
const ServerIDHeader = "X-Xpguard-Server"

// ErrRevoked means the portal no longer recognises this server.
var ErrRevoked = errors.New("server has been removed from the portal")

// Run connects and reconnects until ctx is cancelled or the server is revoked.
func (s *Session) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		started := time.Now()
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		// Removed from the portal (or a proxy in front of it answering for
		// it): the protection on this server keeps running and the agent
		// asks again every hour, so a broken proxy never stops it.
		if errors.Is(err, ErrRevoked) {
			s.Log.Error("the portal does not know this server (removed, or a proxy in front of it drops the request); protection keeps running, asking again in 1 hour", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Hour):
			}
			continue
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		if errors.Is(err, errNotFound) {
			backoff = 10 * time.Minute
		} else if backoff > 2*time.Minute {
			backoff = 2 * time.Minute
		}
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		s.Log.Warn("portal connection lost", "err", err, "retry_in", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff < 2*time.Minute {
			backoff = min(backoff*2, 2*time.Minute)
		}
	}
}

// SetLive switches to 5-second metrics for the given duration.
func (s *Session) SetLive(d time.Duration) {
	s.mu.Lock()
	s.liveUntil = time.Now().Add(d)
	s.mu.Unlock()
}

func (s *Session) live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.liveUntil)
}

func (s *Session) runOnce(ctx context.Context) error {
	u, err := wsURL(s.Cfg.ServerURL, s.Cfg.ServerID)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, res, err := websocket.Dial(dctx, u, &websocket.DialOptions{
		HTTPClient: HTTPClient(s.Cfg.InsecureTLS),
		// The server id also in a header: some proxies (LiteSpeed's
		// WebSocket proxy) drop the query string.
		HTTPHeader: http.Header{"User-Agent": {"xpguard-agent/" + version.Version}, ServerIDHeader: {s.Cfg.ServerID}},
	})
	cancel()
	if err != nil {
		if res != nil && (res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone) {
			// The portal's answer for a removed server, but also what a
			// proxy that mangles the request gets: asked again in 10 minutes.
			return fmt.Errorf("%w (HTTP %d)", errNotFound, res.StatusCode)
		}
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(4 << 20)

	// Handshake: challenge -> auth -> welcome.
	var ch protocol.Envelope
	if err := readTimeout(ctx, conn, &ch, 15*time.Second); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if ch.Type != protocol.TypeChallenge || ch.Nonce == "" {
		return fmt.Errorf("handshake: unexpected %q", ch.Type)
	}
	if err := wsjson.Write(ctx, conn, protocol.Envelope{
		Type: protocol.TypeAuth, ServerID: s.Cfg.ServerID, Version: version.Version,
		Protocol: version.ProtocolVersion, Signature: s.ID.SignB64(protocol.AuthPayload(ch.Nonce, s.Cfg.ServerID)),
	}); err != nil {
		return err
	}
	var wel protocol.Envelope
	if err := readTimeout(ctx, conn, &wel, 15*time.Second); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if wel.Type == protocol.TypeError {
		if wel.Error == "revoked" {
			return ErrRevoked
		}
		return fmt.Errorf("portal refused: %s", wel.Error)
	}
	if wel.Type != protocol.TypeWelcome {
		return fmt.Errorf("handshake: unexpected %q", wel.Type)
	}
	interval := 60 * time.Second
	if wel.Config != nil && wel.Config.MetricsInterval >= 5 {
		interval = time.Duration(wel.Config.MetricsInterval) * time.Second
	}
	s.Log.Info("connected to portal", "server_id", s.Cfg.ServerID)
	if s.OnConnected != nil {
		s.OnConnected()
	}

	cctx, stop := context.WithCancel(ctx)
	defer stop()
	var wmu sync.Mutex
	send := func(e protocol.Envelope) error {
		wmu.Lock()
		defer wmu.Unlock()
		wctx, c := context.WithTimeout(cctx, 30*time.Second)
		defer c()
		return wsjson.Write(wctx, conn, e)
	}

	if err := send(protocol.Envelope{Type: protocol.TypeInventory, Data: sysinfo.Collect()}); err != nil {
		return err
	}
	_ = send(protocol.Envelope{Type: protocol.TypeMetrics, Data: s.sample()})

	errc := make(chan error, 2)
	go func() { // metrics loop
		next := time.Now().Add(interval)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case now := <-t.C:
				if now.Before(next) && !(s.live() && now.Unix()%5 == 0) {
					continue
				}
				if !now.Before(next) {
					next = now.Add(interval)
				}
				if err := send(protocol.Envelope{Type: protocol.TypeMetrics, Data: s.sample()}); err != nil {
					errc <- err
					return
				}
			}
		}
	}()
	go func() { // read loop
		for {
			var e protocol.Envelope
			if err := wsjson.Read(cctx, conn, &e); err != nil {
				errc <- err
				return
			}
			switch e.Type {
			case protocol.TypeCommand:
				go s.handle(cctx, e, send)
			case protocol.TypeError:
				if e.Error == "revoked" {
					errc <- ErrRevoked
					return
				}
				s.Log.Warn("portal error", "error", e.Error)
			}
		}
	}()
	err = <-errc
	conn.Close(websocket.StatusNormalClosure, "")
	return err
}

// sample collects system metrics plus the security summary.
func (s *Session) sample() any {
	m := s.Collector.Collect(10)
	if s.Security == nil {
		return m
	}
	return struct {
		sysinfo.Sample
		Security any `json:"security"`
	}{m, s.Security()}
}

// MaxHandlers is how many portal commands run at once; more are refused
// as busy (the portal's own limit ends with its timeout, not the handler).
const MaxHandlers = 16

// MaxResult keeps a result frame under the portal's 4 MB WebSocket limit:
// a larger frame would close the connection and fail every pending command.
const MaxResult = 3_500_000

// defaultTimeout bounds a command; actionTimeouts are the commands the
// portal waits longer for (server/src/routes/agent-cmd.ts ACTIONS).
const defaultTimeout = 10 * time.Minute

var actionTimeouts = map[string]time.Duration{
	"monitor.rootkit": time.Hour,
	"clamav.reload":   25 * time.Minute,
	"cms.update":      11 * time.Minute,
}

// singleFlight actions are heavy: a second one while one runs is refused.
var singleFlight = map[string]bool{
	"learning.sample": true, "findings.recheck": true, "domainrep.check": true, "db.clean": true,
	"monitor.rootkit": true, "clamav.reload": true,
}

func (s *Session) handle(ctx context.Context, e protocol.Envelope, send func(protocol.Envelope) error) {
	res := protocol.Envelope{Type: protocol.TypeResult, ID: e.ID}
	ok := false
	if data, err := s.run(ctx, e); err != nil {
		res.Error = err.Error()
	} else if b, err := json.Marshal(data); err != nil {
		res.Error = "cannot encode result: " + err.Error()
	} else if len(b) > MaxResult {
		res.Error = fmt.Sprintf("result too large (%d MB); use filters or a smaller page", len(b)>>20)
	} else {
		ok, res.Data = true, json.RawMessage(b)
	}
	res.OK = &ok
	if err := send(res); err != nil {
		s.Log.Warn("failed to send result", "id", e.ID, "err", err)
	}
}

// run calls the handler with its deadline, within the concurrency limits;
// a panic in it becomes an error instead of stopping the agent.
func (s *Session) run(ctx context.Context, e protocol.Envelope) (data any, err error) {
	h, found := s.Handlers[e.Action]
	if !found {
		return nil, errors.New("unsupported action: " + e.Action)
	}
	s.mu.Lock()
	if s.running == nil {
		s.running = map[string]int{}
	}
	busy := s.active >= MaxHandlers || (singleFlight[e.Action] && s.running[e.Action] > 0)
	if !busy {
		s.active++
		s.running[e.Action]++
	}
	s.mu.Unlock()
	if busy {
		return nil, fmt.Errorf("the agent is busy (%s or too many commands running); try again shortly", e.Action)
	}
	defer func() {
		s.mu.Lock()
		s.active--
		s.running[e.Action]--
		s.mu.Unlock()
		if r := recover(); r != nil {
			s.Log.Error("command handler panicked", "action", e.Action, "panic", r, "stack", string(debug.Stack()))
			data, err = nil, errors.New("internal error in "+e.Action)
		}
	}()
	d := defaultTimeout
	if t, ok := actionTimeouts[e.Action]; ok {
		d = t
	}
	hctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return h(hctx, e.Params)
}

func readTimeout(ctx context.Context, c *websocket.Conn, v any, d time.Duration) error {
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return wsjson.Read(rctx, c, v)
}
