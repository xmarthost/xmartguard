// Package client implements enrollment and the persistent WebSocket session
// between the agent and the XMart Guard portal.
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
	req.Header.Set("User-Agent", "xmartguard-agent/"+version.Version)
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

	mu        sync.Mutex
	liveUntil time.Time
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
		if errors.Is(err, ErrRevoked) {
			return err
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		s.Log.Warn("portal connection lost", "err", err, "retry_in", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = min(backoff*2, 2*time.Minute)
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
		HTTPHeader: http.Header{"User-Agent": {"xmartguard-agent/" + version.Version}},
	})
	cancel()
	if err != nil {
		if res != nil && (res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone) {
			return ErrRevoked
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

func (s *Session) handle(ctx context.Context, e protocol.Envelope, send func(protocol.Envelope) error) {
	res := protocol.Envelope{Type: protocol.TypeResult, ID: e.ID}
	ok := false
	h, found := s.Handlers[e.Action]
	if !found {
		res.Error = "unsupported action: " + e.Action
	} else {
		hctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		data, err := h(hctx, e.Params)
		cancel()
		if err != nil {
			res.Error = err.Error()
		} else {
			ok, res.Data = true, data
		}
	}
	res.OK = &ok
	if err := send(res); err != nil {
		s.Log.Warn("failed to send result", "id", e.ID, "err", err)
	}
}

func readTimeout(ctx context.Context, c *websocket.Conn, v any, d time.Duration) error {
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return wsjson.Read(rctx, c, v)
}
