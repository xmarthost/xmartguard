// Package local serves the agent's control API on a Unix socket for the
// cPanel/WHM plugins and the command line. Callers are identified by the
// kernel (SO_PEERCRED), not by anything they send: root gets the admin
// command set, any other user only their own account's commands.
package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Handler matches client.Handler.
type Handler = func(context.Context, json.RawMessage) (any, error)

// DefaultSocket is where the agent listens.
const DefaultSocket = "/run/xmartguard/agent.sock"

// SocketPath honours XG_SOCKET (tests).
func SocketPath() string {
	if p := os.Getenv("XG_SOCKET"); p != "" {
		return p
	}
	return DefaultSocket
}

// Server routes calls by the caller's uid.
type Server struct {
	Root map[string]Handler
	// User returns the command set for a non-root account (nil = no access).
	User func(u *user.User) map[string]Handler
	Log  *slog.Logger
}

type credKey struct{}

// Request is the wire format: {"action": "...", "params": {...}}.
type Request struct {
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

// Response is {"ok": true, "data": ...} or {"ok": false, "error": "..."}.
type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Run listens until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	path := SocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(path), 0o755)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// Anyone may connect; what they can do depends on who they are.
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uc, ok := c.(*net.UnixConn)
			if !ok {
				return ctx
			}
			raw, err := uc.SyscallConn()
			if err != nil {
				return ctx
			}
			var cred *unix.Ucred
			_ = raw.Control(func(fd uintptr) {
				cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
			})
			if cred == nil {
				return ctx
			}
			return context.WithValue(ctx, credKey{}, cred)
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = os.Remove(path)
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, resp Response) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/call" {
		reply(404, Response{Error: "not found"})
		return
	}
	cred, _ := r.Context().Value(credKey{}).(*unix.Ucred)
	if cred == nil {
		reply(403, Response{Error: "cannot identify caller"})
		return
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		reply(400, Response{Error: "invalid request"})
		return
	}
	var table map[string]Handler
	if cred.Uid == 0 {
		table = s.Root
	} else if s.User != nil {
		if u, err := user.LookupId(fmt.Sprint(cred.Uid)); err == nil {
			table = s.User(u)
		}
	}
	if table == nil {
		reply(403, Response{Error: "this account cannot use XMart Guard"})
		return
	}
	h, ok := table[req.Action]
	if !ok {
		reply(404, Response{Error: fmt.Sprintf("unknown action %q", req.Action)})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	data, err := h(ctx, req.Params)
	if err != nil {
		reply(200, Response{Error: err.Error()})
		return
	}
	raw, err := json.Marshal(data)
	if err != nil {
		reply(500, Response{Error: err.Error()})
		return
	}
	if s.Log != nil && cred.Uid != 0 {
		s.Log.Debug("panel call", "uid", cred.Uid, "action", req.Action)
	}
	reply(200, Response{OK: true, Data: raw})
}

// Call sends one request to the running agent.
func Call(ctx context.Context, action string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"action": action, "params": params})
	if err != nil {
		return nil, err
	}
	return CallRaw(ctx, body)
}

// CallRaw forwards an already-encoded Request and returns the data field.
func CallRaw(ctx context.Context, body []byte) (json.RawMessage, error) {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", SocketPath())
		},
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://xmartguard/v1/call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, errors.New("the XMart Guard agent is not running (systemctl start xmartguard-agent)")
	}
	defer res.Body.Close()
	var resp Response
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("bad response from agent: %w", err)
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Data, nil
}
