// Package captcha serves the page that visitors from a banned address see
// instead of a dropped connection. The firewall redirects their HTTP and
// HTTPS traffic here; solving the challenge lifts the ban for that address
// and allows it for a while.
//
// The built-in challenge needs no third party: a distorted PNG of digits
// generated on the server. Cloudflare Turnstile or Google reCAPTCHA v2 can
// be used instead when their keys are configured.
package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Server is the CAPTCHA web server.
type Server struct {
	Settings *settings.Store
	Log      *slog.Logger
	// Solved is called with the visitor address after a correct answer.
	Solved func(ip string) error
	// Certs finds a certificate for a TLS server name (nil = self-signed).
	Certs *CertStore
	// VerifyURL overrides the provider verification endpoint (tests).
	VerifyURL string

	key      []byte
	mu       sync.Mutex
	attempts map[string][]time.Time
	running  [2]*http.Server
	ports    [2]int
}

// Run keeps the listeners in line with the settings until ctx ends: they run
// only while a CAPTCHA option is enabled.
func (s *Server) Run(ctx context.Context) {
	s.key = make([]byte, 32)
	_, _ = rand.Read(s.key)
	s.attempts = map[string][]time.Time{}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		s.sync()
		select {
		case <-ctx.Done():
			s.stop()
			return
		case <-t.C:
		}
	}
}

// Wanted reports whether any CAPTCHA option is on.
func Wanted(st settings.Settings) bool {
	return st.Firewall.Enabled && (st.Firewall.Captcha || (st.IPDB.Enabled && st.IPDB.Captcha))
}

func (s *Server) sync() {
	st := s.Settings.Get()
	want := Wanted(st)
	ports := [2]int{st.Captcha.HTTPPort, st.Captcha.HTTPSPort}
	if s.running[0] != nil && (!want || ports != s.ports) {
		s.stop()
	}
	if !want || s.running[0] != nil {
		return
	}
	s.ports = ports
	plain := &http.Server{Addr: fmt.Sprintf(":%d", ports[0]), Handler: s, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second}
	secure := &http.Server{Addr: fmt.Sprintf(":%d", ports[1]), Handler: s, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs().Get}}
	s.running = [2]*http.Server{plain, secure}
	go func() {
		if err := plain.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Log.Warn("captcha http server", "err", err)
		}
	}()
	go func() {
		if err := secure.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Log.Warn("captcha https server", "err", err)
		}
	}()
	s.Log.Info("captcha server listening", "http", ports[0], "https", ports[1])
}

func (s *Server) certs() *CertStore {
	if s.Certs == nil {
		s.Certs = &CertStore{}
	}
	return s.Certs
}

func (s *Server) stop() {
	for i, srv := range s.running {
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			s.running[i] = nil
		}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// tooMany limits attempts per address (10 per 10 minutes).
func (s *Server) tooMany(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts == nil {
		s.attempts = map[string][]time.Time{}
	}
	cut := time.Now().Add(-10 * time.Minute)
	var keep []time.Time
	for _, t := range s.attempts[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, time.Now())
	s.attempts[ip] = keep
	if len(s.attempts) > 10000 { // bound memory under a flood
		s.attempts = map[string][]time.Time{ip: keep}
	}
	return len(keep) > 10
}

// ServeHTTP answers every path: the challenge page, the image and the answer.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	ip := clientIP(r)
	switch {
	case r.URL.Path == "/.xmartguard/captcha.png":
		s.image(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/.xmartguard/verify":
		s.verify(w, r, ip)
		return
	}
	s.page(w, r, ip, "")
}

// token binds a challenge answer to an address and an expiry.
func (s *Server) token(ip, answer string, exp int64) string {
	m := hmac.New(sha256.New, s.key)
	fmt.Fprintf(m, "%s|%s|%d", ip, answer, exp)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) newChallenge(ip string) (id string, digits string) {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	for i := range b {
		digits += strconv.Itoa(int(b[i]) % 10)
	}
	exp := time.Now().Add(5 * time.Minute).Unix()
	// The image is fetched by id; the id carries the digits sealed with the key.
	id = s.seal(ip, digits, exp)
	return id, digits
}

// seal encrypts digits for the image URL using a keystream derived from the
// server key (the id is opaque to the visitor).
func (s *Server) seal(ip, digits string, exp int64) string {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	ks := s.keystream(nonce, len(digits))
	ct := make([]byte, len(digits))
	for i := range digits {
		ct[i] = digits[i] ^ ks[i]
	}
	body := fmt.Sprintf("%s.%s.%d", base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(ct), exp)
	return body + "." + s.token(ip, body, exp)[:32]
}

func (s *Server) keystream(nonce []byte, n int) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("captcha-stream"))
	m.Write(nonce)
	sum := m.Sum(nil)
	for len(sum) < n {
		sum = append(sum, sum...)
	}
	return sum[:n]
}

// open returns the digits of a sealed id if it is valid for ip.
func (s *Server) open(ip, id string) (string, bool) {
	parts := strings.Split(id, ".")
	if len(parts) != 4 {
		return "", false
	}
	body := strings.Join(parts[:3], ".")
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	if !hmac.Equal([]byte(parts[3]), []byte(s.token(ip, body, exp)[:32])) {
		return "", false
	}
	nonce, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	ct, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(ct) > 8 {
		return "", false
	}
	ks := s.keystream(nonce, len(ct))
	out := make([]byte, len(ct))
	for i := range ct {
		out[i] = ct[i] ^ ks[i]
	}
	return string(out), true
}

func (s *Server) image(w http.ResponseWriter, r *http.Request) {
	digits, ok := s.open(clientIP(r), r.URL.Query().Get("id"))
	if !ok {
		http.Error(w, "expired", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_ = RenderPNG(w, digits)
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func (s *Server) verify(w http.ResponseWriter, r *http.Request, ip string) {
	if s.tooMany(ip) {
		s.page(w, r, ip, "Too many attempts. Please wait a few minutes and try again.")
		return
	}
	_ = r.ParseForm()
	cfg := s.Settings.Get().Captcha
	ok := false
	switch cfg.Provider {
	case "turnstile", "recaptcha":
		ok = s.verifyProvider(r.Context(), cfg, ip, r.PostForm)
	default:
		want, valid := s.open(ip, r.PostForm.Get("id"))
		// Challenges expire after 5 minutes; the attempt limit bounds guessing.
		ok = valid && want != "" && strings.TrimSpace(r.PostForm.Get("answer")) == want
	}
	if !ok {
		s.page(w, r, ip, "That was not right. Please try again.")
		return
	}
	if s.Solved != nil {
		if err := s.Solved(ip); err != nil {
			s.Log.Warn("captcha unblock failed", "ip", ip, "err", err)
			s.page(w, r, ip, "Your answer was correct, but the address could not be unblocked. Please contact the site owner.")
			return
		}
	}
	s.Log.Info("captcha solved; address allowed", "ip", ip)
	back := r.PostForm.Get("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
		back = "/"
	}
	// Close the redirected connection so the next request goes to the site.
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = doneTmpl.Execute(w, map[string]any{"Back": back, "Minutes": cfg.AllowMinutes})
}

func (s *Server) verifyProvider(ctx context.Context, cfg settings.Captcha, ip string, form url.Values) bool {
	endpoint := "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	field := "cf-turnstile-response"
	if cfg.Provider == "recaptcha" {
		endpoint, field = "https://www.google.com/recaptcha/api/siteverify", "g-recaptcha-response"
	}
	if s.VerifyURL != "" {
		endpoint = s.VerifyURL
	}
	resp := form.Get(field)
	if resp == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(url.Values{"secret": {cfg.SecretKey}, "response": {resp}, "remoteip": {ip}}.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := httpClient.Do(req)
	if err != nil {
		s.Log.Warn("captcha provider unreachable", "err", err)
		return false
	}
	defer res.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	return json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<16)).Decode(&out) == nil && out.Success
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, ip, msg string) {
	cfg := s.Settings.Get().Captcha
	back := r.URL.RequestURI()
	if r.Method == http.MethodPost {
		back = r.PostForm.Get("back")
	}
	if len(back) > 500 || strings.HasPrefix(back, "/.xmartguard/") {
		back = "/"
	}
	data := map[string]any{"IP": ip, "Msg": msg, "Back": back, "Provider": cfg.Provider, "SiteKey": cfg.SiteKey, "Host": r.Host}
	if cfg.Provider != "turnstile" && cfg.Provider != "recaptcha" {
		id, _ := s.newChallenge(ip)
		data["ID"] = id
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = pageTmpl.Execute(w, data)
}

var pageTmpl = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Security check</title>
{{if eq .Provider "turnstile"}}<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>{{end}}
{{if eq .Provider "recaptcha"}}<script src="https://www.google.com/recaptcha/api.js" async defer></script>{{end}}
<style>
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f5f9;color:#0f172a;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
.c{background:#fff;border-radius:14px;box-shadow:0 10px 30px #0f172a1a;max-width:420px;width:100%;padding:28px}
h1{font-size:20px;margin:0 0 8px;color:#1e2a5a}p{color:#475569;font-size:14px;line-height:1.5}
img{display:block;width:100%;max-width:260px;height:auto;border-radius:8px;border:1px solid #e2e8f0;margin:12px 0}
input[type=text]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:18px;letter-spacing:4px}
button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#1e2a5a;color:#fff;font-size:15px;cursor:pointer}
.e{background:#fef2f2;color:#991b1b;padding:8px 10px;border-radius:8px;font-size:13px}.f{margin-top:18px;font-size:12px;color:#94a3b8}
</style></head><body><div class="c">
<h1>Security check</h1>
<p>Your address <b>{{.IP}}</b> was temporarily blocked because of suspicious activity. Prove you are a person to continue to {{.Host}}.</p>
{{if .Msg}}<p class="e">{{.Msg}}</p>{{end}}
<form method="post" action="/.xmartguard/verify">
<input type="hidden" name="back" value="{{.Back}}">
{{if eq .Provider "turnstile"}}<div class="cf-turnstile" data-sitekey="{{.SiteKey}}"></div>
{{else if eq .Provider "recaptcha"}}<div class="g-recaptcha" data-sitekey="{{.SiteKey}}"></div>
{{else}}<input type="hidden" name="id" value="{{.ID}}">
<img src="/.xmartguard/captcha.png?id={{.ID}}" alt="Type the digits shown" width="260" height="90">
<input type="text" name="answer" inputmode="numeric" autocomplete="off" maxlength="8" placeholder="Digits in the image" required autofocus>{{end}}
<button type="submit">Continue</button>
</form>
<p class="f">Protected by XMart Guard</p>
</div></body></html>`))

var doneTmpl = template.Must(template.New("d").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3;url={{.Back}}"><title>Thank you</title>
<style>body{font-family:system-ui,sans-serif;background:#f1f5f9;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.c{background:#fff;border-radius:14px;padding:28px;max-width:420px;box-shadow:0 10px 30px #0f172a1a}</style></head>
<body><div class="c"><h2>Thank you</h2><p>Your address is allowed for the next {{.Minutes}} minutes. Taking you back…</p>
<p><a href="{{.Back}}">Continue</a></p></div></body></html>`))
