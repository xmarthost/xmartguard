package captcha

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// The portal's check on the website's own address (settings CentralMode
// "site"). The WAF sends a suspicious visitor of a login page to
// https://<site>:<CAPTCHA port>/.xpguard/gate, and the firewall sends banned
// visitors to this server too. The page here shows the portal's check in a
// frame that fills the whole window. The portal checks the answer, records
// it, and gives this server a ticket for the visitor (captcha.ticket). The
// page then trades the ticket for the pass cookie the WAF accepts, so a pass
// needs no web server reload.

// ticketTTL is how long a ticket from the portal waits to be used.
const ticketTTL = 10 * time.Minute

type ticket struct {
	ip  string
	exp time.Time
}

var reNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)

// AddTicket records the portal's word that the visitor at ip solved the
// check opened with nonce.
func (s *Server) AddTicket(nonce, ip string) bool {
	if !reNonce.MatchString(nonce) || net.ParseIP(ip) == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil || len(s.tickets) > 20_000 {
		s.tickets = map[string]ticket{}
	}
	now := time.Now()
	for k, t := range s.tickets {
		if now.After(t.exp) {
			delete(s.tickets, k)
		}
	}
	s.tickets[nonce] = ticket{ip: net.ParseIP(ip).String(), exp: now.Add(ticketTTL)}
	return true
}

// useTicket takes the ticket for nonce if it is for ip and still valid.
func (s *Server) useTicket(nonce, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[nonce]
	if !ok {
		return false
	}
	delete(s.tickets, nonce)
	p := net.ParseIP(ip)
	return p != nil && t.ip == p.String() && time.Now().Before(t.exp)
}

// sitePage is the page on the website's address: the portal's check in a
// frame without border that fills the window.
func (s *Server) sitePage(w http.ResponseWriter, r *http.Request, ip, back string, status int) {
	c := s.Settings.Get().Captcha
	u, err := url.Parse(c.CentralURL)
	host := r.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if err != nil || u.Scheme != "https" || u.Host == "" || s.ServerID == "" || net.ParseIP(ip) == nil || host == "" || strings.ContainsAny(host, "/?#@&= ") {
		blockedText(w, ip)
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	origin := u.Scheme + "://" + u.Host
	// The page ("u") goes last and as it is: the portal reads everything
	// after "&u=".
	src := c.CentralURL + "?s=" + url.QueryEscape(s.ServerID) + "&ip=" + url.QueryEscape(ip) + "&h=" + url.QueryEscape(host) +
		"&n=" + nonce + "&frame=1&u=" + safeBack(back)
	pass := passURL(host, c, r.TLS != nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-src "+origin+"; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' "+pass+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = siteTmpl.Execute(w, map[string]any{"Src": template.URL(src), "Origin": origin, "Nonce": nonce, "Back": safeBack(back), "Pass": pass})
}

// passURL is where the page trades the ticket: this server's CAPTCHA HTTPS
// port, never the website's own port. A visitor the firewall sends here
// still holds the browser's earlier connection to the website (HTTP/2),
// while this server closes its own after every answer; a "/.xpguard/pass"
// on the page's own port went over the old connection to the website,
// whose WAF refused it (an IPDB-listed POST), so the visitor solved the
// check again and again and never got in (business200, 2026-10-23). The
// pass cookie has no port, so the website gets it all the same.
func passURL(host string, c settings.Captcha, secure bool) string {
	// The page's own scheme: a cookie from the other one is another site's
	// for the browser.
	scheme, port := "https", c.HTTPSPort
	if !secure {
		scheme, port = "http", c.HTTPPort
	}
	if port <= 0 {
		port = map[bool]int{true: 7743, false: 7780}[secure]
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + pathPrefix + "pass"
}

// allowSiteOrigin lets the page on the website's own port read the pass
// answer (and keep the cookie): only that website's own pages.
func allowSiteOrigin(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	u, err := url.Parse(o)
	if o == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" {
		return
	}
	host := r.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	if !strings.EqualFold(u.Hostname(), strings.Trim(host, "[]")) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", o)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")
}

// sitePass trades the portal's ticket for the pass cookie and sends the
// visitor back to the page it wanted.
func (s *Server) sitePass(w http.ResponseWriter, r *http.Request, ip string) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	_ = r.ParseForm()
	allowSiteOrigin(w, r)
	w.Header().Set("Content-Type", "application/json")
	if !s.useTicket(r.PostForm.Get("n"), ip) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "The check could not be confirmed. Please reload the page."})
		return
	}
	tok := ""
	if s.Passes != nil {
		tok = s.Passes.Give(ip, time.Now())
	}
	if tok == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "The check is not available right now. Please try again later."})
		return
	}
	minutes := s.Settings.Get().Captcha.CentralMinutes
	if minutes <= 0 {
		minutes = 720
	}
	// Not Secure: a website without HTTPS reads it too (the value is
	// recorded with this address; see SitePasses).
	http.SetCookie(w, &http.Cookie{Name: GateCookie, Value: tok, Path: "/", MaxAge: minutes * 60, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if s.Passed != nil {
		s.Passed(ip)
	}
	s.Log.Info("captcha solved on the website's address", "ip", ip, "host", r.Host)
	_ = json.NewEncoder(w).Encode(map[string]string{"redirect": siteURL(r, safeBack(r.PostForm.Get("back")))})
}

var siteTmpl = template.Must(template.New("s").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Security check</title>
<style>html,body{margin:0;height:100%;background:#f8fafc}iframe{position:fixed;inset:0;width:100%;height:100%;border:0;display:block}</style>
</head><body><iframe src="{{.Src}}" title="Security check"></iframe>
<script>
var N={{.Nonce}},O={{.Origin}},B={{.Back}},P={{.Pass}};
window.addEventListener('message',function(e){
  if(e.origin!==O||!e.data||e.data.xg!=='pass'||e.data.n!==N)return;
  var f=e.source;
  fetch(P,{method:'POST',mode:'cors',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'n='+encodeURIComponent(N)+'&back='+encodeURIComponent(B)})
  .then(function(r){return r.json()})
  .then(function(j){if(j.redirect){f.postMessage({xg:'back'},O);location.replace(j.redirect)}else{f.postMessage({xg:'error',error:j.error||''},O)}})
  .catch(function(){f.postMessage({xg:'error',error:''},O)});
});
</script></body></html>`))
