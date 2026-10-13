package captcha

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Requests a CAPTCHA can not help with. The firewall sends all web traffic
// of a banned or IPDB-listed address here; like other server firewalls,
// only a person in a browser is asked to solve the check:
//
//   - files machines read (robots.txt, sitemaps, ads.txt, /.well-known/ with
//     the SSL certificate checks, favicon) are served by the website itself,
//     so search consoles, sitemap readers and certificate renewals keep
//     working even from an address on a blocklist;
//   - other requests that are not a browser opening a page (scripts, API
//     calls, form posts, images) get a plain 403, not a redirect to a
//     CAPTCHA page nobody will see.

// machinePath matches the files served from the website (GET/HEAD only).
var machinePath = regexp.MustCompile(`(?i)^/(?:robots\.txt|ads\.txt|app-ads\.txt|security\.txt|humans\.txt|favicon\.ico|[^/]*sitemap[^/]*\.(?:xml|xml\.gz|txt|php)|\.well-known/.*)$`)

// MachinePath reports whether a path is served from the website.
func MachinePath(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && machinePath.MatchString(r.URL.Path)
}

// BrowserPage reports whether the request is a browser opening a page: a
// GET or HEAD that accepts HTML (scripts and API clients send */* or JSON).
func BrowserPage(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

type origDstKey struct{}

// connContext remembers where a redirected connection was going (the
// website's address and port), for serving machine files from the site.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if ap, ok := originalDst(c); ok {
		return context.WithValue(ctx, origDstKey{}, ap)
	}
	return ctx
}

// originalDst reads SO_ORIGINAL_DST of a connection the firewall
// redirected (iptables REDIRECT and nftables redirect both keep it).
func originalDst(c net.Conn) (netip.AddrPort, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, false
	}
	var out netip.AddrPort
	found := false
	local, _ := tc.LocalAddr().(*net.TCPAddr)
	_ = raw.Control(func(fd uintptr) {
		if local != nil && local.IP.To4() == nil {
			// IP6T_SO_ORIGINAL_DST: a sockaddr_in6, read through a struct of the same size.
			info, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, 80)
			if err != nil {
				return
			}
			b := unsafePointer(&info.Addr)[:]
			var a [16]byte
			copy(a[:], b[8:24])
			out, found = netip.AddrPortFrom(netip.AddrFrom16(a), binary.BigEndian.Uint16(b[2:4])), true
			return
		}
		// SO_ORIGINAL_DST: a sockaddr_in, read through a struct of the same size.
		m, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, 80)
		if err != nil {
			return
		}
		b := m.Multiaddr[:]
		var a [4]byte
		copy(a[:], b[4:8])
		out, found = netip.AddrPortFrom(netip.AddrFrom4(a), binary.BigEndian.Uint16(b[2:4])), true
	})
	return out, found && out.Port() != 0
}

// serveFromSite answers a machine-file request with the website's own
// response: the request goes to the address the visitor connected to,
// from this server (local traffic is not redirected again).
func serveFromSite(w http.ResponseWriter, r *http.Request) bool {
	dst, ok := r.Context().Value(origDstKey{}).(netip.AddrPort)
	if !ok || (dst.Port() != 80 && dst.Port() != 443) {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.Out.URL.Scheme = scheme
			p.Out.URL.Host = dst.String()
			p.Out.Host = r.Host
			p.SetXForwarded()
		},
		Transport: &http.Transport{
			// The site's own certificate is for its name, not the address.
			TLSClientConfig:       &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // this server's own website
			ResponseHeaderTimeout: 15 * time.Second,
			DisableKeepAlives:     true,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "The website did not answer.", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
	return true
}

// blockedText is the answer to requests that are not a browser page.
func blockedText(w http.ResponseWriter, ip string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("403 Forbidden: the address " + ip + " is blocked by this server's firewall (xPGuard).\n" +
		"Open the website in a browser to unblock it, or ask the website's hosting provider to allow this address.\n"))
}

func unsafePointer(p *unix.RawSockaddrInet6) *[28]byte { return (*[28]byte)(unsafe.Pointer(p)) }
