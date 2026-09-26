package reputation

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

type mapResolver map[string][]string

func (m mapResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestDomainReputation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ud := filepath.Join(dir, "userdomains")
	os.WriteFile(ud, []byte("clean.example: alice\nphish.example: bob\nspam.example: carol\n*: nobody\nsb.example: dave\n"), 0o644)
	domains := HostedDomains(ud)
	if len(domains) != 4 || domains["phish.example"] != "bob" {
		t.Fatalf("domains %v", domains)
	}
	r := mapResolver{
		"phish.example.multi.surbl.org": {"127.0.0.8"},
		"spam.example.dbl.spamhaus.org": {"127.0.1.2"},
		// A "query refused" answer must not count as a listing.
		"clean.example.dbl.spamhaus.org": {"127.255.255.254"},
		"clean.example.multi.uribl.com":  {"127.0.0.1"},
	}
	sb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		if req.URL.Query().Get("key") != "k123" || !strings.Contains(string(b), "sb.example") {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"matches":[{"threatType":"SOCIAL_ENGINEERING","threat":{"url":"http://sb.example/"}}]}`)
	}))
	defer sb.Close()
	SafeBrowsingURL = sb.URL
	res, err := CheckDomains(context.Background(), db, r, domains, "k123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range res {
		got[x.Domain] = x.Status + ":" + strings.Join(x.Reasons, ",")
	}
	want := map[string]string{
		"clean.example": "clean:",
		"phish.example": "listed:PHISHING (SURBL)",
		"spam.example":  "listed:SPAM (Spamhaus DBL)",
		"sb.example":    "listed:SOCIAL_ENGINEERING (Google Safe Browsing)",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	sum, rows, total, err := LoadDomains(db, "", 25, 0)
	if err != nil || sum.Total != 4 || sum.Flagged != 3 || total != 4 || rows[0].Status != "listed" || len(sum.Listed) != 3 {
		t.Fatalf("summary %+v rows %+v %v", sum, rows, err)
	}
}
