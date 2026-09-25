package reputation

import (
	"context"
	"net"
	"testing"
)

func TestQuery(t *testing.T) {
	q, _ := Query("74.50.90.186", "zen.spamhaus.org")
	if q != "186.90.50.74.zen.spamhaus.org" {
		t.Fatal(q)
	}
	q, _ = Query("2001:db8::1", "x.org")
	if q != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.x.org" {
		t.Fatal(q)
	}
	if _, err := Query("nope", "x"); err == nil {
		t.Fatal("bad ip accepted")
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestCheck(t *testing.T) {
	r := fakeResolver{
		"4.3.2.1.listed.example":  {"127.0.0.2"},
		"4.3.2.1.refused.example": {"127.255.255.254"},
	}
	rep := Check(context.Background(), r, "1.2.3.4", []string{"listed.example", "clean.example", "refused.example"})
	if rep.ListedOn != 1 || rep.Checked != 2 {
		t.Fatalf("%+v", rep)
	}
	if !rep.Results[0].Listed || rep.Results[1].Listed || rep.Results[2].Error == "" {
		t.Fatalf("%+v", rep.Results)
	}
}
