package mail

import (
	"context"
	"strings"
	"testing"
)

func TestSyncGreylistTrusted(t *testing.T) {
	old := WHMAPI
	t.Cleanup(func() { WHMAPI = old })
	var created []string
	WHMAPI = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "read_cpgreylist_trusted_hosts":
			return []byte(`{"metadata":{"result":1},"data":{"ip_blocks":[{"ip_low":"162.220.160.0","ip_high":"162.220.160.15","comment":"MailBaby"}]}}`), nil
		case "create_cpgreylist_trusted_host":
			created = append(created, strings.Join(args[1:], " "))
			return []byte(`{"metadata":{"result":1}}`), nil
		}
		t.Fatalf("unexpected call %v", args)
		return nil, nil
	}
	n, err := SyncGreylistTrusted(context.Background(), map[string][]string{"MailBaby (mail relay)": {"162.220.160.0/28", "67.217.53.0/24", "bad"}})
	if err != nil || n != 1 {
		t.Fatalf("added %d, err %v", n, err)
	}
	// The network already trusted (added by hand from the guide) is not added twice.
	if len(created) != 1 || created[0] != "ip=67.217.53.0/24 comment=MailBaby (mail relay) (xPGuard)" {
		t.Fatalf("created %q", created)
	}
	if lo, hi, _ := cidrRange("66.45.233.16/29"); lo.String() != "66.45.233.16" || hi.String() != "66.45.233.23" {
		t.Fatalf("range %s-%s", lo, hi)
	}
}
