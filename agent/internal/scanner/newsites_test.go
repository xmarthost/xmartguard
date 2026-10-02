package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A website added after the agent started (new account, addon domain,
// transfer, restore) gets its own low-speed "new" scan; the websites that
// were there first, and an addon domain inside a new one, do not.
func TestNewWebsiteScanned(t *testing.T) {
	s := newScanner(t)
	base := t.TempDir()
	old := filepath.Join(base, "old/public_html")
	os.MkdirAll(old, 0o755)
	list := filepath.Join(base, "userdatadomains")
	write := func(lines ...string) { os.WriteFile(list, []byte(strings.Join(lines, "\n")+"\n"), 0o644) }
	write("old.com: old==root==main==old.com==" + old + "==1.2.3.4:80==")
	oldList, oldDelay, oldPoll := userDataDomains, NewSiteDelay, NewSitePoll
	userDataDomains, NewSiteDelay, NewSitePoll = list, 0, 50*time.Millisecond
	defer func() { userDataDomains, NewSiteDelay, NewSitePoll = oldList, oldDelay, oldPoll }()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { s.WatchNewSites(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }() // before the package settings come back
	time.Sleep(200 * time.Millisecond)

	site := filepath.Join(base, "new/public_html")
	addon := filepath.Join(site, "addon.com")
	os.MkdirAll(addon, 0o755)
	os.WriteFile(filepath.Join(addon, "x.php"), []byte(malicious["exec.php"]), 0o644)
	time.Sleep(20 * time.Millisecond) // a newer mtime for the list
	write("old.com: old==root==main==old.com=="+old+"==1.2.3.4:80==",
		"new.com: new==root==main==new.com=="+site+"==1.2.3.4:80==",
		"addon.com: new==root==addon==new.com=="+addon+"==1.2.3.4:80==")
	var scans []Scan
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		scans, _ = s.ListScans(10)
		if len(scans) > 0 && scans[0].Status == "completed" {
			break
		}
	}
	if len(scans) != 1 {
		t.Fatalf("want one scan, got %+v", scans)
	}
	sc := scans[0]
	if sc.Kind != "new" || sc.Target != site || sc.Infected != 1 || !strings.Contains(sc.Initiator, "new") {
		t.Fatalf("%+v", sc)
	}
}
