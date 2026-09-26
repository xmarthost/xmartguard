package mail

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestParseArrival(t *testing.T) {
	cases := []struct {
		line         string
		ok           bool
		auth, localU string
		ip, subject  string
		rcpts        int
	}{
		{`2026-09-24 16:42:01 1x9hqp-000000076Qy-1Ug8 <= ihtisham@pegasusfirms.example H=(laptop) [203.0.113.5]:52100 P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=no A=dovecot_login:ihtisham@pegasusfirms.example S=2201 id=abc@x T="Invoice for September" for a@x.example b@y.example`,
			true, "ihtisham@pegasusfirms.example", "", "203.0.113.5", "Invoice for September", 2},
		{`2026-09-22 16:44:00 1x8yvQ-0000000AutD-1xus <= info@clinic.example U=clinicuser P=local S=900 T="BUY NOW CHEAP OFFERS TODAY" for z@q.example`,
			true, "", "clinicuser", "", "BUY NOW CHEAP OFFERS TODAY", 1},
		// Incoming mail from the internet: not counted.
		{`2026-09-22 16:44:00 1x8yvQ-0000000AutE-1xus <= news@remote.example H=mail.remote.example [198.51.100.9]:25 P=esmtps S=5000 T="Newsletter" for me@local.example`, false, "", "", "", "", 0},
		// Bounces.
		{`2026-09-22 16:44:00 1x8yvQ-0000000AutF-1xus <= <> R=1x8 U=mailnull P=local S=1200 T="Mail delivery failed" for a@b.example`, false, "", "", "", "", 0},
		{`2026-09-22 16:44:00 1x8yvQ-0000000AutF-1xus => a@b.example R=dkim_lookuphost T=dkim_remote_smtp`, false, "", "", "", "", 0},
	}
	for _, c := range cases {
		m, ok := ParseArrival(c.line)
		if ok != c.ok {
			t.Errorf("ok=%v for %s", ok, c.line)
			continue
		}
		if !ok {
			continue
		}
		if m.Auth != c.auth || m.LocalU != c.localU || m.IP != c.ip || m.Subject != c.subject || m.Rcpts != c.rcpts {
			t.Errorf("got %+v", m)
		}
	}
}

func TestSubjectIssue(t *testing.T) {
	if SubjectIssue("BUY NOW CHEAP OFFERS TODAY", nil) == "" {
		t.Error("all caps not flagged")
	}
	if SubjectIssue("OK", nil) != "" || SubjectIssue("Invoice INV-2026", nil) != "" {
		t.Error("normal subject flagged")
	}
	if SubjectIssue("Your wallet verification", []string{"wallet verif"}) == "" {
		t.Error("pattern not flagged")
	}
}

func newMonitor(t *testing.T) (*Monitor, *[]string) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	var calls []string
	m := &Monitor{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Owner:  func(s string) string { return "pegasus" },
		WHMAPI: func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil },
	}
	return m, &calls
}

func TestThresholdsAndActions(t *testing.T) {
	m, calls := newMonitor(t)
	m.Settings.Patch([]byte(`{"osm":{"per_minute":5,"per_hour":8,"action":"hold"}}`))
	base := time.Date(2026, 9, 24, 16, 0, 0, 0, time.Local)
	send := func(i int, at time.Time) {
		m.Observe(Message{At: at, ID: fmt.Sprintf("1x-%04d", i), Sender: "ihtisham@pegasusfirms.example", Auth: "ihtisham@pegasusfirms.example", Subject: "Hello"})
	}
	// 6 in the same minute: per-minute threshold (5) fires once.
	for i := 0; i < 6; i++ {
		send(i, base.Add(time.Duration(i)*time.Second))
	}
	evs, total, _ := m.Events(EventFilter{})
	if total != 1 || evs[0].Interval != "5/m" || evs[0].User != "pegasus" || evs[0].Action != "outgoing mail held" {
		t.Fatalf("events %+v", evs)
	}
	if len(*calls) != 1 || (*calls)[0] != "hold_outgoing_email user=pegasus" {
		t.Fatalf("whmapi calls %v", *calls)
	}
	// Spread over the hour: crossing 8/h fires the hourly event.
	for i := 6; i < 10; i++ {
		send(i, base.Add(time.Duration(i)*5*time.Minute))
	}
	_, total, _ = m.Events(EventFilter{})
	if total != 2 {
		t.Fatalf("want hourly event, total %d", total)
	}
	// Whitelisted senders are ignored.
	m.Settings.Patch([]byte(`{"osm":{"whitelist_senders":["bulk@news.example"]}}`))
	for i := 0; i < 20; i++ {
		m.Observe(Message{At: base.Add(2 * time.Hour), ID: "x", Sender: "bulk@news.example", Auth: "bulk@news.example"})
	}
	if _, total, _ = m.Events(EventFilter{}); total != 2 {
		t.Fatalf("whitelisted sender flagged: %d", total)
	}
}

func TestScriptSourceAndSubject(t *testing.T) {
	m, _ := newMonitor(t)
	m.Settings.Patch([]byte(`{"osm":{"per_minute":3,"per_hour":100}}`))
	base := time.Date(2026, 9, 22, 16, 44, 0, 0, time.Local)
	for i := 0; i < 3; i++ {
		m.Observe(Message{At: base.Add(time.Duration(i) * time.Second), ID: fmt.Sprint("1x8yvQ-", i), Sender: "info@clinic.example",
			LocalU: "clinicuser", CWD: "/home/clinicuser/public_html/wp-content/uploads", Subject: "BUY NOW CHEAP OFFERS TODAY"})
	}
	evs, _, _ := m.Events(EventFilter{})
	if len(evs) != 1 || !strings.HasPrefix(evs[0].Source, "Script /home/clinicuser/public_html") || !strings.Contains(evs[0].Remarks, "ALL CAPS") || evs[0].Action != "notified" {
		t.Fatalf("%+v", evs)
	}
	if n, _ := m.Delete([]int64{evs[0].ID}); n != 1 {
		t.Fatal("delete")
	}
}
