package mail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The page shows every sender of the last 24 hours, not only those over a
// limit, and the summary is complete right after the agent starts.
func TestOutgoingSummary(t *testing.T) {
	m, _ := newMonitor(t)
	m.Settings.Patch([]byte(`{"osm":{"enabled":false}}`)) // counted even when the limits are off
	now := time.Now()
	stamp := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02 15:04:05") }
	var log []string
	for i := 0; i < 3; i++ {
		log = append(log, fmt.Sprintf(`%s 1x9hqp-00000007%04d-1Ug8 <= sales@shop.example H=(pc) [203.0.113.5]:52100 P=esmtpsa A=dovecot_login:sales@shop.example S=2201 T="Offer" for a@x.example b@y.example`, stamp(time.Duration(i)*time.Minute), i))
	}
	log = append(log,
		fmt.Sprintf(`%s 1x9hqp-000000079999-1Ug8 <= info@clinic.example U=clinicuser P=local S=900 T="Hello" for z@q.example`, stamp(2*time.Hour)),
		// Older than a day, and incoming mail: not counted.
		fmt.Sprintf(`%s 1x9hqp-000000078888-1Ug8 <= old@shop.example H=(pc) [203.0.113.5]:52100 P=esmtpsa A=dovecot_login:old@shop.example S=1 T="x" for a@x.example`, stamp(30*time.Hour)),
		fmt.Sprintf(`%s 1x9hqp-000000077777-1Ug8 <= news@remote.example H=mail.remote.example [198.51.100.9]:25 P=esmtps S=5000 T="News" for me@local.example`, stamp(time.Minute)),
	)
	p := filepath.Join(t.TempDir(), "exim_mainlog")
	os.WriteFile(p, []byte(strings.Join(log, "\n")+"\n"), 0o640)
	m.Seed(p)
	m.Observe(Message{At: now, ID: "1x9hqp-live", Sender: "sales@shop.example", Auth: "sales@shop.example", Rcpts: 1})

	s := m.Summary(10)
	if s.Total != 5 || s.Senders != 2 {
		t.Fatalf("total %d senders %d: %+v", s.Total, s.Senders, s.Top)
	}
	top := s.Top[0]
	if top.Sender != "sales@shop.example" || top.Day != 4 || top.Hour < 1 || top.Rcpts != 7 || top.Source != "Authenticated User" {
		t.Fatalf("top sender %+v", top)
	}
	if s.Top[1].Source != "Local user clinicuser" || s.Top[1].Day != 1 {
		t.Fatalf("second sender %+v", s.Top[1])
	}
	if s.Enabled || s.LastMessage == 0 || s.Since == 0 {
		t.Fatalf("summary %+v", s)
	}
}
