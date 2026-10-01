package cms

import (
	"database/sql"
	"testing"
)

func TestChangedSince(t *testing.T) {
	v := func(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }
	none := sql.NullInt64{}
	const lastScan = 1000
	for _, c := range []struct {
		name                string
		tables, known       int
		last, started       sql.NullInt64
		wantChanged, wantOK bool
	}{
		{"a table changed after the last check", 3, 1, v(1500), v(100), true, true},
		{"all tables older than the last check", 3, 3, v(900), v(100), false, true},
		{"some unknown, MySQL up since before the check", 3, 1, v(500), v(100), false, true},
		{"none known, MySQL up since before the check", 3, 0, none, v(100), false, true},
		{"MySQL restarted after the last check", 3, 1, v(1200), v(1100), true, true},
		{"MySQL restarted, nothing known", 3, 0, none, v(1100), false, false},
		{"uptime unreadable", 3, 0, none, none, false, false},
		{"tables missing", 0, 0, none, v(100), false, false},
	} {
		ch, ok := changedSince(lastScan, c.tables, c.known, c.last, c.started)
		if ch != c.wantChanged || ok != c.wantOK {
			t.Errorf("%s: changed=%v ok=%v", c.name, ch, ok)
		}
	}
}
