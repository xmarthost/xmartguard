package firewall

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Blocked-connection kinds, from the kernel log prefix.
var logKinds = map[string]string{
	LogPrefixIPDB:    "ipdb",
	LogPrefixDeny:    "deny",
	LogPrefixTempBan: "tempban",
	LogPrefixCountry: "country",
}

// ConnEvent is one sampled dropped connection.
type ConnEvent struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Kind    string `json:"kind"`
	Src     string `json:"src"`
	SrcPort int    `json:"src_port"`
	Dst     string `json:"dst"`
	DstPort int    `json:"dst_port"`
	Proto   string `json:"proto"`
	Country string `json:"country"`
	Entry   string `json:"entry"`
}

// ParseKernelLog extracts a dropped connection from a kernel log message
// written by our LOG/log rules ("XG-IPDB IN=eth0 ... SRC=a DST=b ... SPT=1 DPT=2").
func ParseKernelLog(msg string) (ConnEvent, bool) {
	var ev ConnEvent
	i := strings.Index(msg, "XG-")
	if i < 0 {
		return ev, false
	}
	msg = msg[i:]
	for prefix, kind := range logKinds {
		if strings.HasPrefix(msg, prefix) {
			ev.Kind = kind
			break
		}
	}
	if ev.Kind == "" {
		return ev, false
	}
	for _, f := range strings.Fields(msg) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "SRC":
			ev.Src = v
		case "DST":
			ev.Dst = v
		case "PROTO":
			ev.Proto = v
		case "SPT":
			ev.SrcPort, _ = strconv.Atoi(v)
		case "DPT":
			ev.DstPort, _ = strconv.Atoi(v)
		}
	}
	if _, err := netip.ParseAddr(ev.Src); err != nil {
		return ev, false
	}
	return ev, true
}

// KmsgPath is the kernel log device (overridable in tests).
var KmsgPath = "/dev/kmsg"

// RunConnLog reads dropped-connection samples from the kernel log and stores
// them for the live monitors. It returns quietly when /dev/kmsg is missing
// (containers).
func (m *Manager) RunConnLog(ctx context.Context) {
	f, err := os.Open(KmsgPath)
	if err != nil {
		m.Log.Info("kernel log unavailable; live connection monitor disabled", "err", err)
		return
	}
	defer f.Close()
	// Start at the end: /dev/kmsg supports SEEK_END to skip old records.
	_, _ = f.Seek(0, io.SeekEnd)
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	events := make(chan ConnEvent, 1024)
	go m.storeConnEvents(ctx, events)
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, syscall.EPIPE) { // records were overwritten; keep reading
				continue
			}
			time.Sleep(time.Second)
			continue
		}
		rec := string(buf[:n])
		if !strings.Contains(rec, "XG-") {
			continue
		}
		// Record format: "prio,seq,usec,flags;message\n"
		if _, msg, ok := strings.Cut(rec, ";"); ok {
			if ev, ok := ParseKernelLog(msg); ok {
				ev.At = store.Now()
				select {
				case events <- ev:
				default:
				}
			}
		}
	}
}

func (m *Manager) storeConnEvents(ctx context.Context, events <-chan ConnEvent) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var batch []ConnEvent
	lastPrune := time.Now()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := m.DB.Begin()
		if err != nil {
			batch = batch[:0]
			return
		}
		for _, ev := range batch {
			if m.IPDB != nil && ev.Kind == "ipdb" {
				ev.Entry, ev.Country = m.IPDB.Lookup(ev.Src)
			}
			_, _ = tx.Exec(`INSERT INTO conn_log (at, kind, src, src_port, dst, dst_port, proto, country, entry) VALUES (?,?,?,?,?,?,?,?,?)`,
				ev.At, ev.Kind, ev.Src, ev.SrcPort, ev.Dst, ev.DstPort, ev.Proto, ev.Country, ev.Entry)
		}
		_ = tx.Commit()
		batch = batch[:0]
		if time.Since(lastPrune) > 10*time.Minute {
			lastPrune = time.Now()
			_, _ = m.DB.Exec(`DELETE FROM conn_log WHERE at < ? OR id < (SELECT coalesce(max(id),0) - 200000 FROM conn_log)`, store.Now()-7*86400)
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-events:
			batch = append(batch, ev)
			if len(batch) >= 500 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// ConnFilter narrows ConnEvents.
type ConnFilter struct {
	Kind   string `json:"kind"`
	Query  string `json:"q"`
	Since  int64  `json:"since_id"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// ConnEvents lists sampled dropped connections, newest first.
func (m *Manager) ConnEvents(f ConnFilter) ([]ConnEvent, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.Kind != "" {
		where, args = append(where, "kind = ?"), append(args, f.Kind)
	}
	if f.Query != "" {
		where, args = append(where, "(src LIKE ? OR dst LIKE ? OR country = ?)"), append(args, "%"+f.Query+"%", "%"+f.Query+"%", strings.ToUpper(f.Query))
	}
	if f.Since > 0 {
		where, args = append(where, "id > ?"), append(args, f.Since)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM conn_log WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, at, kind, src, src_port, dst, dst_port, proto, country, entry FROM conn_log WHERE `+cond+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ConnEvent{}
	for rows.Next() {
		var e ConnEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Src, &e.SrcPort, &e.Dst, &e.DstPort, &e.Proto, &e.Country, &e.Entry); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// dropStats turns cumulative per-rule counters into per-minute rows.
type dropStats struct {
	mu   sync.Mutex
	last map[string]uint64
}

var commentKind = map[string]string{"xg-ipdb": "ipdb", "xg-deny": "deny", "xg-tempban": "tempban", "xg-country": "country", "xg-dos": "dos"}

func (d *dropStats) record(db *sql.DB, counters map[string]uint64, now int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = map[string]uint64{}
	}
	minute := now - now%60
	for comment, cur := range counters {
		kind := commentKind[comment]
		if kind == "" {
			continue
		}
		prev, seen := d.last[comment]
		d.last[comment] = cur
		if !seen {
			continue // first sample only sets the baseline
		}
		delta := cur
		if cur >= prev {
			delta = cur - prev
		}
		if delta == 0 {
			continue
		}
		_, _ = db.Exec(`INSERT INTO drop_stats (minute, kind, packets) VALUES (?,?,?)
			ON CONFLICT(minute, kind) DO UPDATE SET packets = packets + excluded.packets`, minute, kind, delta)
	}
	_, _ = db.Exec(`DELETE FROM drop_stats WHERE minute < ?`, now-35*86400)
}

// TimePoint is one bucket of a drop timeline.
type TimePoint struct {
	At      int64 `json:"at"`
	Packets int64 `json:"packets"`
}

// DropTimeline returns packets dropped per bucket (seconds) since `from`,
// optionally for one kind, with empty buckets filled in.
func (m *Manager) DropTimeline(kind string, from, bucket int64) []TimePoint {
	now := store.Now()
	from -= from % bucket
	q, args := `SELECT (minute / ?) * ? AS b, sum(packets) FROM drop_stats WHERE minute >= ?`, []any{bucket, bucket, from}
	if kind != "" {
		q, args = q+` AND kind = ?`, append(args, kind)
	}
	got := map[int64]int64{}
	if rows, err := m.DB.Query(q+` GROUP BY b`, args...); err == nil {
		for rows.Next() {
			var b, n int64
			if rows.Scan(&b, &n) == nil {
				got[b] = n
			}
		}
		rows.Close()
	}
	out := []TimePoint{}
	for b := from; b <= now; b += bucket {
		out = append(out, TimePoint{At: b, Packets: got[b]})
	}
	return out
}

// DropTotals sums dropped packets per kind since `from`.
func (m *Manager) DropTotals(from int64) map[string]int64 {
	out := map[string]int64{}
	rows, err := m.DB.Query(`SELECT kind, sum(packets) FROM drop_stats WHERE minute >= ? GROUP BY kind`, from)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if rows.Scan(&k, &n) == nil {
			out[k] = n
		}
	}
	return out
}
