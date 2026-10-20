package mail

import (
	"bufio"
	"io"
	"os"
	"sort"
	"time"
)

// Outgoing mail summary: every sender's messages of the last 24 hours,
// whether or not it crossed a limit, so the page shows the monitor is
// watching (most servers never raise an event).

// statsWindow is how far back the summary counts.
const statsWindow = 24 * time.Hour

type senderStat struct {
	sender, source string
	user           string        // the cPanel account a local script ran as
	hours          map[int64]int // hour (unix/3600) -> messages
	rcpts          map[int64]int // hour -> recipients, pruned with hours
	last           time.Time
}

// SenderStat is one sender in the summary.
type SenderStat struct {
	Sender   string `json:"sender"`
	Source   string `json:"source"`
	User     string `json:"user"`
	Day      int    `json:"day"`      // messages in the last 24 hours
	Hour     int    `json:"hour"`     // in the last hour
	Rcpts    int    `json:"rcpts"`    // recipients in the last 24 hours
	LastAt   int64  `json:"last_at"`  // unix time of the last message
	Exceeded bool   `json:"exceeded"` // over a limit in the last hour
}

// Stats is the summary the portal shows above the events.
type Stats struct {
	Log         string       `json:"log"`
	LogFound    bool         `json:"log_found"`
	Enabled     bool         `json:"enabled"`
	PerMinute   int          `json:"per_minute"`
	PerHour     int          `json:"per_hour"`
	Since       int64        `json:"since"`   // counting since (agent start or the oldest line read)
	Total       int          `json:"total"`   // messages in the last 24 hours
	Senders     int          `json:"senders"` // senders in the last 24 hours
	LastMessage int64        `json:"last_message"`
	Top         []SenderStat `json:"top"`
}

// count adds a message to the summary (called with o.mu held).
func (o *Monitor) count(m Message, now time.Time) {
	if o.stats == nil {
		o.stats = map[string]*senderStat{}
	}
	k := m.senderKey()
	s := o.stats[k]
	if s == nil {
		s = &senderStat{sender: firstNonEmpty(m.Auth, m.Sender), hours: map[int64]int{}, rcpts: map[int64]int{}}
		o.stats[k] = s
	}
	s.source = m.Source()
	s.user = m.account()
	s.hours[now.Unix()/3600]++
	s.rcpts[now.Unix()/3600] += max(m.Rcpts, 1)
	if now.After(s.last) {
		s.last = now
	}
	if now.After(o.lastMsg) {
		o.lastMsg = now
	}
	// Forget what left the window (checked on a sample of messages).
	if len(o.stats)%64 == 0 {
		o.prune(now)
	}
}

func (o *Monitor) prune(now time.Time) {
	oldest := now.Add(-statsWindow).Unix() / 3600
	for k, s := range o.stats {
		for h := range s.hours {
			if h < oldest {
				delete(s.hours, h)
			}
		}
		for h := range s.rcpts {
			if h < oldest {
				delete(s.rcpts, h)
			}
		}
		if len(s.hours) == 0 {
			delete(o.stats, k)
		}
	}
	o.pruneLimits(now)
}

// Seed counts the messages of the last 24 hours already in the log, so the
// summary is complete right after the agent starts. It reads at most the
// last 64 MB.
func (o *Monitor) Seed(path string) {
	o.init()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 64<<20 {
		_, _ = f.Seek(st.Size()-64<<20, io.SeekStart)
	}
	from := time.Now().Add(-statsWindow)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	o.mu.Lock()
	defer o.mu.Unlock()
	for sc.Scan() {
		m, ok := ParseArrival(sc.Text())
		if !ok || m.At.Before(from) {
			continue
		}
		o.count(m, m.At)
		if o.since.IsZero() || m.At.Before(o.since) {
			o.since = m.At
		}
	}
}

// Summary returns the last 24 hours, busiest senders first.
func (o *Monitor) Summary(limit int) Stats {
	o.init()
	cfg := o.Settings.Get().OSM
	_, err := os.Stat(LogPath)
	st := Stats{Log: LogPath, LogFound: err == nil, Enabled: cfg.Enabled, PerMinute: cfg.PerMinute, PerHour: cfg.PerHour, Top: []SenderStat{}}
	now := time.Now()
	o.mu.Lock()
	o.prune(now)
	st.Since = o.since.Unix()
	if o.since.IsZero() {
		st.Since = o.started.Unix()
	}
	if !o.lastMsg.IsZero() {
		st.LastMessage = o.lastMsg.Unix()
	}
	hour := now.Unix() / 3600
	var all []SenderStat
	for _, s := range o.stats {
		x := SenderStat{Sender: s.sender, Source: s.source, User: s.user, LastAt: s.last.Unix()}
		for _, n := range s.rcpts {
			x.Rcpts += n
		}
		for h, n := range s.hours {
			x.Day += n
			if h == hour {
				x.Hour += n
			}
		}
		x.Exceeded = cfg.PerHour > 0 && x.Hour >= cfg.PerHour
		st.Total += x.Day
		all = append(all, x)
	}
	o.mu.Unlock()
	st.Senders = len(all)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Day != all[j].Day {
			return all[i].Day > all[j].Day
		}
		return all[i].Sender < all[j].Sender
	})
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(all) > limit {
		all = all[:limit]
	}
	for i := range all {
		if all[i].User == "" && o.Owner != nil {
			all[i].User = o.Owner(all[i].Sender)
		}
	}
	st.Top = append(st.Top, all...)
	return st
}
