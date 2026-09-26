// Package ai gives files a second opinion ("AI scanner").
//
// Providers:
//   - builtin (default): XMart Guard's own model (package ml), free, runs
//     locally, nothing leaves the server;
//   - portal: the portal asks the free AI APIs configured there (Google
//     Gemini, Groq, OpenRouter, ...), fails over between keys and providers
//     when one hits its limit, and shares every verdict with all linked
//     servers.
//
// With "learn" on, the agent also uses the fleet's knowledge: files any
// server's AI found malicious are detected here by hash at once, and the
// built-in model receives the update the portal trained from the AI's
// verdicts (see Sync).
//
// Verdicts are cached by SHA-256, so each distinct file is judged once.
package ai

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ml"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Verdicts.
const (
	Malicious  = "malicious"
	Suspicious = "suspicious"
	Clean      = "clean"
	Error      = "error"
)

// Verdict is the AI's opinion of one file.
type Verdict struct {
	SHA256     string `json:"sha256"`
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason"`
	Model      string `json:"model"`
	At         int64  `json:"at"`
	// Injected: malicious code was added to an otherwise legitimate file;
	// Cut says where (for Trim).
	Injected bool          `json:"injected,omitempty"`
	Cut      []scanner.Cut `json:"cut,omitempty"`
	// Source: builtin | ai (asked now) | fleet (another server's verdict)
	// | fallback (built-in model while the portal AI was unavailable).
	Source string `json:"source"`
	Size   int64  `json:"-"`
}

// Job asks for a verdict on one file.
type Job struct {
	FindingID int64 // 0 for a clean file checked in "all files" mode
	Path      string
	SHA256    string
	Signature string // what the local engine matched
}

// Analyzer runs jobs in the background.
type Analyzer struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	// OnVerdict is called after a new verdict (to apply actions).
	OnVerdict func(Job, Verdict)
	// Portal describes the portal's AI gateway (provider "portal").
	Portal *PortalAI

	queue chan Job
	once  sync.Once
	mu    sync.Mutex
	sent  []time.Time
}

func (a *Analyzer) init() {
	a.once.Do(func() { a.queue = make(chan Job, 1000) })
}

// Enqueue schedules a job; it never blocks (a full queue drops the job,
// which is retried on the next scan of the file).
func (a *Analyzer) Enqueue(j Job) {
	a.init()
	if !a.Settings.Get().AI.Enabled || j.Path == "" {
		return
	}
	select {
	case a.queue <- j:
	default:
	}
}

// EnqueueNew schedules a clean new/changed code file ("all files" mode).
func (a *Analyzer) EnqueueNew(path string) {
	cfg := a.Settings.Get().AI
	if cfg.Provider != "portal" || cfg.Scope != "all" {
		return
	}
	a.Enqueue(Job{Path: path})
}

const batchMax = 6

// Run processes the queue until ctx ends. Jobs arriving within a couple of
// seconds are sent together: one request for several files uses fewer
// requests (the free tiers' scarcest limit) and one copy of the instructions.
func (a *Analyzer) Run(ctx context.Context) {
	a.init()
	for {
		var batch []Job
		select {
		case <-ctx.Done():
			return
		case j := <-a.queue:
			batch = append(batch, j)
		}
		wait := time.After(2 * time.Second)
	gather:
		for len(batch) < batchMax {
			select {
			case j := <-a.queue:
				batch = append(batch, j)
			case <-wait:
				break gather
			case <-ctx.Done():
				return
			}
		}
		a.process(ctx, batch)
	}
}

func (a *Analyzer) process(ctx context.Context, batch []Job) {
	cfg := a.Settings.Get().AI
	if !cfg.Enabled {
		return
	}
	var todo []Job
	for _, j := range batch {
		if j.SHA256 == "" {
			j.SHA256 = fileSHA(j.Path)
			if j.SHA256 == "" {
				continue
			}
		}
		if v, ok := Cached(a.DB, j.SHA256); ok && v.Verdict != Error && (v.Source != "fallback" || cfg.Provider != "portal") {
			// Known content: act on the stored verdict (a new detection of a
			// file the fleet already judged, or known malware reappearing).
			if a.OnVerdict != nil && (j.FindingID != 0 || v.Verdict == Malicious) {
				a.OnVerdict(j, v)
			}
			continue
		}
		if j.FindingID == 0 && !a.allow(cfg.MaxPerHour) {
			continue
		}
		todo = append(todo, j)
	}
	if len(todo) == 0 {
		return
	}
	verdicts, err := a.AnalyzeBatch(ctx, todo)
	if err != nil {
		a.Log.Warn("AI scan failed", "files", len(todo), "err", err)
	}
	for i, v := range verdicts {
		if v.Verdict != "" && a.OnVerdict != nil {
			a.OnVerdict(todo[i], v)
		}
	}
}

// allow enforces the hourly cap on clean files sent in "all files" mode.
func (a *Analyzer) allow(limit int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit <= 0 {
		limit = 120
	}
	cut := time.Now().Add(-time.Hour)
	keep := a.sent[:0]
	for _, t := range a.sent {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	a.sent = keep
	if len(a.sent) >= limit {
		return false
	}
	a.sent = append(a.sent, time.Now())
	return true
}

// Cached returns a stored verdict for a file hash.
func Cached(db *sql.DB, sha string) (Verdict, bool) {
	v := Verdict{SHA256: sha}
	var cut string
	var injected int
	err := db.QueryRow(`SELECT verdict, confidence, reason, model, at, injected, cut, source, size FROM ai_verdicts WHERE sha256 = ?`, sha).
		Scan(&v.Verdict, &v.Confidence, &v.Reason, &v.Model, &v.At, &injected, &cut, &v.Source, &v.Size)
	if err != nil {
		return v, false
	}
	v.Injected = injected == 1
	if cut != "" {
		_ = json.Unmarshal([]byte(cut), &v.Cut)
	}
	return v, true
}

// Save stores a verdict.
func Save(db *sql.DB, v Verdict) {
	cut := ""
	if len(v.Cut) > 0 {
		b, _ := json.Marshal(v.Cut)
		cut = string(b)
	}
	injected := 0
	if v.Injected {
		injected = 1
	}
	_, _ = db.Exec(`INSERT INTO ai_verdicts (sha256, verdict, confidence, reason, model, at, injected, cut, source, size) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence, reason = excluded.reason,
		model = excluded.model, at = excluded.at, injected = excluded.injected, cut = excluded.cut, source = excluded.source,
		size = CASE WHEN excluded.size > 0 THEN excluded.size ELSE ai_verdicts.size END`,
		v.SHA256, v.Verdict, v.Confidence, v.Reason, v.Model, v.At, injected, cut, v.Source, v.Size)
	noteCleared(db, v)
}

// Analyze judges one file now (the "Check with AI" button).
func (a *Analyzer) Analyze(ctx context.Context, j Job) (Verdict, error) {
	if j.SHA256 == "" {
		j.SHA256 = fileSHA(j.Path)
	}
	vs, err := a.AnalyzeBatch(ctx, []Job{j})
	if len(vs) == 1 && vs[0].Verdict != "" {
		return vs[0], nil
	}
	if err == nil {
		err = errors.New("no verdict")
	}
	return Verdict{}, err
}

// AnalyzeBatch judges files with the configured provider and stores the
// verdicts. The result is parallel to jobs; a job without a verdict has an
// empty Verdict field.
func (a *Analyzer) AnalyzeBatch(ctx context.Context, jobs []Job) ([]Verdict, error) {
	cfg := a.Settings.Get().AI
	out := make([]Verdict, len(jobs))
	var err error
	if cfg.Provider == "portal" {
		out, err = a.analyzePortal(ctx, jobs, cfg)
		// Findings still get the built-in model's opinion while the portal
		// AI is unavailable; it is asked again later.
		for i, v := range out {
			if v.Verdict == "" && jobs[i].FindingID != 0 {
				if b, berr := analyzeBuiltin(jobs[i]); berr == nil {
					b.Source = "fallback"
					out[i] = b
				}
			}
		}
	} else {
		for i, j := range jobs {
			v, berr := analyzeBuiltin(j)
			if berr != nil {
				err = berr
				continue
			}
			out[i] = v
		}
	}
	for i := range out {
		if out[i].Verdict == "" {
			continue
		}
		out[i].SHA256, out[i].At = jobs[i].SHA256, store.Now()
		out[i].Confidence, out[i].Reason = clamp(out[i].Confidence), truncate(out[i].Reason, 600)
		if st, serr := os.Stat(jobs[i].Path); serr == nil {
			out[i].Size = st.Size()
		}
		Save(a.DB, out[i])
	}
	return out, err
}

func analyzeBuiltin(j Job) (Verdict, error) {
	m, err := ml.Default()
	if err != nil {
		return Verdict{}, err
	}
	raw, err := readHead(j.Path)
	if err != nil {
		return Verdict{}, err
	}
	sc := m.Score(raw)
	v := Verdict{Verdict: m.Verdict(sc), Model: "builtin " + m.Version, Source: "builtin"}
	if v.Verdict == Clean {
		v.Confidence = int((1 - sc) * 100)
		v.Reason = fmt.Sprintf("Model score %.0f%%: the code looks like ordinary application code.", sc*100)
	} else {
		v.Confidence = int(sc * 100)
		v.Reason = fmt.Sprintf("Model score %.0f%%. Strongest indicators: %s.", sc*100, strings.Join(m.Explain(raw, 5), ", "))
	}
	return v, nil
}

func readHead(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, ml.MaxBytes))
}

func fileSHA(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func clamp(n int) int {
	return max(0, min(100, n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// SourceAdmin marks content an administrator restored from quarantine on
// this server: it is not flagged again here while it is unchanged (a
// changed file has another hash and is scanned normally). Unlike "clear"
// (false positive), it is not shared with other servers.
const SourceAdmin = "admin"

// ClearMinConfidence is how sure the AI must be that a file is clean before
// it is restored from quarantine and never flagged again.
const ClearMinConfidence = 90

// cleared caches the SHA-256 of files the AI (on any server) or an
// administrator found clean, for the scanner's per-file check.
var cleared struct {
	mu  sync.RWMutex
	db  *sql.DB
	set map[string]bool
}

func isClearedVerdict(v Verdict) bool {
	return v.Verdict == Clean && v.Confidence >= ClearMinConfidence && (v.Source == "ai" || v.Source == "fleet" || v.Source == SourceAdmin)
}

func loadCleared(db *sql.DB) {
	set := map[string]bool{}
	rows, err := db.Query(`SELECT sha256 FROM ai_verdicts WHERE verdict = 'clean' AND confidence >= ? AND source IN ('ai','fleet','admin')`, ClearMinConfidence)
	if err == nil {
		for rows.Next() {
			var s string
			if rows.Scan(&s) == nil {
				set[s] = true
			}
		}
		rows.Close()
	}
	cleared.db, cleared.set = db, set
}

// IsCleared reports whether content with this SHA-256 was found clean.
func IsCleared(db *sql.DB, sha string) bool {
	cleared.mu.RLock()
	if cleared.db == db && cleared.set != nil {
		ok := cleared.set[sha]
		cleared.mu.RUnlock()
		return ok
	}
	cleared.mu.RUnlock()
	cleared.mu.Lock()
	defer cleared.mu.Unlock()
	if cleared.db != db || cleared.set == nil {
		loadCleared(db)
	}
	return cleared.set[sha]
}

func noteCleared(db *sql.DB, v Verdict) {
	cleared.mu.Lock()
	defer cleared.mu.Unlock()
	if cleared.db != db || cleared.set == nil {
		return // loaded on first use
	}
	if isClearedVerdict(v) {
		cleared.set[v.SHA256] = true
	} else {
		delete(cleared.set, v.SHA256)
	}
}
