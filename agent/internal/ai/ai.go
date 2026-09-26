// Package ai gives suspicious files a second opinion ("AI scanner").
//
// Providers:
//   - builtin (default): XMart Guard's own model (package ml), free, runs
//     locally, nothing leaves the server;
//   - ollama: a free LLM the administrator hosts (e.g. on the portal server);
//   - anthropic: Claude through the Anthropic API with the administrator's
//     own (paid) key.
//
// Verdicts are cached by SHA-256, so each distinct file is judged once.
package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"

	"github.com/xmarthost/xmartguard/agent/internal/ml"
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

// Verdict is the model's opinion of one file.
type Verdict struct {
	SHA256     string `json:"sha256"`
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason"`
	Model      string `json:"model"`
	At         int64  `json:"at"`
}

// Job asks for a verdict on one finding.
type Job struct {
	FindingID int64
	Path      string
	SHA256    string
	Signature string // what the local engine matched
}

// Analyzer runs jobs one at a time with an hourly cap.
type Analyzer struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	// OnVerdict is called after a new verdict (to apply actions).
	OnVerdict func(Job, Verdict)
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
	// PerHour caps API calls (default 120).
	PerHour int

	queue chan Job
	once  sync.Once
	mu    sync.Mutex
	sent  []time.Time
}

func (a *Analyzer) init() {
	a.once.Do(func() { a.queue = make(chan Job, 500) })
}

// Enqueue schedules a job; it never blocks (a full queue drops the job,
// which is retried on the next scan of the file).
func (a *Analyzer) Enqueue(j Job) {
	a.init()
	if !a.Settings.Get().AI.Enabled || j.SHA256 == "" {
		return
	}
	select {
	case a.queue <- j:
	default:
	}
}

// Run processes the queue until ctx ends.
func (a *Analyzer) Run(ctx context.Context) {
	a.init()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-a.queue:
			if !a.Settings.Get().AI.Enabled {
				continue
			}
			if v, ok := Cached(a.DB, j.SHA256); ok && v.Verdict != Error {
				continue
			}
			if a.Settings.Get().AI.Provider != "builtin" && !a.allow() {
				a.Log.Warn("AI scanner hourly limit reached; skipping", "path", j.Path)
				continue
			}
			v, err := a.Analyze(ctx, j)
			if err != nil {
				a.Log.Warn("AI scan failed", "path", j.Path, "err", err)
				continue
			}
			if a.OnVerdict != nil {
				a.OnVerdict(j, v)
			}
		}
	}
}

func (a *Analyzer) allow() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	limit := a.PerHour
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
	err := db.QueryRow(`SELECT verdict, confidence, reason, model, at FROM ai_verdicts WHERE sha256 = ?`, sha).
		Scan(&v.Verdict, &v.Confidence, &v.Reason, &v.Model, &v.At)
	return v, err == nil
}

func save(db *sql.DB, v Verdict) {
	_, _ = db.Exec(`INSERT INTO ai_verdicts (sha256, verdict, confidence, reason, model, at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence,
		reason = excluded.reason, model = excluded.model, at = excluded.at`, v.SHA256, v.Verdict, v.Confidence, v.Reason, v.Model, v.At)
}

const systemPrompt = `You are the malware analyst of a web hosting security product. You receive one file from a
customer's website that a signature engine flagged, and you decide whether it is malicious.

Judge what the code does, not how it looks: minified or encoded code in plugins and themes is often
legitimate; eval of decoded data, remote code download and execution, hidden file managers or shells,
credential or card skimming, SEO spam injection, mailers used for spam, cryptominers and backdoors that
take commands from request parameters are malicious. Library code, installers and admin tools of known
CMS projects are usually clean.

Answer with the verdict, a confidence from 0 to 100, and one or two sentences of reason that name the
behaviour you found (for example "decodes a base64 payload from a POST parameter and passes it to eval").
Do not quote long code. The file may be truncated; say so if it limits your judgement.`

var schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"verdict":    map[string]any{"type": "string", "enum": []string{Malicious, Suspicious, Clean}},
		"confidence": map[string]any{"type": "integer"},
		"reason":     map[string]any{"type": "string"},
	},
	"required":             []string{"verdict", "confidence", "reason"},
	"additionalProperties": false,
}

// sample returns the text sent for a file: all of it when it fits,
// otherwise the beginning and the end (where injected code usually sits),
// marked as truncated.
func sample(raw []byte, maxKB int) (string, bool) {
	limit := maxKB * 1024
	if len(raw) <= limit {
		return strings.ToValidUTF8(string(raw), "?"), false
	}
	head := raw[:limit*3/4]
	tail := raw[len(raw)-limit/4:]
	for len(head) > 0 && !utf8.Valid(head[len(head)-3:]) {
		head = head[:len(head)-1]
	}
	return strings.ToValidUTF8(string(head), "?") +
		fmt.Sprintf("\n\n[... %d bytes omitted ...]\n\n", len(raw)-len(head)-len(tail)) +
		strings.ToValidUTF8(string(tail), "?"), true
}

// Analyze judges one file with the configured provider and stores the verdict.
func (a *Analyzer) Analyze(ctx context.Context, j Job) (Verdict, error) {
	cfg := a.Settings.Get().AI
	var v Verdict
	var err error
	switch cfg.Provider {
	case "ollama":
		v, err = a.analyzeOllama(ctx, j, cfg)
	case "anthropic":
		v, err = a.analyzeClaude(ctx, j, cfg)
	default:
		v, err = analyzeBuiltin(j)
	}
	if err != nil {
		return Verdict{}, err
	}
	v.SHA256, v.At = j.SHA256, store.Now()
	v.Confidence, v.Reason = clamp(v.Confidence), truncate(v.Reason, 600)
	save(a.DB, v)
	return v, nil
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
	v := Verdict{Verdict: m.Verdict(sc), Model: "builtin " + m.Version}
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

// prompt builds the user message sent to an LLM provider.
func prompt(j Job, maxKB int) (string, error) {
	raw, err := os.ReadFile(j.Path)
	if err != nil {
		return "", err
	}
	text, truncated := sample(raw, maxKB)
	note := ""
	if truncated {
		note = fmt.Sprintf(" The file is %d bytes; only its beginning and end are included.", len(raw))
	}
	return fmt.Sprintf("File name: %s\nLocal engine match: %s.%s\n\n<file>\n%s\n</file>", baseName(j.Path), j.Signature, note, text), nil
}

type llmAnswer struct {
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason"`
}

func (x llmAnswer) valid() bool {
	return x.Verdict == Malicious || x.Verdict == Suspicious || x.Verdict == Clean
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// analyzeOllama asks a self-hosted Ollama server (free, no data leaves the
// administrator's infrastructure).
func (a *Analyzer) analyzeOllama(ctx context.Context, j Job, cfg settings.AI) (Verdict, error) {
	user, err := prompt(j, cfg.MaxKB)
	if err != nil {
		return Verdict{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"model":    cfg.Model,
		"stream":   false,
		"format":   schema,
		"options":  map[string]any{"temperature": 0},
		"messages": []map[string]string{{"role": "system", "content": systemPrompt}, {"role": "user", "content": user}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.OllamaURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("Ollama unreachable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 500))
		return Verdict{}, fmt.Errorf("Ollama error %d: %s", res.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return Verdict{}, err
	}
	var ans llmAnswer
	if json.Unmarshal([]byte(out.Message.Content), &ans) != nil || !ans.valid() {
		return Verdict{}, errors.New("unexpected answer from the Ollama model")
	}
	return Verdict{Verdict: ans.Verdict, Confidence: ans.Confidence, Reason: ans.Reason, Model: "ollama " + cfg.Model}, nil
}

// analyzeClaude asks Claude through the Anthropic API (paid, own key).
func (a *Analyzer) analyzeClaude(ctx context.Context, j Job, cfg settings.AI) (Verdict, error) {
	if cfg.APIKey == "" {
		return Verdict{}, errors.New("no Anthropic API key configured")
	}
	user, err := prompt(j, cfg.MaxKB)
	if err != nil {
		return Verdict{}, err
	}

	opts := []option.RequestOption{option.WithAPIKey(cfg.APIKey), option.WithMaxRetries(2)}
	if a.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(a.BaseURL))
	}
	client := anthropic.NewClient(opts...)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	params := anthropic.BetaMessageNewParams{
		Model:     cfg.Model,
		MaxTokens: 4096,
		System:    []anthropic.BetaTextBlockParam{{Text: systemPrompt}},
		Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user))},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortMedium,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
	}
	// Malware analysis can trip the model's cyber-safety classifier; the
	// server-side fallback lets another model answer instead of a refusal.
	if cfg.Model == "claude-opus-5" || cfg.Model == "claude-fable-5-1" {
		params.Fallbacks = anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()}
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}
	msg, err := client.Beta.Messages.New(cctx, params)
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case 401, 403:
				return Verdict{}, errors.New("the Anthropic API key was rejected")
			case 429:
				return Verdict{}, errors.New("Anthropic API rate limit reached; try again later")
			}
			return Verdict{}, fmt.Errorf("Anthropic API error %d", apiErr.StatusCode)
		}
		return Verdict{}, err
	}
	v := Verdict{Model: string(msg.Model)}
	if msg.StopReason == "refusal" {
		v.Verdict, v.Reason = Error, "the model declined to analyse this file"
		return v, nil
	}
	var out llmAnswer
	var body strings.Builder
	for _, b := range msg.Content {
		if t, ok := b.AsAny().(anthropic.BetaTextBlock); ok {
			body.WriteString(t.Text)
		}
	}
	if err := json.Unmarshal([]byte(body.String()), &out); err != nil || !out.valid() {
		return Verdict{}, fmt.Errorf("unexpected answer (stop reason %s)", msg.StopReason)
	}
	v.Verdict, v.Confidence, v.Reason = out.Verdict, out.Confidence, out.Reason
	return v, nil
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
