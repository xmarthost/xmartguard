package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ml"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// PortalAI is the portal's AI gateway. Requests are signed with the agent's
// identity key, so only enrolled servers can use the portal's API keys.
type PortalAI struct {
	URL      string // portal base URL
	ServerID string
	Sign     func(msg []byte) string // base64 Ed25519 signature
	Client   *http.Client
}

// Signed envelope: the portal verifies
// Ed25519("xg-ai-v2:<server_id>:<ts>:<sha256(payload)>").
// Post sends a signed request to the portal and decodes the answer.
func (p *PortalAI) Post(ctx context.Context, path string, payload any, out any) error {
	return p.post(ctx, path, payload, out)
}

func (p *PortalAI) post(ctx context.Context, path string, payload any, out any) error {
	if p == nil || p.URL == "" || p.Sign == nil {
		return errors.New("this agent is not enrolled with a portal")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(raw)
	sig := p.Sign([]byte("xg-ai-v2:" + p.ServerID + ":" + ts + ":" + hex.EncodeToString(sum[:])))
	body, _ := json.Marshal(map[string]string{"server_id": p.ServerID, "ts": ts, "signature": sig, "payload": string(raw)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 4 * time.Minute}
	}
	res, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("portal unreachable: %w", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data[:min(len(data), 200)]))
		}
		return fmt.Errorf("portal AI: %s (HTTP %d)", e.Error, res.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// fileReq is one file sent to the portal.
type fileReq struct {
	ID        string   `json:"id"`
	SHA256    string   `json:"sha256"`
	Size      int64    `json:"size"`
	Name      string   `json:"name"`
	Match     string   `json:"match,omitempty"` // the local engine's detection, "" for a clean file
	Excerpt   string   `json:"excerpt"`
	Lines     int      `json:"lines"`
	Truncated bool     `json:"truncated"`
	Base      string   `json:"base,omitempty"` // built-in model version (for fleet training)
	Z         float64  `json:"z,omitempty"`    // its logit for this file
	Features  []uint32 `json:"features,omitempty"`
}

type fileResp struct {
	ID         string        `json:"id"`
	Verdict    string        `json:"verdict"`
	Confidence int           `json:"confidence"`
	Reason     string        `json:"reason"`
	Injected   bool          `json:"injected"`
	Cut        []scanner.Cut `json:"cut"`
	Model      string        `json:"model"`
	Source     string        `json:"source"` // ai | fleet
	Error      string        `json:"error"`
}

func (a *Analyzer) analyzePortal(ctx context.Context, jobs []Job, cfg settings.AI) ([]Verdict, error) {
	out := make([]Verdict, len(jobs))
	var files []fileReq
	var base *ml.Model
	if cfg.Learn {
		base, _ = ml.Base()
	}
	for i, j := range jobs {
		raw, err := os.ReadFile(j.Path)
		if err != nil {
			continue
		}
		text, lines, truncated := Excerpt(raw, cfg.MaxKB*1024)
		f := fileReq{ID: strconv.Itoa(i), SHA256: j.SHA256, Size: int64(len(raw)), Name: baseName(j.Path),
			Match: j.Signature, Excerpt: text, Lines: lines, Truncated: truncated}
		if base != nil {
			if len(raw) > ml.MaxBytes {
				raw = raw[:ml.MaxBytes]
			}
			f.Features = ml.Features(raw)
			f.Base, f.Z = base.Version, base.Logit(f.Features)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return out, errors.New("the files could not be read")
	}
	var res struct {
		Results []fileResp `json:"results"`
	}
	if err := a.Portal.post(ctx, "/api/agent/ai/judge", map[string]any{"files": files, "scope": cfg.Scope}, &res); err != nil {
		return out, err
	}
	var errs []string
	for _, r := range res.Results {
		i, err := strconv.Atoi(r.ID)
		if err != nil || i < 0 || i >= len(out) {
			continue
		}
		if r.Error != "" || (r.Verdict != Malicious && r.Verdict != Suspicious && r.Verdict != Clean) {
			if r.Error != "" {
				errs = append(errs, r.Error)
			}
			continue
		}
		src := r.Source
		if src == "" {
			src = "ai"
		}
		out[i] = Verdict{Verdict: r.Verdict, Confidence: r.Confidence, Reason: r.Reason, Model: r.Model,
			Injected: r.Injected && r.Verdict == Malicious, Cut: r.Cut, Source: src}
	}
	if len(errs) > 0 {
		return out, errors.New(errs[0])
	}
	return out, nil
}

// ------------------------------------------------------------------ fleet sync

// SyncInterval is how often fleet knowledge is fetched.
const SyncInterval = 10 * time.Minute

func deltaPath() string { return filepath.Join(store.StateDir(), "ai-delta.json") }

// LoadDelta applies the fleet model update saved by the last sync.
func LoadDelta() {
	raw, err := os.ReadFile(deltaPath())
	if err != nil {
		return
	}
	var d ml.Delta
	if json.Unmarshal(raw, &d) == nil {
		_ = ml.ApplyDelta(&d)
	}
}

// RunSync keeps fleet knowledge up to date until ctx ends.
func (a *Analyzer) RunSync(ctx context.Context) {
	LoadDelta()
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	for {
		if cfg := a.Settings.Get().AI; cfg.Enabled && cfg.Learn && a.Portal != nil {
			if n, err := a.Sync(ctx); err != nil {
				a.Log.Debug("AI fleet sync failed", "err", err)
			} else if n > 0 {
				a.Log.Info("AI fleet knowledge updated", "verdicts", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(SyncInterval):
		}
	}
}

// Sync fetches verdicts other servers' AI gave (and the fleet's model
// update) and returns how many verdicts were new.
func (a *Analyzer) Sync(ctx context.Context) (int, error) {
	base, err := ml.Base()
	if err != nil {
		return 0, err
	}
	cursor, _ := strconv.ParseInt(store.GetKV(a.DB, "ai_kb_cursor"), 10, 64)
	modelVer, _ := strconv.ParseInt(store.GetKV(a.DB, "ai_model_version"), 10, 64)
	total := 0
	for page := 0; page < 20; page++ {
		var res struct {
			KB []struct {
				SHA256     string `json:"sha256"`
				Size       int64  `json:"size"`
				Verdict    string `json:"verdict"`
				Confidence int    `json:"confidence"`
				Reason     string `json:"reason"`
				Model      string `json:"model"`
				Injected   bool   `json:"injected"`
			} `json:"kb"`
			Cursor int64     `json:"cursor"`
			More   bool      `json:"more"`
			Delta  *ml.Delta `json:"delta"`
		}
		if err := a.Portal.post(ctx, "/api/agent/ai/sync", map[string]any{"cursor": cursor, "base": base.Version, "model_version": modelVer}, &res); err != nil {
			return total, err
		}
		for _, k := range res.KB {
			if len(k.SHA256) != 64 {
				continue
			}
			Save(a.DB, Verdict{SHA256: strings.ToLower(k.SHA256), Verdict: k.Verdict, Confidence: k.Confidence, Reason: k.Reason,
				Model: k.Model, Injected: k.Injected, Source: "fleet", At: store.Now(), Size: k.Size})
		}
		total += len(res.KB)
		cursor = max(cursor, res.Cursor)
		_ = store.SetKV(a.DB, "ai_kb_cursor", strconv.FormatInt(cursor, 10))
		if res.Delta != nil && res.Delta.Version != modelVer {
			if err := ml.ApplyDelta(res.Delta); err == nil {
				modelVer = res.Delta.Version
				if b, err := json.Marshal(res.Delta); err == nil {
					_ = os.WriteFile(deltaPath(), b, 0o600)
				}
				_ = store.SetKV(a.DB, "ai_model_version", strconv.FormatInt(modelVer, 10))
				a.Log.Info("AI model updated from the fleet", "version", modelVer, "samples", res.Delta.Samples)
			}
		}
		if !res.More {
			break
		}
	}
	if total > 0 {
		if err := a.WriteLearned(); err != nil {
			return total, err
		}
	}
	return total, nil
}

// LearnedMinConfidence is how sure the AI must have been for a verdict to
// become a hash detection on every server.
const LearnedMinConfidence = 90

// WriteLearned regenerates the fleet-learned hash list the scanner loads.
func (a *Analyzer) WriteLearned() error {
	rows, err := a.DB.Query(`SELECT sha256, size FROM ai_verdicts WHERE verdict = 'malicious' AND confidence >= ? AND size > 0 AND source IN ('ai','fleet')`, LearnedMinConfidence)
	if err != nil {
		return err
	}
	var lines []string
	for rows.Next() {
		var sha string
		var size int64
		if rows.Scan(&sha, &size) == nil {
			lines = append(lines, fmt.Sprintf("%d %s %s", size, sha, scanner.LearnedLabel))
		}
	}
	rows.Close()
	sort.Strings(lines)
	p := scanner.LearnedHashPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p+".tmp", []byte("# XMart Guard: files the fleet's AI found malicious\n"+strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(p+".tmp", p); err != nil {
		return err
	}
	scanner.ReloadHashDB()
	return nil
}
