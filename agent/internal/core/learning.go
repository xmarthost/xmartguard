package core

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// learning.sample gives the portal's "xPGuard Learning" exports a picture
// of this server for a time window that fits in a small file: every WAF
// rule and every detection signature with its count, and a few examples
// of each (different sites and files first), so one noisy rule or
// signature cannot fill the export. Examples of detections carry the
// AI's opinion and, for pattern rules, the matched lines.

type sampleWAFGroup struct {
	RuleID int    `json:"rule_id"`
	Msg    string `json:"msg"`
	Action string `json:"action"`
	Count  int    `json:"count"`
	IPs    int    `json:"ips"`
	Hosts  int    `json:"hosts"`
}

type sampleWAFEvent struct {
	At       int64  `json:"at"`
	IP       string `json:"ip"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	URI      string `json:"uri"`
	RuleID   int    `json:"rule_id"`
	Msg      string `json:"msg"`
	Category string `json:"category"`
	Action   string `json:"action"`
	User     string `json:"user"`
	Detail   string `json:"detail"`
}

type sampleSigGroup struct {
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	Count     int    `json:"count"`
	Files     int    `json:"files"`
}

type sampleFinding struct {
	scanner.Finding
	MatchLine int    `json:"match_line,omitempty"`
	Matched   string `json:"matched,omitempty"`
}

type learningSample struct {
	Server     map[string]any   `json:"server"`
	Since      int64            `json:"since"`
	WAFGroups  []sampleWAFGroup `json:"waf_groups,omitempty"`
	WAFEvents  []sampleWAFEvent `json:"waf_events,omitempty"`
	SigGroups  []sampleSigGroup `json:"sig_groups,omitempty"`
	Detections []sampleFinding  `json:"detections,omitempty"`
}

func (a *Agent) learningSample(ctx context.Context, kind string, hours, perGroup, maxRows int) (learningSample, error) {
	hours = min(max(hours, 1), 24*14)
	perGroup = min(max(perGroup, 1), 200)
	maxRows = min(max(maxRows, 10), 50000)
	cfg := a.Settings.Get()
	host, _ := os.Hostname()
	out := learningSample{Since: store.Now() - int64(hours)*3600, Server: map[string]any{
		"hostname": host, "version": version.Version,
		"waf_enabled": cfg.WAF.Enabled, "waf_level": cfg.WAF.Level, "waf_auto_exclusions": cfg.WAF.AutoExclusions,
		"virus_action": cfg.Scanner.VirusAction, "suspicious_action": cfg.Scanner.SuspiciousAction, "binary_action": cfg.Scanner.BinaryAction,
		"ai_provider": cfg.AI.Provider,
	}}
	if kind == "waf" {
		return out, a.sampleWAF(ctx, &out, perGroup, maxRows)
	}
	return out, a.sampleDetections(ctx, &out, perGroup, maxRows)
}

func (a *Agent) sampleWAF(ctx context.Context, out *learningSample, perGroup, maxRows int) error {
	rows, err := a.DB.QueryContext(ctx, `SELECT rule_id, count(*), count(DISTINCT ip), count(DISTINCT host),
		coalesce((SELECT msg FROM waf_events w2 WHERE w2.rule_id = w.rule_id AND w2.at >= ? ORDER BY id DESC LIMIT 1), ''),
		coalesce((SELECT action FROM waf_events w3 WHERE w3.rule_id = w.rule_id AND w3.at >= ? ORDER BY id DESC LIMIT 1), '')
		FROM waf_events w WHERE at >= ? GROUP BY rule_id ORDER BY count(*) DESC`, out.Since, out.Since, out.Since)
	if err != nil {
		return err
	}
	for rows.Next() {
		var g sampleWAFGroup
		if rows.Scan(&g.RuleID, &g.Count, &g.IPs, &g.Hosts, &g.Msg, &g.Action) == nil {
			out.WAFGroups = append(out.WAFGroups, g)
		}
	}
	rows.Close()
	per := perGroupFor(len(out.WAFGroups), perGroup, maxRows)
	for _, g := range out.WAFGroups {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Different sites and addresses first: the latest of each.
		r, err := a.DB.QueryContext(ctx, `SELECT at, ip, method, host, uri, rule_id, msg, category, action, user, detail FROM waf_events
			WHERE id IN (SELECT max(id) FROM waf_events WHERE rule_id = ? AND at >= ? GROUP BY host, ip) ORDER BY id DESC LIMIT ?`,
			g.RuleID, out.Since, per)
		if err != nil {
			return err
		}
		for r.Next() {
			var e sampleWAFEvent
			if r.Scan(&e.At, &e.IP, &e.Method, &e.Host, &e.URI, &e.RuleID, &e.Msg, &e.Category, &e.Action, &e.User, &e.Detail) == nil {
				out.WAFEvents = append(out.WAFEvents, e)
			}
		}
		r.Close()
	}
	return nil
}

func (a *Agent) sampleDetections(ctx context.Context, out *learningSample, perGroup, maxRows int) error {
	rows, err := a.DB.QueryContext(ctx, `SELECT signature, category, status, count(*), count(DISTINCT sha256) FROM findings
		WHERE updated_at >= ? GROUP BY signature, category, status ORDER BY count(*) DESC`, out.Since)
	if err != nil {
		return err
	}
	sigs := map[string]bool{}
	var order []string
	for rows.Next() {
		var g sampleSigGroup
		if rows.Scan(&g.Signature, &g.Category, &g.Status, &g.Count, &g.Files) == nil {
			out.SigGroups = append(out.SigGroups, g)
			if !sigs[g.Signature] {
				sigs[g.Signature] = true
				order = append(order, g.Signature)
			}
		}
	}
	rows.Close()
	per := perGroupFor(len(order), perGroup, maxRows)
	for _, sig := range order {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Different file contents and accounts first.
		r, err := a.DB.QueryContext(ctx, `SELECT id FROM findings WHERE id IN (SELECT max(id) FROM findings WHERE signature = ? AND updated_at >= ?
			GROUP BY sha256, owner) ORDER BY id DESC LIMIT ?`, sig, out.Since, per)
		if err != nil {
			return err
		}
		var ids []int64
		for r.Next() {
			var id int64
			if r.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		r.Close()
		for _, id := range ids {
			f, err := a.Scanner.Get(id)
			if err != nil {
				continue
			}
			sf := sampleFinding{Finding: f}
			sf.MatchLine, sf.Matched = a.matchedLines(id, f.Signature)
			out.Detections = append(out.Detections, sf)
		}
	}
	return nil
}

// perGroupFor spreads maxRows over the groups (at least one each).
func perGroupFor(groups, perGroup, maxRows int) int {
	if groups == 0 {
		return perGroup
	}
	return max(1, min(perGroup, maxRows/groups))
}

// matchedLines returns the lines a pattern rule matched (heuristic
// detections have no single match and return nothing).
func (a *Agent) matchedLines(id int64, sig string) (int, string) {
	p, _, err := a.Scanner.ContentPath(id)
	if err != nil {
		return 0, ""
	}
	fh, err := os.Open(p)
	if err != nil {
		return 0, ""
	}
	defer fh.Close()
	b, _ := io.ReadAll(io.LimitReader(fh, 2<<20))
	line, snip := scanner.Locate(strings.TrimPrefix(sig, "Archive."), b)
	if len(snip) > 1500 {
		snip = snip[:1500]
	}
	return line, snip
}

func (a *Agent) learningHandlers(h map[string]client.Handler) {
	h["learning.sample"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Kind     string `json:"kind"`
			Hours    int    `json:"hours"`
			PerGroup int    `json:"per_group"`
			MaxRows  int    `json:"max_rows"`
		}](p)
		if err != nil {
			return nil, err
		}
		return a.learningSample(ctx, in.Kind, in.Hours, in.PerGroup, in.MaxRows)
	}
}
