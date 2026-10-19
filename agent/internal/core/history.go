package core

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Settings history: the settings before every change are kept (the last
// historyKeep), so a change that caused trouble at night is undone with
// one click in the morning, on one server or (from the portal) on all.

const historyKeep = 100

// patchSummary names the settings a change touches ("waf.level, scanner").
func patchSummary(p json.RawMessage) string {
	var top map[string]json.RawMessage
	if json.Unmarshal(p, &top) != nil {
		return "settings"
	}
	var parts []string
	for k, v := range top {
		var sub map[string]json.RawMessage
		if json.Unmarshal(v, &sub) == nil && len(sub) > 0 && len(sub) <= 4 {
			for sk := range sub {
				parts = append(parts, k+"."+sk)
			}
			continue
		}
		parts = append(parts, k)
	}
	sort.Strings(parts)
	s := strings.Join(parts, ", ")
	if len(s) > 300 {
		s = s[:297] + "..."
	}
	if s == "" {
		s = "settings"
	}
	return s
}

// recordSettings keeps the current settings before a change.
func (a *Agent) recordSettings(p json.RawMessage, summary string) {
	if summary == "" {
		summary = patchSummary(p)
	}
	before, err := json.Marshal(a.Settings.Get())
	if err != nil {
		return
	}
	_, _ = a.DB.Exec(`INSERT INTO settings_history (at, summary, before) VALUES (?,?,?)`, store.Now(), summary, string(before))
	_, _ = a.DB.Exec(`DELETE FROM settings_history WHERE id <= (SELECT max(id) FROM settings_history) - ?`, historyKeep)
}

// HistoryEntry is one settings change.
type HistoryEntry struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Summary string `json:"summary"`
}

func (a *Agent) settingsHistory(limit int) []HistoryEntry {
	rows, err := a.DB.Query(`SELECT id, at, summary FROM settings_history ORDER BY id DESC LIMIT ?`, min(max(limit, 1), historyKeep))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if rows.Scan(&e.ID, &e.At, &e.Summary) == nil {
			out = append(out, e)
		}
	}
	return out
}

// rollbackSettings puts back the settings as they were before change id,
// or before the first change at or after time before (the fleet rollback).
func (a *Agent) rollbackSettings(ctx context.Context, id, before int64) (any, error) {
	var raw string
	var at int64
	var err error
	if id > 0 {
		err = a.DB.QueryRow(`SELECT before, at FROM settings_history WHERE id = ?`, id).Scan(&raw, &at)
	} else {
		err = a.DB.QueryRow(`SELECT id, before, at FROM settings_history WHERE at >= ? ORDER BY id LIMIT 1`, before).Scan(&id, &raw, &at)
	}
	if err != nil {
		return nil, errors.New("no settings change to undo in that time")
	}
	return a.saveSettings(ctx, json.RawMessage(raw), "rollback: settings before change #"+itoa(id), true)
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (a *Agent) historyHandlers(h map[string]client.Handler) {
	h["settings.history"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"history": a.settingsHistory(historyKeep)}, nil
	}
	h["settings.rollback"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID     int64 `json:"id"`
			Before int64 `json:"before"`
		}](p)
		if err != nil {
			return nil, err
		}
		if in.ID <= 0 && in.Before <= 0 {
			return nil, errors.New("choose a change or a time")
		}
		return a.rollbackSettings(ctx, in.ID, in.Before)
	}
}
