package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// Cut is one piece of injected code to remove: whole lines From..To
// (1-based, inclusive), or only Text when it is set (From == To) and the
// rest of that line is legitimate.
type Cut struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	Text string `json:"text,omitempty"`
}

// ApplyCuts removes the cuts from content and returns the result and the
// number of bytes removed.
func ApplyCuts(content []byte, cuts []Cut) ([]byte, int, error) {
	if len(cuts) == 0 {
		return nil, 0, errors.New("nothing to trim")
	}
	lines := bytes.SplitAfter(content, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	sorted := append([]Cut(nil), cuts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].From > sorted[j].From })
	removed, lastFrom := 0, len(lines)+1
	for _, c := range sorted {
		if c.To == 0 {
			c.To = c.From
		}
		if c.From < 1 || c.To < c.From || c.To > len(lines) {
			return nil, 0, fmt.Errorf("line range %d-%d is outside the file (%d lines)", c.From, c.To, len(lines))
		}
		if c.To >= lastFrom {
			return nil, 0, errors.New("overlapping line ranges")
		}
		lastFrom = c.From
		if c.Text != "" {
			if c.From != c.To {
				return nil, 0, errors.New("a partial cut must stay on one line")
			}
			line := lines[c.From-1]
			i := bytes.Index(line, []byte(c.Text))
			if i < 0 {
				return nil, 0, fmt.Errorf("the code to remove was not found on line %d", c.From)
			}
			lines[c.From-1] = append(append([]byte(nil), line[:i]...), line[i+len(c.Text):]...)
			removed += len(c.Text)
			continue
		}
		for i := c.From - 1; i < c.To; i++ {
			removed += len(lines[i])
		}
		lines = append(lines[:c.From-1], lines[c.To:]...)
	}
	return bytes.Join(lines, nil), removed, nil
}

// phpTagBalance is the number of PHP open tags minus close tags in b.
func phpTagBalance(b []byte) int {
	l := bytes.ToLower(b)
	return bytes.Count(l, []byte("<?php")) + bytes.Count(l, []byte("<?=")) - bytes.Count(l, []byte("?>"))
}

// refineCuts keeps PHP tags balanced. Injected code is often a complete
// "<?php ... ?>" block glued in front of the file's own "<?php" on line 1;
// deleting that whole line would turn the rest of the file into plain text
// that is sent to visitors. Such a line cut becomes a cut of just the
// injected block; any other cut that would unbalance the tags is refused.
func refineCuts(content []byte, cuts []Cut) ([]Cut, error) {
	lines := bytes.SplitAfter(content, []byte("\n"))
	out := make([]Cut, 0, len(cuts))
	for _, c := range cuts {
		if c.To == 0 {
			c.To = c.From
		}
		if c.From < 1 || c.To < c.From || c.To > len(lines) {
			out = append(out, c) // ApplyCuts reports the range error
			continue
		}
		var removed []byte
		if c.Text != "" {
			removed = []byte(c.Text)
		} else {
			removed = bytes.Join(lines[c.From-1:c.To], nil)
		}
		if phpTagBalance(removed) == 0 {
			out = append(out, c)
			continue
		}
		if c.Text == "" && c.From == c.To {
			line := lines[c.From-1]
			if i := bytes.Index(line, []byte("?>")); i >= 0 {
				block := line[:i+2]
				if phpTagBalance(block) == 0 && len(bytes.TrimSpace(line[i+2:])) > 0 {
					out = append(out, Cut{From: c.From, To: c.To, Text: string(block)})
					continue
				}
			}
		}
		return nil, fmt.Errorf("removing lines %d-%d would break the file's PHP tags", c.From, c.To)
	}
	return out, nil
}

// phpBinary finds a PHP CLI for syntax checks (cPanel ships several).
func phpBinary() string {
	if p, err := exec.LookPath("php"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/local/bin/php", "/usr/bin/php"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if m, _ := filepath.Glob("/opt/cpanel/ea-php*/root/usr/bin/php"); len(m) > 0 {
		sort.Strings(m)
		return m[len(m)-1]
	}
	return ""
}

func isPHP(name string) bool {
	switch extOf(name) {
	case ".php", ".phtml", ".inc", ".php5", ".php7", ".php8", ".pht":
		return true
	}
	return false
}

// Trim removes injected code from a detected file and keeps the rest of the
// file live. The original is kept in quarantine (Restore puts it back). The
// file is left untouched when more than maxPercent of it would be removed,
// when the result fails a PHP syntax check, or when the scanner still
// detects malware in it.
func (s *Scanner) Trim(id int64, cuts []Cut, maxPercent int) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	src := r.path
	switch r.status {
	case "detected", "disabled":
	case "quarantined":
		src = r.qpath
		if _, err := os.Lstat(r.path); err == nil {
			return fmt.Errorf("a file already exists at %s", r.path)
		}
	default:
		return fmt.Errorf("cannot trim a %s file", r.status)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if isPHP(filepath.Base(r.path)) {
		if cuts, err = refineCuts(orig, cuts); err != nil {
			return err
		}
	}
	out, removed, err := ApplyCuts(orig, cuts)
	if err != nil {
		return err
	}
	if maxPercent <= 0 {
		maxPercent = 20
	}
	if removed*100 > len(orig)*maxPercent {
		return fmt.Errorf("the injected code is %d%% of the file (limit %d%%); quarantine it instead", removed*100/max(1, len(orig)), maxPercent)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return errors.New("nothing legitimate would remain")
	}

	// Check the result in a private directory under its own name, so
	// name-based rules apply as they would to the real file.
	work, err := os.MkdirTemp(QuarantineDir(), "trim-")
	if err != nil {
		if err := os.MkdirAll(QuarantineDir(), 0o700); err != nil {
			return err
		}
		if work, err = os.MkdirTemp(QuarantineDir(), "trim-"); err != nil {
			return err
		}
	}
	defer os.RemoveAll(work)
	tmp := filepath.Join(work, filepath.Base(r.path))
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if isPHP(filepath.Base(r.path)) {
		if php := phpBinary(); php != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			msg, err := exec.CommandContext(ctx, php, "-n", "-l", tmp).CombinedOutput()
			cancel()
			if err != nil {
				return fmt.Errorf("the trimmed file fails the PHP syntax check: %s", bytes.TrimSpace(bytes.ReplaceAll(msg, []byte(tmp), []byte(filepath.Base(r.path)))))
			}
		}
	}
	info, err := os.Stat(tmp)
	if err != nil {
		return err
	}
	cfg := s.Settings.Get().Scanner
	cfg.WhitelistPaths, cfg.WhitelistUsers = nil, nil
	if d, _ := s.CheckFile(tmp, info, cfg); d != nil && d.Category != CatBinary {
		return fmt.Errorf("the scanner still detects %s after trimming", d.Signature)
	}

	return s.replaceLive(id, r, orig, out, "trimmed")
}

// replaceLive keeps the current content (orig) in quarantine and puts
// replacement live at the finding's path with its original owner and mode.
func (s *Scanner) replaceLive(id int64, r row, orig, replacement []byte, status string) error {
	if err := os.MkdirAll(QuarantineDir(), 0o700); err != nil {
		return err
	}
	backup := filepath.Join(QuarantineDir(), strconv.FormatInt(id, 10)+".orig")
	if r.status == "quarantined" {
		if err := os.Rename(r.qpath, backup); err != nil {
			return err
		}
	} else if err := os.WriteFile(backup, orig, 0o000); err != nil {
		return err
	}
	_ = os.Chmod(backup, 0o000)
	mode := os.FileMode(r.mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	next := filepath.Join(filepath.Dir(r.path), "."+filepath.Base(r.path)+".xg-new")
	if err := os.WriteFile(next, replacement, mode); err != nil {
		return err
	}
	if r.uid >= 0 {
		_ = os.Lchown(next, r.uid, r.gid)
	}
	_ = os.Chmod(next, mode)
	if err := os.Rename(next, r.path); err != nil {
		os.Remove(next)
		return err
	}
	return s.setStatus(id, status, backup)
}

// ReplaceWithOfficial puts the official version of an infected file (e.g. a
// WordPress core file from the release) in place; the infected copy stays
// in quarantine and Restore can bring it back.
func (s *Scanner) ReplaceWithOfficial(id int64, official []byte) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	src := r.path
	switch r.status {
	case "detected", "disabled":
	case "quarantined":
		src = r.qpath
		if _, err := os.Lstat(r.path); err == nil {
			return fmt.Errorf("a file already exists at %s", r.path)
		}
	default:
		return fmt.Errorf("cannot replace a %s file", r.status)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return s.replaceLive(id, r, orig, official, "cleaned")
}

// Clear marks a detection as a false positive: a quarantined or disabled
// file is put back with its owner and permissions.
func (s *Scanner) Clear(id int64) error {
	return s.ClearAs(id, "cleared")
}

// StatusAIRestored marks a file the AI scanner found clean and put back.
const StatusAIRestored = "ai_restored"

// ClearAs is Clear with the final status (StatusAIRestored when the AI
// scanner, not an administrator, cleared the file).
func (s *Scanner) ClearAs(id int64, status string) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	switch r.status {
	case "quarantined", "disabled":
		if err := s.Restore(id); err != nil {
			return err
		}
	case "detected", "restored":
	default:
		return fmt.Errorf("cannot clear a %s file", r.status)
	}
	return s.setStatus(id, status, "")
}

// Content returns a finding's current content (the quarantined copy, or the
// original before trimming) for viewing, up to limit bytes.
func (s *Scanner) Content(id int64, limit int64) ([]byte, bool, error) {
	r, err := s.load(id)
	if err != nil {
		return nil, false, err
	}
	p := r.path
	if (r.status == "quarantined" || r.status == "trimmed" || r.status == "cleaned") && r.qpath != "" {
		p = r.qpath
	}
	if r.status == "deleted" {
		return nil, false, errors.New("the file was deleted")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	buf := make([]byte, limit+1)
	n, _ := f.Read(buf)
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	return buf[:min(n, int(limit))], n > int(limit), nil
}
