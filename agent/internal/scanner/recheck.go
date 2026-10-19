package scanner

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// RecheckItem is a quarantined script the current engine no longer flags.
type RecheckItem struct {
	ID        int64  `json:"id"`
	Path      string `json:"path"`
	Owner     string `json:"owner"`
	Signature string `json:"signature"`
}

// RecheckReport: how many quarantined scripts were judged again and which
// the current engine (later false-positive fixes) no longer flags.
// NextBeforeID pages on to older findings (0 when there are none).
type RecheckReport struct {
	Checked      int           `json:"checked"`
	Still        int           `json:"still_flagged"`
	Skipped      int           `json:"skipped"`
	Clean        []RecheckItem `json:"no_longer_flagged"`
	NextBeforeID int64         `json:"next_before_id,omitempty"`
}

// RecheckFilter picks the quarantined findings to judge again: one
// signature (or all), older than BeforeID (paging), or exactly IDs.
type RecheckFilter struct {
	Signature string
	BeforeID  int64
	IDs       []int64
	Limit     int
}

// Recheck runs the current engine on the newest quarantined scripts the
// filter picks. keep reports content that must stay in quarantine whatever
// the engine says (an AI or administrator verdict of malicious). Nothing is
// restored here.
func (s *Scanner) Recheck(f RecheckFilter, keep func(sha string) bool) (RecheckReport, error) {
	var rep RecheckReport
	limit := f.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT id, path, owner, signature, qpath FROM findings WHERE status = 'quarantined' AND qpath != ''`
	args := []any{}
	if f.Signature != "" {
		q += ` AND signature = ?`
		args = append(args, f.Signature)
	}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	if len(f.IDs) > 0 {
		q += ` AND id IN (?` + strings.Repeat(`,?`, len(f.IDs)-1) + `)`
		for _, id := range f.IDs {
			args = append(args, id)
		}
	}
	rows, err := s.DB.Query(q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return rep, err
	}
	var items []struct {
		RecheckItem
		qpath string
	}
	for rows.Next() {
		var it struct {
			RecheckItem
			qpath string
		}
		if rows.Scan(&it.ID, &it.Path, &it.Owner, &it.Signature, &it.qpath) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	if len(items) == limit && len(f.IDs) == 0 {
		rep.NextBeforeID = items[len(items)-1].ID
	}
	for _, it := range items {
		ext := extOf(filepath.Base(it.Path))
		content, err := os.ReadFile(it.qpath)
		if err != nil || !ScriptExts[ext] {
			rep.Skipped++
			continue
		}
		rep.Checked++
		sum := sha256.Sum256(content)
		if keep != nil && keep(hex.EncodeToString(sum[:])) {
			rep.Still++
			continue
		}
		if d := s.checkContent(it.Path, ext, content); d != nil {
			rep.Still++
			continue
		}
		rep.Clean = append(rep.Clean, it.RecheckItem)
	}
	return rep, nil
}

// checkContent is the content part of checkFile for a script whose bytes
// are at hand (a quarantined copy) and whose original path is known.
func (s *Scanner) checkContent(path, ext string, content []byte) *Detection {
	sum := md5.Sum(content)
	if s.KnownGood != nil && s.KnownGood(sum) {
		return nil
	}
	if s.KnownGoodPath != nil && s.KnownGoodPath(path, sum) {
		return nil
	}
	if trustedHostingTool(path, content) || translationFile(path, content) {
		return nil
	}
	if hdb := activeHashDB(); !s.NoHash && hdb.SizeKnown(int64(len(content))) {
		if label := hdb.LookupSums(int64(len(content)), func() (string, string) {
			h, m := sha256.Sum256(content), md5.Sum(content)
			return hex.EncodeToString(h[:]), hex.EncodeToString(m[:])
		}); label != "" {
			return &Detection{CatVirus, label}
		}
	}
	if IsELF(content) {
		d, _ := binaryCheck(path, content)
		return d
	}
	var d *Detection
	if a := analyze(ext, content); a != nil {
		d = capHeuristic(path, ext, a)
		if d == nil {
			return nil
		}
	} else if r := Match(ext, content); r != nil {
		d = &Detection{r.Category, r.Name}
	} else if c := clamCheck(content); c != nil {
		d = c
	} else if name := feedPatterns.Match(content); name != "" {
		d = &Detection{CatSuspicious, "LMD." + name}
	}
	if d != nil {
		d = applyOverride(d)
	}
	return d
}
