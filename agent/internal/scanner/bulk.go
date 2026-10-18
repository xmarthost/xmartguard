package scanner

import (
	"errors"
	"strings"
)

// Bulk actions on many findings at once, chosen by signature and time
// (for example everything one signature quarantined yesterday between 2
// and 6): a preview first, then restore or quarantine them all.

// BulkFilter selects findings; Signature is required.
type BulkFilter struct {
	Signature string `json:"signature"`
	From      int64  `json:"from"` // last change (quarantine) at or after; 0 = any
	To        int64  `json:"to"`   // and before; 0 = now
	Owner     string `json:"owner,omitempty"`
	Action    string `json:"action"` // restore | quarantine
}

// BulkLimit caps one bulk action.
const BulkLimit = 100000

// bulkStatuses are the statuses an action applies to.
var bulkStatuses = map[string][]string{
	"restore": {"quarantined", "disabled"},
	// Files the AI put back count too: a wrong "clean" is undone in bulk.
	"quarantine": {"detected", StatusAIRestored},
}

func (f BulkFilter) where() (string, []any, error) {
	st, ok := bulkStatuses[f.Action]
	if !ok {
		return "", nil, errors.New("action must be restore or quarantine")
	}
	if strings.TrimSpace(f.Signature) == "" {
		return "", nil, errors.New("choose a signature")
	}
	q := `signature = ? AND status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(st)), ",") + `)`
	args := []any{f.Signature}
	for _, x := range st {
		args = append(args, x)
	}
	if f.From > 0 {
		q += ` AND updated_at >= ?`
		args = append(args, f.From)
	}
	if f.To > 0 {
		q += ` AND updated_at < ?`
		args = append(args, f.To)
	}
	if f.Owner != "" {
		q += ` AND owner = ?`
		args = append(args, f.Owner)
	}
	return q, args, nil
}

// BulkPreview counts the findings a bulk action would change and returns
// up to limit of them (newest first).
func (s *Scanner) BulkPreview(f BulkFilter, limit int) (int, []Finding, error) {
	q, args, err := f.where()
	if err != nil {
		return 0, nil, err
	}
	var total int
	if err := s.DB.QueryRow(`SELECT count(*) FROM findings WHERE `+q, args...).Scan(&total); err != nil {
		return 0, nil, err
	}
	ids, err := s.bulkIDs(q, args, min(max(limit, 1), 500))
	if err != nil {
		return 0, nil, err
	}
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		if x, err := s.Get(id); err == nil {
			out = append(out, x)
		}
	}
	return total, out, nil
}

func (s *Scanner) bulkIDs(q string, args []any, limit int) ([]int64, error) {
	rows, err := s.DB.Query(`SELECT id FROM findings WHERE `+q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// BulkResult is what a bulk action did.
type BulkResult struct {
	Done   int      `json:"done"`
	Failed int      `json:"failed"`
	Errors []string `json:"errors,omitempty"`
}

// BulkApply restores or quarantines every finding the filter selects;
// restore puts one back (nil = Restore).
func (s *Scanner) BulkApply(f BulkFilter, restore func(int64) error) (BulkResult, error) {
	if restore == nil {
		restore = s.Restore
	}
	q, args, err := f.where()
	if err != nil {
		return BulkResult{}, err
	}
	ids, err := s.bulkIDs(q, args, BulkLimit)
	if err != nil {
		return BulkResult{}, err
	}
	var r BulkResult
	for _, id := range ids {
		var err error
		if f.Action == "restore" {
			err = restore(id)
		} else {
			err = s.Quarantine(id)
		}
		if err != nil {
			r.Failed++
			if len(r.Errors) < 20 {
				r.Errors = append(r.Errors, err.Error())
			}
			continue
		}
		r.Done++
	}
	return r, nil
}
