package cms

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Cleaning database findings: the injected part of the row is cut out, the
// rest of the row is kept, and the old value is saved here so it can be
// put back. Rows are only updated, never deleted (an emptied malware option
// is harmless and can be restored as it was).

// DBCleanResult is the outcome for one finding.
type DBCleanResult struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Action string `json:"action,omitempty"` // "cleaned", "already clean"
	Error  string `json:"error,omitempty"`
}

// The tables, keys and columns the DB scanner reads; nothing else is written.
var dbCleanTargets = map[string][2]string{
	"options":  {"option_name", "option_value"},
	"posts":    {"ID", "post_content"},
	"postmeta": {"meta_id", "meta_value"},
}

var reSafeName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// cleanRow is one finding's row, resolved from what the scan stored.
type cleanRow struct {
	id                                    int64
	site, dbName, table, keyCol, key, col string
	signature, category, status           string
}

func (m *Manager) loadCleanRow(id int64) (cleanRow, error) {
	var r cleanRow
	r.id = id
	var ref string
	err := m.DB.QueryRow(`SELECT site_path, db_name, tbl, row_ref, signature, category, status, column_name FROM db_findings WHERE id = ?`, id).
		Scan(&r.site, &r.dbName, &r.table, &ref, &r.signature, &r.category, &r.status, &r.col)
	if err != nil {
		return r, fmt.Errorf("finding %d not found", id)
	}
	k, v, ok := strings.Cut(ref, "=")
	if !ok {
		return r, errors.New("unknown row reference " + ref)
	}
	r.keyCol, r.key = k, v
	return r, nil
}

// target checks the row against the site's own tables.
func (r cleanRow) target(prefix string) error {
	if !reSafeName.MatchString(r.table) || !strings.HasPrefix(r.table, prefix) {
		return fmt.Errorf("table %s is not one of this site's tables", r.table)
	}
	t, ok := dbCleanTargets[strings.TrimPrefix(r.table, prefix)]
	if !ok || t[0] != r.keyCol || (r.col != "" && t[1] != r.col) {
		return fmt.Errorf("%s.%s can not be cleaned here", r.table, r.keyCol)
	}
	return nil
}

// CleanDBFindings cleans the given findings in the site databases.
func (m *Manager) CleanDBFindings(ctx context.Context, ids []int64) []DBCleanResult {
	out := make([]DBCleanResult, 0, len(ids))
	conns := map[string]*sql.DB{}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for _, id := range ids {
		res := DBCleanResult{ID: id}
		action, err := m.cleanOne(ctx, id, conns)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.OK, res.Action = true, action
		}
		out = append(out, res)
	}
	return out
}

func (m *Manager) cleanOne(ctx context.Context, id int64, conns map[string]*sql.DB) (string, error) {
	r, err := m.loadCleanRow(id)
	if err != nil {
		return "", err
	}
	if r.status != "detected" && r.status != "archived" {
		return "", fmt.Errorf("finding is %s", r.status)
	}
	// An administrator is a person's account and a plugin someone's
	// install: the owner decides, in WordPress (admins.go, pluginwatch.go).
	if r.category == AdminCategory {
		return "", errors.New("an administrator is not cleaned here: demote or delete the user in WordPress")
	}
	if watchCategory(r.category) {
		return "", errors.New("a plugin is not cleaned here: reinstall, deactivate or delete it in WordPress")
	}
	cfg, err := ReadWPConfig(r.site)
	if err != nil {
		return "", err
	}
	if err := r.target(cfg.Prefix); err != nil {
		return "", err
	}
	col := dbCleanTargets[strings.TrimPrefix(r.table, cfg.Prefix)][1]
	db := conns[r.site]
	if db == nil {
		if db, err = cfg.Open(); err != nil {
			return "", err
		}
		conns[r.site] = db
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var old sql.NullString
	q := fmt.Sprintf("SELECT `%s` FROM `%s` WHERE `%s` = ?", col, r.table, r.keyCol)
	if err := db.QueryRowContext(cctx, q, r.key).Scan(&old); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			m.markDBFinding(id, "cleaned", "row no longer exists")
			return "already clean", nil
		}
		return "", fmt.Errorf("read %s: %w", r.table, err)
	}
	var cleaned string
	if r.category == "siteurl" {
		cleaned, err = cleanSiteURL(old.String)
	} else {
		cleaned, err = CleanStoredValue(old.String)
	}
	if err != nil {
		return "", err
	}
	if cleaned == old.String {
		m.markDBFinding(id, "cleaned", "nothing found in the row any more")
		return "already clean", nil
	}
	// The old value goes first, so a failed update loses nothing.
	if _, err := m.DB.Exec(`INSERT INTO db_clean_backup (finding_id, at, site_path, db_name, tbl, key_col, key_val, col, old_value)
		VALUES (?,?,?,?,?,?,?,?,?)`, id, store.Now(), r.site, cfg.Name, r.table, r.keyCol, r.key, col, old.String); err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	// Only if the row is still what was read (WordPress may write it meanwhile).
	u := fmt.Sprintf("UPDATE `%s` SET `%s` = ? WHERE `%s` = ? AND `%s` = ?", r.table, col, r.keyCol, col)
	res, err := db.ExecContext(cctx, u, cleaned, r.key, old.String)
	if err != nil {
		return "", fmt.Errorf("update %s: %w", r.table, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errors.New("the row changed while cleaning; run the DB scan again")
	}
	m.markDBFinding(id, "cleaned", "cleaned by xPGuard (old value saved, can be restored)")
	return "cleaned", nil
}

func (m *Manager) markDBFinding(id int64, status, note string) {
	_, _ = m.DB.Exec(`UPDATE db_findings SET status = ?, note = ? WHERE id = ?`, status, note, id)
}

// RestoreDBFindings puts back the values saved when the findings were cleaned.
func (m *Manager) RestoreDBFindings(ctx context.Context, ids []int64) []DBCleanResult {
	out := make([]DBCleanResult, 0, len(ids))
	for _, id := range ids {
		res := DBCleanResult{ID: id}
		if err := m.restoreOne(ctx, id); err != nil {
			res.Error = err.Error()
		} else {
			res.OK, res.Action = true, "restored"
		}
		out = append(out, res)
	}
	return out
}

func (m *Manager) restoreOne(ctx context.Context, id int64) error {
	var site, dbName, table, keyCol, key, col, old string
	err := m.DB.QueryRow(`SELECT site_path, db_name, tbl, key_col, key_val, col, old_value FROM db_clean_backup WHERE finding_id = ? ORDER BY id DESC LIMIT 1`, id).
		Scan(&site, &dbName, &table, &keyCol, &key, &col, &old)
	if err != nil {
		return errors.New("no saved value for this finding")
	}
	cfg, err := ReadWPConfig(site)
	if err != nil {
		return err
	}
	// The value goes back only into the database it came from (a staging
	// clone or a migrated site may use another one now).
	if cfg.Name != dbName {
		return fmt.Errorf("the site now uses database %s, not %s where the value was saved", cfg.Name, dbName)
	}
	// And only over the value the clean wrote: an edit made since then is
	// not overwritten. The cleaned value is worked out again from the saved one.
	var category string
	_ = m.DB.QueryRow(`SELECT category FROM db_findings WHERE id = ?`, id).Scan(&category)
	cleaned, err := CleanStoredValue(old)
	if category == "siteurl" {
		cleaned, err = cleanSiteURL(old)
	}
	if err != nil {
		return err
	}
	r := cleanRow{table: table, keyCol: keyCol, col: col}
	if err := r.target(cfg.Prefix); err != nil {
		return err
	}
	db, err := cfg.Open()
	if err != nil {
		return err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := fmt.Sprintf("UPDATE `%s` SET `%s` = ? WHERE `%s` = ? AND `%s` = ?", table, col, keyCol, col)
	res, err := db.ExecContext(cctx, q, old, key, cleaned)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("the value changed since it was cleaned (or the row is gone); not overwritten")
	}
	m.markDBFinding(id, "detected", "restored from the saved value")
	return nil
}

// CleanStoredValue cuts what the DB scanner reports out of a stored value:
// serialized PHP data and JSON stay valid, everything else in the row
// stays as it is. It fails when the value is still reported afterwards.
func CleanStoredValue(v string) (string, error) {
	if isSerialized(v) {
		val, rest, err := unserialize(v)
		if err == nil && strings.TrimSpace(rest) == "" {
			changed := false
			if err := val.walkStrings(func(s string) (string, error) {
				c, err := cleanText(s)
				changed = changed || c != s
				return c, err
			}); err != nil {
				return v, err
			}
			if !changed {
				return v, nil
			}
			return val.serialize(), nil
		}
	}
	c, err := cleanText(v)
	if err != nil {
		return v, err
	}
	if json.Valid([]byte(v)) && !json.Valid([]byte(c)) {
		return v, errors.New("cleaning would break the JSON data of this row; clean it by hand")
	}
	return c, nil
}

// cleanText removes the reported parts of plain text one by one.
func cleanText(v string) (string, error) {
	for i := 0; i < 200; i++ {
		d, loc := scanValueLoc(v)
		if d.Signature == "" {
			return v, nil
		}
		if loc == nil || loc[1] <= loc[0] {
			return v, fmt.Errorf("%s can not be cut out automatically; clean it by hand", d.Signature)
		}
		v = v[:loc[0]] + v[loc[1]:]
	}
	return v, errors.New("too many injections in one row; clean it by hand")
}

var reCloseIframe = regexp.MustCompile(`(?is)^\s*</iframe\s*>`)

// scanValueLoc is ScanValueDetail with the span to remove: the whole
// <script> element, the <iframe> element with its closing tag, or the PHP
// block that holds the reported code.
func scanValueLoc(v string) (Detail, []int) {
	d := ScanValueDetail(v)
	if d.Signature == "" {
		return d, nil
	}
	switch d.Category {
	case "script":
		for _, loc := range reScript.FindAllStringSubmatchIndex(v, 20) {
			if sd := ScanValueDetail(v[loc[0]:loc[1]]); sd.Signature != "" {
				return d, loc[:2]
			}
		}
	case "iframe":
		for _, loc := range reIframeTag.FindAllStringIndex(v, 20) {
			tag := jsonHTML.Replace(v[loc[0]:loc[1]])
			if reHiddenIframe.MatchString(tag) && !benignIframe(tag) {
				end := loc[1]
				if c := reCloseIframe.FindStringIndex(v[end:]); c != nil {
					end += c[1]
				}
				return d, []int{loc[0], end}
			}
		}
	case "php":
		// The first PHP block that is reported on its own; a value that is
		// one payload goes as a whole.
		for _, loc := range rePHPTag.FindAllStringIndex(v, -1) {
			if sd := ScanValueDetail(v[loc[0]:loc[1]]); sd.Signature != "" {
				return d, loc
			}
		}
	}
	return d, nil
}

var reURLOnly = regexp.MustCompile(`^https?://[^\s<>"']+$`)

// cleanSiteURL keeps the address in front of an injection into siteurl/home.
func cleanSiteURL(v string) (string, error) {
	c := v
	if i := strings.IndexAny(c, "<>\"'"); i >= 0 {
		c = c[:i]
	}
	c = strings.TrimSpace(c)
	if !reURLOnly.MatchString(c) {
		return v, errors.New("the site address can not be recovered from this value; set it in WordPress » Settings » General")
	}
	return c, nil
}

// ---- PHP serialized data (what WordPress stores in options and post meta)

type phpVal struct {
	kind  byte // 's', 'i', 'd', 'b', 'N', 'a', 'O'
	raw   string
	str   string
	class string
	keys  []*phpVal
	vals  []*phpVal
}

var reSerialized = regexp.MustCompile(`^(?:[aO]:\d+:|s:\d+:")`)

func isSerialized(v string) bool { return reSerialized.MatchString(v) }

// unserialize reads one value and returns the rest of the input.
func unserialize(s string) (*phpVal, string, error) {
	if len(s) < 2 {
		return nil, s, errors.New("short")
	}
	switch s[0] {
	case 'N':
		if !strings.HasPrefix(s, "N;") {
			return nil, s, errors.New("bad null")
		}
		return &phpVal{kind: 'N'}, s[2:], nil
	case 'i', 'd', 'b':
		if s[1] != ':' {
			return nil, s, errors.New("bad scalar")
		}
		end := strings.IndexByte(s, ';')
		if end < 0 {
			return nil, s, errors.New("bad scalar")
		}
		return &phpVal{kind: s[0], raw: s[2:end]}, s[end+1:], nil
	case 's':
		n, rest, err := readLen(s[1:])
		if err != nil || len(rest) < n+3 || rest[0] != '"' || rest[n+1:n+3] != "\";" {
			return nil, s, errors.New("bad string")
		}
		return &phpVal{kind: 's', str: rest[1 : n+1]}, rest[n+3:], nil
	case 'a':
		n, rest, err := readLen(s[1:])
		if err != nil || !strings.HasPrefix(rest, "{") {
			return nil, s, errors.New("bad array")
		}
		v := &phpVal{kind: 'a'}
		rest, err = readPairs(v, rest[1:], n)
		return v, rest, err
	case 'O':
		n, rest, err := readLen(s[1:])
		if err != nil || len(rest) < n+3 || rest[0] != '"' || rest[n+1:n+3] != "\":" {
			return nil, s, errors.New("bad object")
		}
		v := &phpVal{kind: 'O', class: rest[1 : n+1]}
		cnt, rest2, err := readLen(rest[n+2:])
		if err != nil || !strings.HasPrefix(rest2, "{") {
			return nil, s, errors.New("bad object")
		}
		rest2, err = readPairs(v, rest2[1:], cnt)
		return v, rest2, err
	}
	return nil, s, fmt.Errorf("unsupported type %q", s[0])
}

// readLen reads ":<n>:" and returns n and what follows.
func readLen(s string) (int, string, error) {
	if !strings.HasPrefix(s, ":") {
		return 0, s, errors.New("bad length")
	}
	end := strings.IndexByte(s[1:], ':')
	if end < 0 {
		return 0, s, errors.New("bad length")
	}
	n, err := strconv.Atoi(s[1 : end+1])
	if err != nil || n < 0 {
		return 0, s, errors.New("bad length")
	}
	return n, s[end+2:], nil
}

func readPairs(v *phpVal, s string, n int) (string, error) {
	for i := 0; i < n; i++ {
		k, rest, err := unserialize(s)
		if err != nil {
			return s, err
		}
		val, rest2, err := unserialize(rest)
		if err != nil {
			return s, err
		}
		v.keys, v.vals, s = append(v.keys, k), append(v.vals, val), rest2
	}
	if !strings.HasPrefix(s, "}") {
		return s, errors.New("bad end")
	}
	return s[1:], nil
}

// walkStrings rewrites every string value (keys stay).
func (v *phpVal) walkStrings(f func(string) (string, error)) error {
	switch v.kind {
	case 's':
		// A string can hold serialized data itself (widgets, page builders).
		if isSerialized(v.str) {
			if in, rest, err := unserialize(v.str); err == nil && rest == "" {
				if err := in.walkStrings(f); err != nil {
					return err
				}
				v.str = in.serialize()
				return nil
			}
		}
		c, err := f(v.str)
		v.str = c
		return err
	case 'a', 'O':
		for _, x := range v.vals {
			if err := x.walkStrings(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *phpVal) serialize() string {
	var b strings.Builder
	v.write(&b)
	return b.String()
}

func (v *phpVal) write(b *strings.Builder) {
	switch v.kind {
	case 'N':
		b.WriteString("N;")
	case 'i', 'd', 'b':
		b.WriteByte(v.kind)
		b.WriteByte(':')
		b.WriteString(v.raw)
		b.WriteByte(';')
	case 's':
		fmt.Fprintf(b, "s:%d:\"%s\";", len(v.str), v.str)
	case 'a', 'O':
		if v.kind == 'a' {
			fmt.Fprintf(b, "a:%d:{", len(v.keys))
		} else {
			fmt.Fprintf(b, "O:%d:\"%s\":%d:{", len(v.class), v.class, len(v.keys))
		}
		for i := range v.keys {
			v.keys[i].write(b)
			v.vals[i].write(b)
		}
		b.WriteByte('}')
	}
}
