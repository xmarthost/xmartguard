package cms

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Admin watch. Nearly every WordPress takeover of 2025-2026 ends in a new
// administrator: plugin bugs that create one (OttoKit, King Addons, Post
// SMTP), logins with stolen passwords (server1, 2026-10-28) and kits that
// keep making them (sawanysc: 11,966 administrators in two weeks, no
// alert). The DB scan reads each site's administrators and reports:
//
//   - WP.Admin.New: an administrator that was not there when xPGuard first
//     read the site (at that first read: one registered in the last 30
//     days, other than the site's first user);
//   - WP.Admin.Suspicious: names and addresses kits use (adm + random
//     characters, a hex suffix, a look-alike of "admin", @example.com or
//     .local mail);
//   - WP.Admin.Farm: more new or suspicious administrators than are worth
//     a row each, or a site with more than 50.
//
// Nothing is changed in the site: an administrator decides (demote,
// delete or archive the finding). The first read is the baseline; it is
// never learned again, so a new administrator stays reported until the
// finding is archived.

const (
	adminRows    = 20 // rows reported one by one; more become one Farm row
	adminMany    = 50 // administrators no site needs
	adminRecent  = 30 * 24 * time.Hour
	adminSigNew  = "WP.Admin.New"
	adminSigSus  = "WP.Admin.Suspicious"
	adminSigFarm = "WP.Admin.Farm"
)

// AdminCategory marks admin watch findings (never cleaned by the DB cleaner).
const AdminCategory = "admin"

var (
	// A word, then a hex or random tail: admin_3f9a1c, backup_a1b2c3d4,
	// adm2jwo0u, root_80j74hg.
	reKitLoginHex  = regexp.MustCompile(`^(?:adm|admin|administrator|backup|support|wp|wps|root|sys|system|dev|manager|service)[_.-]?[0-9a-f]{6,}$`)
	reKitLoginRand = regexp.MustCompile(`^(?:adm|root)[_-]?([a-z0-9]{5,8})$`)
	// "admln", "adrnin", "admiin": made to be read as "admin".
	reAdminLookalike = regexp.MustCompile(`^ad(?:m|rn)(?:l|1|ii|ı|\|)n$`)
	reHasDigit       = regexp.MustCompile(`[0-9]`)
)

// kitMailDomains are domains no real administrator receives mail at.
var kitMailDomains = []string{"example.com", "example.org", "example.net", "example.invalid", "wordpress.org", "localhost"}

type wpAdmin struct {
	ID         int64
	Login      string
	Email      string
	Registered time.Time
}

// suspiciousAdmin reports why a login or address looks made by a kit.
func suspiciousAdmin(a wpAdmin) string {
	login := strings.ToLower(a.Login)
	switch {
	case reKitLoginHex.MatchString(login) && reHasDigit.MatchString(login):
		return "random name"
	case reAdminLookalike.MatchString(login):
		return "look-alike of admin"
	}
	if m := reKitLoginRand.FindStringSubmatch(login); m != nil && reHasDigit.MatchString(m[1]) && !strings.HasPrefix(m[1], "in") {
		return "random name"
	}
	email := strings.ToLower(a.Email)
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		d := email[at+1:]
		for _, k := range kitMailDomains {
			if d == k {
				return "mail at " + d
			}
		}
		if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".invalid") || !strings.Contains(d, ".") {
			return "mail at " + d
		}
	}
	return ""
}

// adminFindings judges a site's administrators against its baseline (nil:
// the first read).
func adminFindings(table string, admins []wpAdmin, baseline map[int64]bool, now time.Time) []DBFinding {
	first := int64(-1)
	for _, a := range admins {
		if first < 0 || a.ID < first {
			first = a.ID
		}
	}
	var sus, fresh []DBFinding
	for _, a := range admins {
		desc := fmt.Sprintf("%s <%s>, registered %s", a.Login, a.Email, a.Registered.UTC().Format("2006-01-02 15:04"))
		row := "ID=" + strconv.FormatInt(a.ID, 10)
		if why := suspiciousAdmin(a); why != "" {
			sus = append(sus, DBFinding{Table: table, Row: row, Signature: adminSigSus, Column: "user_login", Category: AdminCategory,
				Snippet: "administrator " + desc + " (" + why + ")"})
			continue
		}
		isNew := false
		if baseline != nil {
			isNew = !baseline[a.ID]
		} else {
			isNew = a.ID != first && !a.Registered.IsZero() && now.Sub(a.Registered) < adminRecent
		}
		if isNew {
			fresh = append(fresh, DBFinding{Table: table, Row: row, Signature: adminSigNew, Column: "user_login", Category: AdminCategory,
				Snippet: "new administrator " + desc})
		}
	}
	var out []DBFinding
	if len(sus)+len(fresh) > adminRows || len(admins) > adminMany {
		var names []string
		for _, f := range append(append([]DBFinding{}, sus...), fresh...) {
			if len(names) == 10 {
				break
			}
			names = append(names, strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(f.Snippet, "new "), "administrator "), " ", 2)[0])
		}
		out = append(out, DBFinding{Table: table, Row: "administrators", Signature: adminSigFarm, Column: "user_login", Category: AdminCategory,
			Snippet: fmt.Sprintf("%d administrators, %d suspicious, %d new; for example %s", len(admins), len(sus), len(fresh), strings.Join(names, ", "))})
		// The first rows still name who to look at.
		sus, fresh = sus[:min(len(sus), adminRows/2)], fresh[:min(len(fresh), adminRows/2)]
	}
	return append(append(out, sus...), fresh...)
}

// readAdmins lists a site's administrators (at most 100,000).
func readAdmins(ctx context.Context, db *sql.DB, prefix string) ([]wpAdmin, error) {
	q := "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM `" + prefix + "users` u JOIN `" + prefix +
		"usermeta` m ON m.user_id = u.ID WHERE m.meta_key = ? AND m.meta_value LIKE '%\"administrator\"%' LIMIT 100000"
	rows, err := db.QueryContext(ctx, q, prefix+"capabilities")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wpAdmin
	for rows.Next() {
		var a wpAdmin
		var reg sql.NullString
		if rows.Scan(&a.ID, &a.Login, &a.Email, &reg) != nil {
			continue
		}
		if t, err := time.Parse("2006-01-02 15:04:05", reg.String); err == nil {
			a.Registered = t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// watchAdmins reads a site's administrators and returns what to report;
// the first read of a site becomes its baseline.
func (m *Manager) watchAdmins(ctx context.Context, c DBConfig, sitePath string) []DBFinding {
	db, err := c.Open()
	if err != nil {
		return nil
	}
	defer db.Close()
	return m.watchAdminsDB(ctx, db, c.Prefix, sitePath)
}

func (m *Manager) watchAdminsDB(ctx context.Context, db *sql.DB, prefix, sitePath string) []DBFinding {
	admins, err := readAdmins(ctx, db, prefix)
	if err != nil {
		m.Log.Info("admin watch skipped", "site", sitePath, "err", err)
		return nil
	}
	var baseline map[int64]bool
	if rows, err := m.DB.Query(`SELECT user_id FROM cms_admins WHERE site_path = ?`, sitePath); err == nil {
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				if baseline == nil {
					baseline = map[int64]bool{}
				}
				baseline[id] = true
			}
		}
		rows.Close()
	}
	out := adminFindings(prefix+"users", admins, baseline, time.Now())
	if baseline == nil && len(admins) > 0 {
		// The baseline is what a person set up before xPGuard looked:
		// what this first read reports is left out of it.
		reported := map[string]bool{}
		for _, f := range out {
			reported[f.Row] = true
		}
		farm := len(out) > 0 && out[0].Signature == adminSigFarm
		tx, err := m.DB.Begin()
		if err == nil {
			for _, a := range admins {
				if reported["ID="+strconv.FormatInt(a.ID, 10)] || farm && suspiciousAdmin(a) != "" {
					continue
				}
				_, _ = tx.Exec(`INSERT OR IGNORE INTO cms_admins (site_path, user_id) VALUES (?, ?)`, sitePath, a.ID)
			}
			// A marker row: the site has a baseline even if every admin was reported.
			_, _ = tx.Exec(`INSERT OR IGNORE INTO cms_admins (site_path, user_id) VALUES (?, 0)`, sitePath)
			_ = tx.Commit()
		}
	}
	return out
}
