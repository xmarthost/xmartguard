package cms

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

// DBConfig is a WordPress database connection read from wp-config.php.
type DBConfig struct {
	Name, User, Password, Host, Prefix string
}

var (
	reDefine = regexp.MustCompile(`define\s*\(\s*['"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['"]\s*,\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*\)`)
	rePrefix = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([A-Za-z0-9_]+)['"]`)
)

// ReadWPConfig parses the database settings of a WordPress install.
func ReadWPConfig(root string) (DBConfig, error) {
	b, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		return DBConfig{}, err
	}
	c := DBConfig{Prefix: "wp_", Host: "localhost"}
	for _, m := range reDefine.FindAllStringSubmatch(string(b), -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		v = strings.ReplaceAll(strings.ReplaceAll(v, `\'`, `'`), `\\`, `\`)
		switch m[1] {
		case "DB_NAME":
			c.Name = v
		case "DB_USER":
			c.User = v
		case "DB_PASSWORD":
			c.Password = v
		case "DB_HOST":
			c.Host = v
		}
	}
	if m := rePrefix.FindStringSubmatch(string(b)); m != nil {
		c.Prefix = m[1]
	}
	if c.Name == "" || c.User == "" {
		return c, fmt.Errorf("database settings not found in wp-config.php")
	}
	return c, nil
}

// socketPaths are where MySQL/MariaDB usually listen on hosting servers.
var socketPaths = []string{"/var/lib/mysql/mysql.sock", "/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/tmp/mysql.sock"}

// Open connects to the site database (read-only use).
func (c DBConfig) Open() (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.DBName = c.User, c.Password, c.Name
	cfg.Timeout, cfg.ReadTimeout = 10*time.Second, 60*time.Second
	host, port := c.Host, "3306"
	if h, rest, ok := strings.Cut(c.Host, ":"); ok {
		host = h
		if strings.HasPrefix(rest, "/") {
			cfg.Net, cfg.Addr = "unix", rest
		} else {
			port = rest
		}
	}
	if cfg.Net == "" {
		if host == "localhost" {
			for _, s := range socketPaths {
				if _, err := os.Stat(s); err == nil {
					cfg.Net, cfg.Addr = "unix", s
					break
				}
			}
		}
		if cfg.Net == "" {
			if host == "localhost" {
				host = "127.0.0.1"
			}
			cfg.Net, cfg.Addr = "tcp", host+":"+port
		}
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// DBFinding is one infected database row.
type DBFinding struct {
	Table     string `json:"table"`
	Row       string `json:"row"`
	Signature string `json:"signature"`
	// Column holds the value that matched, Category the kind of
	// injection (script, iframe, php, siteurl) and Snippet the matching part.
	Column   string `json:"column"`
	Category string `json:"category"`
	Snippet  string `json:"snippet"`
}

// Hidden iframes these services use legitimately (Google Tag Manager's
// <noscript> iframe, reCAPTCHA, video embeds kept hidden until opened).
var benignIframeHosts = []string{"googletagmanager.com", "google.com", "gstatic.com", "youtube.com", "youtube-nocookie.com",
	"player.vimeo.com", "facebook.com", "doubleclick.net", "hotjar.com", "calendly.com", "hubspot.com", "tiktok.com"}

// DBRulesVersion changes when the database rules change in a way that
// drops earlier detections: the next scan runs at once and marks what is no
// longer found as a false positive ("cleared"), not as cleaned.
const DBRulesVersion = "2"

// Options that hold plugin data or documentation, never page output
// (Freemius keeps the plugins' descriptions, with example HTML, in fs_accounts).
var skipOptions = map[string]bool{"fs_accounts": true, "fs_api_cache": true, "fs_debug_mode": true}

var (
	// WordPress core embeds another post (oEmbed): a sandboxed iframe kept
	// hidden until wp-embed.js has sized it.
	reWPEmbed = regexp.MustCompile(`(?is)\bclass\s*=\s*["'][^"']*\bwp-embedded-content\b`)
	reSandbox = regexp.MustCompile(`(?i)\ssandbox\s*=`)
	reEmbedTo = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']?(?:https?:)?//[^"'\s>]+(?:/embed/?(?:[#?"'\s>]|$)|[?&]embed=true)`)
	// GiveWP donation forms load hidden and are shown by Give's resizer.
	reGiveForm = regexp.MustCompile(`(?i)\bname\s*=\s*["']give-embed-form["']`)
)

var reIframeTag = regexp.MustCompile(`(?is)<iframe\b[^>]*>`)
var reIframeSrc = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']?(?:https?:)?//([^/"'\s>?#]+)`)

// Detail is what ScanValueDetail found.
type Detail struct {
	Signature, Category, Snippet string
}

func snippetAround(v string, loc []int) string {
	if loc == nil {
		return ""
	}
	start, end := loc[0]-60, loc[1]+60
	if start < 0 {
		start = 0
	}
	if end > len(v) {
		end = len(v)
	}
	if end-start > 400 {
		end = start + 400
	}
	return strings.TrimSpace(strings.ToValidUTF8(v[start:end], ""))
}

func benignIframe(tag string) bool {
	if reWPEmbed.MatchString(tag) && reSandbox.MatchString(tag) && reEmbedTo.MatchString(tag) {
		return true
	}
	if reGiveForm.MatchString(tag) {
		return true
	}
	m := reIframeSrc.FindStringSubmatch(tag)
	if m == nil {
		return true // no remote source: nothing is loaded
	}
	host := strings.ToLower(m[1])
	for _, b := range benignIframeHosts {
		if host == b || strings.HasSuffix(host, "."+b) {
			return true
		}
	}
	return false
}

var (
	reScript = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	// A zero width or height attribute (not marginwidth/marginheight, which
	// embed codes set to 0) or a hiding style.
	reHiddenIframe = regexp.MustCompile(`(?is)<iframe\b[^>]*(?:\s(?:width|height)\s*=\s*["']?0(?:px)?["'\s>]|display\s*:\s*none|visibility\s*:\s*hidden)`)
	rePHPOpen      = regexp.MustCompile(`(?i)<\?php`)
	reScriptSrc    = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']?(?:https?:)?//([^/"'\s>]+)`)
)

// ScanValue checks one stored value for injected malware.
func ScanValue(v string) string { return ScanValueDetail(v).Signature }

// ScanValueDetail checks one stored value and says what matched.
func ScanValueDetail(v string) Detail {
	if v == "" {
		return Detail{}
	}
	for _, loc := range reScript.FindAllStringSubmatchIndex(v, 20) {
		if d := scanner.AnalyzeScript("js", []byte(v[loc[2]:loc[3]])); d != nil {
			return Detail{"DB." + d.Signature, "script", snippetAround(v, loc[:2])}
		}
	}
	for _, loc := range reIframeTag.FindAllStringIndex(v, 20) {
		tag := v[loc[0]:loc[1]]
		if reHiddenIframe.MatchString(tag) && !benignIframe(tag) {
			return Detail{"DB.Injected.HiddenIframe", "iframe", snippetAround(v, loc)}
		}
	}
	if loc := rePHPOpen.FindStringIndex(v); loc != nil {
		if d := scanner.AnalyzeScript("php", []byte(v)); d != nil {
			return Detail{"DB." + d.Signature, "php", snippetAround(v, loc)}
		}
	}
	return Detail{}
}

// ScanDatabase scans a WordPress database for injected code in options,
// posts and widgets. It only reads.
// DBChangedSince reports whether the tables the scan reads (options,
// posts, postmeta) changed since unix time t. ok is false when MySQL cannot
// tell: then scan.
func DBChangedSince(ctx context.Context, c DBConfig, t int64) (changed, ok bool) {
	db, err := c.Open()
	if err != nil {
		return false, false
	}
	defer db.Close()
	p := c.Prefix
	var last, started sql.NullInt64
	var tables, known int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(UPDATE_TIME), CAST(UNIX_TIMESTAMP(MAX(UPDATE_TIME)) AS SIGNED),
		CAST(UNIX_TIMESTAMP() - (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'UPTIME') AS SIGNED)
		FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?, ?)`,
		p+"options", p+"posts", p+"postmeta").Scan(&tables, &known, &last, &started)
	if err != nil {
		return false, false
	}
	return changedSince(t, tables, known, last, started)
}

// changedSince decides from information_schema: InnoDB keeps a table's
// update time in memory only, so it is empty for tables not changed since
// MySQL started. Empty times are "unchanged" only when MySQL was already
// running at the last check.
func changedSince(t int64, tables, known int, last, started sql.NullInt64) (changed, ok bool) {
	if tables == 0 {
		return false, false
	}
	if known > 0 && last.Valid && last.Int64 >= t {
		return true, true
	}
	if known == tables && last.Valid {
		return false, true // every table has an update time before t
	}
	if started.Valid && started.Int64 > 0 && started.Int64 < t {
		return false, true // the rest did not change since MySQL started
	}
	return false, false
}

func ScanDatabase(ctx context.Context, c DBConfig) ([]DBFinding, error) {
	db, err := c.Open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("cannot connect to database %s: %w", c.Name, err)
	}
	p := c.Prefix
	var out []DBFinding
	// siteurl/home should be plain URLs; anything else is an injection.
	rows, err := db.QueryContext(ctx, "SELECT option_name, option_value FROM `"+p+"options` WHERE option_name IN ('siteurl','home')")
	if err == nil {
		for rows.Next() {
			var name, val string
			if rows.Scan(&name, &val) == nil && strings.ContainsAny(val, "<>\"'") {
				out = append(out, DBFinding{Table: p + "options", Row: "option_name=" + name, Signature: "DB.Injected.SiteURL",
					Column: "option_value", Category: "siteurl", Snippet: snippetAround(val, []int{0, min(len(val), 200)})})
			}
		}
		rows.Close()
	}
	candidates := []struct {
		table, key, col string
	}{
		{p + "options", "option_name", "option_value"},
		{p + "posts", "ID", "post_content"},
		{p + "postmeta", "meta_id", "meta_value"},
	}
	for _, t := range candidates {
		q := fmt.Sprintf("SELECT `%s`, `%s` FROM `%s` WHERE `%s` LIKE '%%<script%%' OR `%s` LIKE '%%<iframe%%' OR `%s` LIKE '%%<?php%%' LIMIT 20000",
			t.key, t.col, t.table, t.col, t.col, t.col)
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			continue // table missing (multisite/custom prefix)
		}
		for rows.Next() {
			var key string
			var val sql.NullString
			if rows.Scan(&key, &val) != nil || (t.key == "option_name" && skipOptions[key]) {
				continue
			}
			if d := ScanValueDetail(val.String); d.Signature != "" {
				out = append(out, DBFinding{Table: t.table, Row: t.key + "=" + key, Signature: d.Signature,
					Column: t.col, Category: d.Category, Snippet: d.Snippet})
			}
		}
		rows.Close()
	}
	return out, nil
}

// ExternalScripts lists third-party script hosts referenced by a value
// (informational; used in tests and for future reputation checks).
func ExternalScripts(v string) []string {
	var hosts []string
	for _, m := range reScriptSrc.FindAllStringSubmatch(v, 20) {
		hosts = append(hosts, strings.ToLower(m[1]))
	}
	return hosts
}
