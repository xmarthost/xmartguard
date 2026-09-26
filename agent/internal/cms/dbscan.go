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
}

var (
	reScript       = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	reHiddenIframe = regexp.MustCompile(`(?is)<iframe\b[^>]*(?:width\s*=\s*["']?0["'\s>]|height\s*=\s*["']?0["'\s>]|display\s*:\s*none|visibility\s*:\s*hidden)`)
	rePHPOpen      = regexp.MustCompile(`(?i)<\?php`)
	reScriptSrc    = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']?(?:https?:)?//([^/"'\s>]+)`)
)

// ScanValue checks one stored value for injected malware.
func ScanValue(v string) string {
	if v == "" {
		return ""
	}
	for _, m := range reScript.FindAllStringSubmatch(v, 20) {
		if d := scanner.AnalyzeScript("js", []byte(m[1])); d != nil {
			return "DB." + d.Signature
		}
	}
	if reHiddenIframe.MatchString(v) {
		return "DB.Injected.HiddenIframe"
	}
	if rePHPOpen.MatchString(v) {
		if d := scanner.AnalyzeScript("php", []byte(v)); d != nil {
			return "DB." + d.Signature
		}
	}
	return ""
}

// ScanDatabase scans a WordPress database for injected code in options,
// posts and widgets. It only reads.
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
				out = append(out, DBFinding{p + "options", "option_name=" + name, "DB.Injected.SiteURL"})
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
			if rows.Scan(&key, &val) != nil {
				continue
			}
			if sig := ScanValue(val.String); sig != "" {
				out = append(out, DBFinding{t.table, t.key + "=" + key, sig})
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
