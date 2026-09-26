package main

// xgcli: XMart Guard's command line (like cpgcli). It talks to the running
// agent over its root-only local socket, so every change goes through the
// same validation as the portal and takes effect at once.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/local"
	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// caller runs an agent action (the local socket; a fake in tests).
type caller func(action string, params any) (json.RawMessage, error)

type cli struct {
	call caller
	out  io.Writer
	args []string
	cmd  string
}

func localCaller(action string, params any) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	data, err := local.Call(ctx, action, params)
	if err != nil && strings.Contains(err.Error(), "connect") {
		return nil, fmt.Errorf("%w (is the agent running? systemctl status xmartguard-agent)", err)
	}
	return data, err
}

func cmdCLI(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		cliUsage(os.Stdout)
		return nil
	}
	if args[0] == "-v" || args[0] == "--version" || args[0] == "version" {
		fmt.Println("XMart Guard", version.Version)
		return nil
	}
	c := &cli{call: localCaller, out: os.Stdout, cmd: args[0], args: args[1:]}
	return c.run()
}

func (c *cli) run() error {
	h, ok := cliCommands[c.cmd]
	if !ok {
		return fmt.Errorf("unknown command %q (xgcli --help lists them)", c.cmd)
	}
	return h(c)
}

// ------------------------------------------------------------------ arguments

// has reports whether a flag is present.
func (c *cli) has(flag string) bool {
	for _, a := range c.args {
		if a == flag {
			return true
		}
	}
	return false
}

// val returns the first value after flag ("" if none).
func (c *cli) val(flag string) string {
	v := c.vals(flag)
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// raw returns the single argument after flag, unsplit ("" if none): for
// free text such as --reason 'office server' or --from '-24 hours'.
func (c *cli) raw(flag string) string {
	for i, a := range c.args {
		if a == flag && i+1 < len(c.args) && (!strings.HasPrefix(c.args[i+1], "--")) {
			return c.args[i+1]
		}
	}
	return ""
}

// vals returns the values after flag up to the next --option; values may
// also be separated by commas.
func (c *cli) vals(flag string) []string {
	var out []string
	for i, a := range c.args {
		if a != flag {
			continue
		}
		for _, v := range c.args[i+1:] {
			if strings.HasPrefix(v, "--") {
				break
			}
			for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				out = append(out, part)
			}
		}
		break
	}
	return out
}

// onOff reads "enable"/"disable" after flag; ok is false when absent.
func (c *cli) onOff(flag string) (on bool, ok bool, err error) {
	if !c.has(flag) {
		return false, false, nil
	}
	switch strings.ToLower(c.val(flag)) {
	case "enable", "on", "yes", "true", "1":
		return true, true, nil
	case "disable", "off", "no", "false", "0":
		return false, true, nil
	case "", "status":
		return false, false, nil
	}
	return false, false, fmt.Errorf("%s takes enable or disable", flag)
}

// enableFlag handles --enable / --disable.
func (c *cli) enableFlag() (on bool, ok bool) {
	if c.has("--enable") {
		return true, true
	}
	if c.has("--disable") {
		return false, true
	}
	return false, false
}

// ------------------------------------------------------------------ agent helpers

func (c *cli) callJSON(action string, params any, out any) error {
	data, err := c.call(action, params)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *cli) settings() (map[string]map[string]any, error) {
	var r struct {
		Settings map[string]map[string]any `json:"settings"`
	}
	err := c.callJSON("settings.get", nil, &r)
	return r.Settings, err
}

func (c *cli) section(name string) (map[string]any, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	sec, ok := s[name]
	if !ok {
		return nil, fmt.Errorf("unknown settings section %q", name)
	}
	return sec, nil
}

// set changes settings fields of one section.
func (c *cli) set(section string, fields map[string]any) error {
	var r struct {
		Warning string `json:"warning"`
	}
	if err := c.callJSON("settings.set", map[string]any{section: fields}, &r); err != nil {
		return err
	}
	if r.Warning != "" {
		fmt.Fprintln(c.out, "warning:", r.Warning)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(c.out, "%s.%s = %s\n", section, k, show(fields[k]))
	}
	return nil
}

func (c *cli) toggle(section, field, label string) error {
	on, ok := c.enableFlag()
	if !ok {
		sec, err := c.section(section)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.out, "%s: %s\n", label, enabled(sec[field]))
		return nil
	}
	return c.set(section, map[string]any{field: on})
}

// listEdit implements --list / --add / --remove on a string list setting.
func (c *cli) listEdit(section, field, flag string) error {
	sec, err := c.section(section)
	if err != nil {
		return err
	}
	cur := strList(sec[field])
	switch {
	case c.has("--add"):
		add := c.vals("--add")
		if len(add) == 0 {
			return errors.New("--add needs a value")
		}
		for _, v := range add {
			if !contains(cur, v) {
				cur = append(cur, v)
			}
		}
	case c.has("--remove") || c.has("--delete"):
		rm := append(c.vals("--remove"), c.vals("--delete")...)
		if len(rm) == 0 {
			return errors.New("--remove needs a value")
		}
		var keep []string
		for _, v := range cur {
			if !contains(rm, v) {
				keep = append(keep, v)
			}
		}
		cur = keep
	default:
		if len(cur) == 0 {
			fmt.Fprintf(c.out, "no entries (%s)\n", flag)
		}
		for _, v := range cur {
			fmt.Fprintln(c.out, v)
		}
		return nil
	}
	if cur == nil {
		cur = []string{}
	}
	return c.set(section, map[string]any{field: cur})
}

func strList(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if f, ok := x.(float64); ok && f == float64(int64(f)) {
				out = append(out, strconv.FormatInt(int64(f), 10))
				continue
			}
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func enabled(v any) string {
	if b, ok := v.(bool); ok && b {
		return "enabled"
	}
	return "disabled"
}

func show(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []string:
		return strings.Join(x, ", ")
	case []any:
		return strings.Join(strList(x), ", ")
	case bool:
		if x {
			return "on"
		}
		return "off"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func (c *cli) printSection(name string, fields ...string) error {
	sec, err := c.section(name)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		for k := range sec {
			fields = append(fields, k)
		}
		sort.Strings(fields)
	}
	tw := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
	for _, f := range fields {
		if v, ok := sec[f]; ok {
			if strings.Contains(f, "key") || strings.Contains(f, "token") || strings.Contains(f, "webhook") {
				if s, _ := v.(string); s != "" {
					v = "(set)"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\n", f, show(v))
		}
	}
	return tw.Flush()
}

func actionName(v string) (string, error) {
	switch strings.ToLower(v) {
	case "email", "notify", "report":
		return "notify", nil
	case "disable", "quarantine":
		return strings.ToLower(v), nil
	}
	return "", fmt.Errorf("invalid action %q (email|disable|quarantine)", v)
}

// ------------------------------------------------------------------ commands

var cliCommands map[string]func(*cli) error

func init() {
	cliCommands = map[string]func(*cli) error{
		"status":      cliStatus,
		"cloud":       cliStatus,
		"scanner":     cliScanner,
		"dailyscan":   func(c *cli) error { return c.toggle("scanner", "daily_scan", "daily scan") },
		"weeklyscan":  func(c *cli) error { return c.toggle("scanner", "weekly_scan", "weekly scan") },
		"ai-scan":     cliAIScan,
		"watch":       cliWatch,
		"whitelist":   cliWhitelist,
		"blacklist":   cliBlacklist,
		"file-action": cliFileAction,
		"cleanup": func(c *cli) error {
			return c.toggle("scanner", "auto_clean", "cleanup of infected WordPress core files")
		},
		"trim":            cliTrim,
		"scan":            cliScan,
		"logs":            cliLogs,
		"view":            cliView,
		"log-action":      cliLogAction,
		"fw":              cliFirewall,
		"ip":              cliIP,
		"lfd":             cliLFD,
		"waf":             cliWAF,
		"bot-check":       func(c *cli) error { return c.toggle("waf", "bad_bots", "bad bot blocking") },
		"account-suspend": cliSuspend,
		"rootkit":         cliRootkit,
		"process-monitor": cliProcess,
		"cron-monitor":    cliCron,
		"osm":             cliOSM,
		"ip-reputation":   cliReputation,
		"dbscan":          cliDBScan,
		"notification":    cliNotification,
		"cms":             cliCMS,
		"upload-scanner":  cliUpload,
		"config":          cliConfig,
		"update":          cliUpdate,
	}
}

func cliStatus(c *cli) error {
	var o struct {
		Version  string `json:"version"`
		Portal   string `json:"portal"`
		Scanner  bool   `json:"scanner"`
		Realtime bool   `json:"realtime"`
		Firewall struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
			Healthy  bool   `json:"healthy"`
			Error    string `json:"error"`
		} `json:"firewall"`
		IPDB struct {
			Enabled bool  `json:"enabled"`
			Entries int64 `json:"entries"`
		} `json:"ipdb"`
		Summary struct {
			Scanner struct {
				Threats30d  int `json:"threats_30d"`
				Quarantined int `json:"quarantined"`
				Open        int `json:"open_findings"`
			} `json:"scanner"`
		} `json:"summary"`
	}
	if err := c.callJSON("overview", nil, &o); err != nil {
		return err
	}
	ai, _ := c.section("ai")
	tw := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "XMart Guard\t%s\n", o.Version)
	fmt.Fprintf(tw, "Portal\t%s\n", o.Portal)
	fmt.Fprintf(tw, "Virus scanner\t%s (realtime %s)\n", enabled(o.Scanner), enabled(o.Realtime))
	fmt.Fprintf(tw, "Firewall\t%s, %s%s\n", enabled(o.Firewall.Enabled), o.Firewall.Provider, map[bool]string{true: "", false: " (not healthy: " + o.Firewall.Error + ")"}[o.Firewall.Healthy || !o.Firewall.Enabled])
	fmt.Fprintf(tw, "IPDB\t%s, %d entries\n", enabled(o.IPDB.Enabled), o.IPDB.Entries)
	if ai != nil {
		fmt.Fprintf(tw, "AI scanner\t%s, %s, scope %s\n", enabled(ai["enabled"]), show(ai["provider"]), show(ai["scope"]))
	}
	fmt.Fprintf(tw, "Threats (30 days)\t%d, %d open, %d quarantined\n", o.Summary.Scanner.Threats30d, o.Summary.Scanner.Open, o.Summary.Scanner.Quarantined)
	return tw.Flush()
}

func cliScanner(c *cli) error {
	if on, ok, err := c.onOff("--realtime"); err != nil {
		return err
	} else if ok {
		return c.set("scanner", map[string]any{"realtime": on})
	}
	if on, ok := c.enableFlag(); ok {
		return c.set("scanner", map[string]any{"enabled": on})
	}
	if c.has("--restart") {
		fmt.Fprintln(c.out, "the scanner reloads its settings automatically; nothing to restart")
		return nil
	}
	return c.printSection("scanner", "enabled", "realtime", "daily_scan", "weekly_scan", "virus_action", "suspicious_action", "binary_action",
		"use_clamav", "yara", "feeds", "wp_core_repair", "trim", "trim_max_percent", "max_file_size_mb", "keep_days")
}

func cliAIScan(c *cli) error {
	f := map[string]any{}
	if on, ok := c.enableFlag(); ok {
		f["enabled"] = on
	}
	if v := c.val("--provider"); v != "" {
		f["provider"] = v
	}
	if v := c.val("--scope"); v != "" {
		f["scope"] = v
	}
	for flag, field := range map[string]string{"--learn": "learn", "--act": "act", "--restore-clean": "restore_clean"} {
		on, ok, err := c.onOff(flag)
		if err != nil {
			return err
		}
		if ok {
			f[field] = on
		}
	}
	if v := c.val("--max-per-hour"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.New("--max-per-hour takes a number")
		}
		f["max_per_hour"] = n
	}
	if c.has("--sync") {
		var r struct {
			Verdicts int `json:"verdicts"`
		}
		if err := c.callJSON("ai.sync", nil, &r); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "fleet knowledge synced: %d new verdicts\n", r.Verdicts)
	}
	if v := c.val("--check"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return errors.New("--check takes a log ID (xgcli logs)")
		}
		var r map[string]any
		if err := c.callJSON("ai.check", map[string]any{"id": id}, &r); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "%s (%v%%) by %s: %s\n", show(r["verdict"]), r["confidence"], show(r["model"]), show(r["reason"]))
		return nil
	}
	if len(f) > 0 {
		return c.set("ai", f)
	}
	if c.has("--sync") {
		return nil
	}
	return c.printSection("ai")
}

func cliWatch(c *cli) error {
	var r struct {
		Users []struct {
			Name    string `json:"name"`
			Home    string `json:"home"`
			WebRoot string `json:"web_root"`
		} `json:"users"`
	}
	if err := c.callJSON("scanner.paths", nil, &r); err != nil {
		return err
	}
	if c.has("--add") || c.has("--remove") {
		return errors.New("XMart Guard watches every hosting account's home directory automatically; use `xgcli whitelist --file` to exclude paths")
	}
	for _, u := range r.Users {
		fmt.Fprintf(c.out, "%-16s %s\n", u.Name, u.Home)
	}
	return nil
}

func cliWhitelist(c *cli) error {
	switch {
	case c.has("--user"):
		return c.listEdit("scanner", "whitelist_users", "--user")
	case c.has("--file"):
		return c.listEdit("scanner", "whitelist_paths", "--file")
	}
	return errors.New("use --user or --file with --list, --add or --remove")
}

func cliBlacklist(c *cli) error {
	if !c.has("--file") {
		return errors.New("use --file with --list, --add or --remove")
	}
	return c.listEdit("scanner", "blacklist_names", "--file")
}

func cliFileAction(c *cli) error {
	f := map[string]any{}
	for flag, field := range map[string]string{"--virus": "virus_action", "--suspicious": "suspicious_action", "--binary": "binary_action"} {
		if v := c.val(flag); v != "" {
			a, err := actionName(v)
			if err != nil {
				return err
			}
			f[field] = a
		}
	}
	if on, ok, err := c.onOff("--symbolic-link"); err != nil {
		return err
	} else if ok {
		f["delete_symlinks"] = on
	}
	if len(f) == 0 {
		return c.printSection("scanner", "virus_action", "suspicious_action", "binary_action", "delete_symlinks")
	}
	return c.set("scanner", f)
}

func cliTrim(c *cli) error {
	f := map[string]any{}
	if on, ok := c.enableFlag(); ok {
		f["trim"] = on
	}
	if v := c.val("--max"); v != "" {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "%"))
		if err != nil {
			return errors.New("--max takes a percentage")
		}
		f["trim_max_percent"] = n
	}
	if len(f) == 0 {
		return c.printSection("scanner", "trim", "trim_max_percent")
	}
	return c.set("scanner", f)
}

type cliScanRow struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Files      int64  `json:"files"`
	Infected   int64  `json:"infected"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`
	Error      string `json:"error"`
}

type cliFinding struct {
	ID           int64  `json:"id"`
	ScanID       int64  `json:"scan_id"`
	Path         string `json:"path"`
	Owner        string `json:"owner"`
	Category     string `json:"category"`
	Signature    string `json:"signature"`
	SHA256       string `json:"sha256"`
	Status       string `json:"status"`
	CreatedAt    int64  `json:"created_at"`
	AIVerdict    string `json:"ai_verdict"`
	AIConfidence int    `json:"ai_confidence"`
	AIInjected   bool   `json:"ai_injected"`
}

func (c *cli) scans() ([]cliScanRow, error) {
	var r struct {
		Scans []cliScanRow `json:"scans"`
	}
	err := c.callJSON("scan.list", nil, &r)
	return r.Scans, err
}

func ts(t int64) string {
	if t == 0 {
		return "-"
	}
	return time.Unix(t, 0).Format("2006-01-02 15:04:05")
}

func cliScan(c *cli) error {
	idArg := func(flag string) (int64, error) {
		n, err := strconv.ParseInt(c.val(flag), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s takes a scan ID", flag)
		}
		return n, nil
	}
	switch {
	case c.has("--list"):
		list, err := c.scans()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tKIND\tSTATUS\tFILES\tINFECTED\tSTARTED\tTARGET")
		for _, s := range list {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%d\t%s\t%s\n", s.ID, s.Kind, s.Status, s.Files, s.Infected, ts(s.StartedAt), s.Target)
		}
		return tw.Flush()
	case c.has("--stop"):
		id, err := idArg("--stop")
		if err != nil {
			return err
		}
		if err := c.callJSON("scan.stop", map[string]any{"ID": id}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "scan %d stopped\n", id)
		return nil
	case c.has("--delete"):
		id, err := idArg("--delete")
		if err != nil {
			return err
		}
		if err := c.callJSON("scan.delete", map[string]any{"ID": id}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "scan %d deleted\n", id)
		return nil
	case c.has("--result"):
		id, err := idArg("--result")
		if err != nil {
			return err
		}
		return c.findings(map[string]any{"scan_id": id}, c.raw("--export"))
	}
	kind, path := "", ""
	switch {
	case c.has("--all"):
		kind = "full"
	case c.has("--daily"):
		kind = "daily"
	case c.has("--weekly"):
		kind = "weekly"
	case c.has("--path"):
		kind, path = "path", c.raw("--path")
		if path == "" {
			return errors.New("--path needs a directory")
		}
	default:
		return errors.New("choose --all, --path DIR, --daily or --weekly (or --list, --result ID, --stop ID, --delete ID)")
	}
	var r struct {
		ID int64 `json:"id"`
	}
	if err := c.callJSON("scan.start", map[string]any{"kind": kind, "path": path, "initiator": "xgcli"}, &r); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "scan %d started\n", r.ID)
	if c.has("--no-wait") {
		return nil
	}
	for {
		time.Sleep(2 * time.Second)
		list, err := c.scans()
		if err != nil {
			return err
		}
		for _, s := range list {
			if s.ID != r.ID {
				continue
			}
			fmt.Fprintf(c.out, "\r%s: %d files, %d infected   ", s.Status, s.Files, s.Infected)
			if s.Status != "running" && s.Status != "queued" {
				fmt.Fprintln(c.out)
				if s.Error != "" {
					fmt.Fprintln(c.out, "error:", s.Error)
				}
				if s.Infected > 0 {
					fmt.Fprintf(c.out, "details: xgcli scan --result %d\n", s.ID)
				}
				return nil
			}
		}
	}
}

// findings prints (or exports as CSV) detections matching a filter.
func (c *cli) findings(filter map[string]any, export string) error {
	limit, _ := strconv.Atoi(c.val("--limit"))
	if limit <= 0 {
		limit = 50
	}
	page, _ := strconv.Atoi(c.val("--page"))
	if page <= 0 {
		page = 1
	}
	filter["limit"], filter["offset"] = limit, (page-1)*limit
	if export != "" {
		filter["limit"], filter["offset"] = 500, 0
	}
	var r struct {
		Findings []cliFinding `json:"findings"`
		Total    int          `json:"total"`
	}
	if err := c.callJSON("findings.list", filter, &r); err != nil {
		return err
	}
	if export != "" {
		f, err := os.Create(export)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		_ = w.Write([]string{"id", "time", "path", "owner", "category", "signature", "status", "ai_verdict", "sha256"})
		for _, x := range r.Findings {
			_ = w.Write([]string{strconv.FormatInt(x.ID, 10), ts(x.CreatedAt), x.Path, x.Owner, x.Category, x.Signature, x.Status, x.AIVerdict, x.SHA256})
		}
		w.Flush()
		fmt.Fprintf(c.out, "%d detections written to %s\n", len(r.Findings), export)
		return w.Error()
	}
	tw := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "LOG ID\tTIME\tSTATUS\tCATEGORY\tSIGNATURE\tAI\tUSER\tFILE")
	for _, x := range r.Findings {
		ai := "-"
		if x.AIVerdict != "" {
			ai = fmt.Sprintf("%s %d%%", x.AIVerdict, x.AIConfidence)
			if x.AIInjected {
				ai += " (trim)"
			}
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.ID, ts(x.CreatedAt), x.Status, x.Category, x.Signature, ai, x.Owner, x.Path)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "page %d, %d of %d detections\n", page, len(r.Findings), r.Total)
	return nil
}

func cliLogs(c *cli) error {
	f := map[string]any{"status": c.val("--status"), "category": c.val("--category"), "q": c.raw("--file")}
	return c.findings(f, c.raw("--export"))
}

func cliView(c *cli) error {
	if len(c.args) == 0 {
		return errors.New("usage: xgcli view LOG_ID")
	}
	id, err := strconv.ParseInt(c.args[0], 10, 64)
	if err != nil {
		return errors.New("usage: xgcli view LOG_ID")
	}
	var r struct {
		Content   string `json:"content"`
		Truncated bool   `json:"truncated"`
		Binary    bool   `json:"binary"`
		AI        *struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
			Cut     []struct {
				From int `json:"from"`
				To   int `json:"to"`
			} `json:"cut"`
		} `json:"ai"`
	}
	if err := c.callJSON("finding.content", map[string]any{"id": id}, &r); err != nil {
		return err
	}
	if r.Binary {
		return errors.New("binary file: not shown")
	}
	marked := map[int]bool{}
	if r.AI != nil {
		fmt.Fprintf(c.out, "# AI: %s: %s\n", r.AI.Verdict, r.AI.Reason)
		for _, x := range r.AI.Cut {
			for n := x.From; n <= x.To; n++ {
				marked[n] = true
			}
		}
	}
	for i, line := range strings.Split(r.Content, "\n") {
		mark := " "
		if marked[i+1] {
			mark = ">"
		}
		fmt.Fprintf(c.out, "%s%5d | %s\n", mark, i+1, line)
	}
	if r.Truncated {
		fmt.Fprintln(c.out, "# (only the first 512 KB are shown)")
	}
	return nil
}

var relTime = regexp.MustCompile(`^-?\s*(\d+)\s*(minute|min|hour|day|week)s?$`)

// parseWhen reads "now", "-24 hours", "01-08-2023", "2023-08-01" or "2023-08-01 10:00".
func parseWhen(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "now" {
		return time.Now().Unix(), nil
	}
	if m := relTime.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"minute": time.Minute, "min": time.Minute, "hour": time.Hour, "day": 24 * time.Hour, "week": 7 * 24 * time.Hour}[m[2]]
		return time.Now().Add(-time.Duration(n) * unit).Unix(), nil
	}
	for _, layout := range []string{"02-01-2006", "2006-01-02", "2006-01-02 15:04", "02-01-2006 15:04", time.RFC3339} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("cannot read the time %q", s)
}

func cliLogAction(c *cli) error {
	action := ""
	for _, a := range []string{"restore", "quarantine", "delete", "disable", "trim", "ignore", "clear"} {
		if c.has("--" + a) {
			action = a
		}
	}
	if action == "" {
		return errors.New("choose --restore, --quarantine, --delete, --disable, --trim, --clear or --ignore, plus filters")
	}
	var ids []int64
	if v := c.vals("--log-id"); len(v) > 0 {
		for _, x := range v {
			n, err := strconv.ParseInt(x, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid log ID %q", x)
			}
			ids = append(ids, n)
		}
	} else {
		user, file, sig := c.val("--user"), c.raw("--file"), c.raw("--signature")
		var from, to int64
		var err error
		if v := c.raw("--from"); v != "" {
			if from, err = parseWhen(v); err != nil {
				return err
			}
		}
		if v := c.raw("--to"); v != "" {
			if to, err = parseWhen(v); err != nil {
				return err
			}
		}
		scanID, _ := strconv.ParseInt(c.val("--scan-id"), 10, 64)
		if user == "" && file == "" && sig == "" && from == 0 && to == 0 && scanID == 0 {
			return errors.New("add at least one filter (--user, --file, --signature, --from, --to, --scan-id or --log-id)")
		}
		q := file
		if q == "" {
			q = sig
		}
		for offset := 0; ; offset += 500 {
			var r struct {
				Findings []cliFinding `json:"findings"`
				Total    int          `json:"total"`
			}
			if err := c.callJSON("findings.list", map[string]any{"scan_id": scanID, "q": q, "limit": 500, "offset": offset}, &r); err != nil {
				return err
			}
			for _, f := range r.Findings {
				if (user == "" || f.Owner == user) && (file == "" || strings.Contains(f.Path, file)) && (sig == "" || strings.Contains(f.Signature, sig)) &&
					(from == 0 || f.CreatedAt >= from) && (to == 0 || f.CreatedAt <= to) {
					ids = append(ids, f.ID)
				}
			}
			if offset+500 >= r.Total || len(r.Findings) == 0 {
				break
			}
		}
	}
	if len(ids) == 0 {
		fmt.Fprintln(c.out, "no matching logs")
		return nil
	}
	done, failed := 0, 0
	for i := 0; i < len(ids); i += 500 {
		batch := ids[i:min(len(ids), i+500)]
		var r struct {
			Done   int               `json:"done"`
			Failed map[string]string `json:"failed"`
		}
		if err := c.callJSON("finding.action", map[string]any{"ids": batch, "action": action}, &r); err != nil {
			return err
		}
		done += r.Done
		failed += len(r.Failed)
		for id, msg := range r.Failed {
			fmt.Fprintf(c.out, "log %s: %s\n", id, msg)
		}
	}
	fmt.Fprintf(c.out, "%s: %d done, %d failed\n", action, done, failed)
	return nil
}

// ------------------------------------------------------------------ firewall

func portField(name string) (string, error) {
	f := map[string]string{"tcp-in": "tcp_in", "tcp-out": "tcp_out", "udp-in": "udp_in", "udp-out": "udp_out"}[name]
	if f == "" {
		return "", errors.New("--port takes tcp-in, tcp-out, udp-in or udp-out")
	}
	return f, nil
}

func cliFirewall(c *cli) error {
	switch {
	case c.has("--status"):
		var r struct {
			Firewall struct {
				Enabled  bool   `json:"enabled"`
				Provider string `json:"provider"`
				Healthy  bool   `json:"healthy"`
				Error    string `json:"error"`
			} `json:"firewall"`
		}
		if err := c.callJSON("stats.get", nil, &r); err != nil {
			return err
		}
		st := r.Firewall
		fmt.Fprintf(c.out, "firewall %s (%s), healthy: %v %s\n", enabled(st.Enabled), st.Provider, st.Healthy, st.Error)
		return nil
	case c.has("--restart"):
		if err := c.callJSON("fw.apply", nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "firewall rules re-applied")
		return nil
	case c.has("--provider"):
		v := c.val("--provider")
		if v == "" {
			return c.printSection("firewall", "provider")
		}
		return c.set("firewall", map[string]any{"provider": v})
	case c.has("--allow-country"):
		return c.countryList("allowed_countries", "--allow-country")
	case c.has("--deny-country"):
		return c.countryList("blocked_countries", "--deny-country")
	case c.has("--ignore-country"):
		return c.countryList("ignored_countries", "--ignore-country")
	case c.has("--port"):
		field, err := portField(c.val("--port"))
		if err != nil {
			return err
		}
		sec, err := c.section("firewall")
		if err != nil {
			return err
		}
		cur := strings.FieldsFunc(show(sec[field]), func(r rune) bool { return r == ',' || r == ' ' })
		switch {
		case c.has("--add"):
			for _, p := range c.vals("--add") {
				if !contains(cur, p) {
					cur = append(cur, p)
				}
			}
		case c.has("--remove"):
			rm := c.vals("--remove")
			var keep []string
			for _, p := range cur {
				if !contains(rm, p) {
					keep = append(keep, p)
				}
			}
			cur = keep
		default:
			fmt.Fprintln(c.out, strings.Join(cur, ","))
			return nil
		}
		return c.set("firewall", map[string]any{field: strings.Join(cur, ",")})
	case c.has("--dos-threshold"):
		n, err := strconv.Atoi(c.val("--dos-threshold"))
		if err != nil {
			return c.printSection("firewall", "dos_threshold")
		}
		return c.set("firewall", map[string]any{"dos_threshold": n})
	}
	for flag, target := range map[string][2]string{
		"--captcha":         {"firewall", "captcha"},
		"--ipdb":            {"ipdb", "enabled"},
		"--ipdb-log":        {"ipdb", "log"},
		"--ipdb-captcha":    {"ipdb", "captcha"},
		"--ipdb-report":     {"ipdb", "report"},
		"--port-filter":     {"firewall", "port_filter"},
		"--dos":             {"firewall", "dos"},
		"--block-ai-bots":   {"waf", "ai_bots"},
		"--block-seo-bots":  {"waf", "seo_bots"},
		"--waf-ban":         {"firewall", "waf_ban"},
		"--log-blocked":     {"firewall", "log_blocked"},
		"--bruteforce":      {"firewall", "bruteforce"},
		"--block-bad-bots":  {"waf", "bad_bots"},
		"--block-meta-bots": {"waf", "seo_bots"},
	} {
		if !c.has(flag) {
			continue
		}
		on, ok, err := c.onOff(flag)
		if err != nil {
			return err
		}
		if !ok {
			sec, err := c.section(target[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(c.out, "%s: %s\n", strings.TrimPrefix(flag, "--"), enabled(sec[target[1]]))
			return nil
		}
		return c.set(target[0], map[string]any{target[1]: on})
	}
	if on, ok := c.enableFlag(); ok {
		return c.set("firewall", map[string]any{"enabled": on})
	}
	return c.printSection("firewall")
}

func (c *cli) countryList(field, flag string) error {
	sec, err := c.section("firewall")
	if err != nil {
		return err
	}
	cur := strList(sec[field])
	switch {
	case c.has("--list"):
		fmt.Fprintln(c.out, strings.Join(cur, " "))
		return nil
	case c.has("--remove"):
		rm := c.vals("--remove")
		var keep []string
		for _, x := range cur {
			if !contains(rm, x) {
				keep = append(keep, x)
			}
		}
		if keep == nil {
			keep = []string{}
		}
		return c.set("firewall", map[string]any{field: keep})
	}
	add := c.vals(flag)
	if len(add) == 0 {
		fmt.Fprintln(c.out, strings.Join(cur, " "))
		return nil
	}
	for _, x := range add {
		if !contains(cur, x) {
			cur = append(cur, strings.ToUpper(x))
		}
	}
	return c.set("firewall", map[string]any{field: cur})
}

var ipKinds = map[string]string{"--allow": "allow", "--deny": "deny", "--ignore": "ignore", "--temp-allow": "tempallow", "--temp-ban": "tempban"}

func parseExpiry(s string) (int, error) {
	if s == "" {
		return 24 * 60, nil
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid --expiry %q (e.g. 30m, 2h, 7d)", s)
	}
	switch s[len(s)-1] {
	case 'm':
		return n, nil
	case 'h':
		return n * 60, nil
	case 'd':
		return n * 24 * 60, nil
	}
	return 0, fmt.Errorf("invalid --expiry %q (e.g. 30m, 2h, 7d)", s)
}

// readSource expands a file path or URL into its entries (one per line).
func readSource(src string) ([]string, error) {
	var raw []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		hc := &http.Client{Timeout: time.Minute}
		res, herr := hc.Get(src)
		if herr != nil {
			return nil, herr
		}
		defer res.Body.Close()
		raw, err = io.ReadAll(io.LimitReader(res.Body, 20<<20))
	} else {
		raw, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			out = append(out, strings.Fields(line)[0])
		}
	}
	return out, nil
}

func cliIP(c *cli) error {
	if v := c.val("--check"); v != "" {
		var r struct {
			Status    string `json:"status"`
			Protected bool   `json:"protected"`
			Matches   []struct {
				Kind    string `json:"kind"`
				CIDR    string `json:"cidr"`
				Comment string `json:"comment"`
			} `json:"matches"`
		}
		if err := c.callJSON("fw.check", map[string]any{"IP": v}, &r); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "%s: %s", v, r.Status)
		if r.Protected {
			fmt.Fprint(c.out, " (this server or the portal: never blocked)")
		}
		fmt.Fprintln(c.out)
		for _, m := range r.Matches {
			fmt.Fprintf(c.out, "  %s %s %s\n", m.Kind, m.CIDR, m.Comment)
		}
		return nil
	}
	if v := c.val("--unblock"); v != "" {
		if err := c.callJSON("fw.unblock", map[string]any{"Addr": v}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "%s unblocked\n", v)
		return nil
	}
	if c.has("--ddns") {
		return c.listEditDDNS()
	}
	for _, src := range []struct{ flag, kind string }{{"--allow-source", "allow"}, {"--deny-source", "deny"}} {
		if v := c.val(src.flag); v != "" && !c.has("--list") && !c.has("--remove") {
			entries, err := readSource(v)
			if err != nil {
				return err
			}
			added := 0
			for _, e := range entries {
				if err := c.callJSON("fw.add", map[string]any{"kind": src.kind, "addr": e, "comment": "source: " + v}, nil); err == nil {
					added++
				}
			}
			fmt.Fprintf(c.out, "%d of %d entries from %s added to the %s list\n", added, len(entries), v, src.kind)
			return nil
		}
	}
	for flag, kind := range ipKinds {
		if !c.has(flag) {
			continue
		}
		switch {
		case c.has("--list"):
			var r struct {
				Rules []struct {
					CIDR      string `json:"cidr"`
					Comment   string `json:"comment"`
					CreatedAt int64  `json:"created_at"`
					ExpiresAt int64  `json:"expires_at"`
				} `json:"rules"`
			}
			if err := c.callJSON("fw.list", map[string]any{"Kind": kind}, &r); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(c.out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ADDRESS\tADDED\tEXPIRES\tCOMMENT")
			for _, x := range r.Rules {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.CIDR, ts(x.CreatedAt), ts(x.ExpiresAt), x.Comment)
			}
			return tw.Flush()
		case c.has("--remove"):
			for _, a := range c.vals("--remove") {
				if err := c.callJSON("fw.remove", map[string]any{"Kind": kind, "Addr": a}, nil); err != nil {
					return fmt.Errorf("%s: %w", a, err)
				}
				fmt.Fprintf(c.out, "%s removed from the %s list\n", a, kind)
			}
			return nil
		}
		addrs := c.vals(flag)
		if len(addrs) == 0 {
			return fmt.Errorf("%s needs one or more IPs/CIDRs (or --list / --remove)", flag)
		}
		minutes := 0
		if kind == "tempallow" || kind == "tempban" {
			var err error
			if minutes, err = parseExpiry(c.val("--expiry")); err != nil {
				return err
			}
		}
		for _, a := range addrs {
			if _, err := os.Stat(a); err == nil {
				entries, rerr := readSource(a)
				if rerr != nil {
					return rerr
				}
				for _, e := range entries {
					_ = c.callJSON("fw.add", map[string]any{"kind": kind, "addr": e, "comment": c.raw("--reason"), "minutes": minutes}, nil)
				}
				fmt.Fprintf(c.out, "%d entries from %s added to the %s list\n", len(entries), a, kind)
				continue
			}
			if err := c.callJSON("fw.add", map[string]any{"kind": kind, "addr": a, "comment": c.raw("--reason"), "minutes": minutes}, nil); err != nil {
				return fmt.Errorf("%s: %w", a, err)
			}
			fmt.Fprintf(c.out, "%s added to the %s list\n", a, kind)
		}
		return nil
	}
	return errors.New("use --check, --allow, --deny, --ignore, --temp-allow, --temp-ban, --unblock, --ddns, --allow-source or --deny-source")
}

func (c *cli) listEditDDNS() error {
	sec, err := c.section("firewall")
	if err != nil {
		return err
	}
	cur := strList(sec["ddns"])
	switch {
	case c.has("--list"):
		for _, x := range cur {
			fmt.Fprintln(c.out, x)
		}
		return nil
	case c.has("--remove"):
		rm := c.vals("--remove")
		var keep []string
		for _, x := range cur {
			if !contains(rm, x) {
				keep = append(keep, x)
			}
		}
		if keep == nil {
			keep = []string{}
		}
		return c.set("firewall", map[string]any{"ddns": keep})
	}
	for _, x := range c.vals("--ddns") {
		if !contains(cur, x) {
			cur = append(cur, x)
		}
	}
	return c.set("firewall", map[string]any{"ddns": cur})
}

func cliLFD(c *cli) error {
	switch {
	case c.has("--list-jails"):
		var r struct {
			Jails []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"jails"`
		}
		if err := c.callJSON("fw.meta", nil, &r); err != nil {
			return err
		}
		for _, j := range r.Jails {
			fmt.Fprintf(c.out, "%-20s %s\n", j.ID, j.Name)
		}
		return nil
	case c.has("--ignore"):
		if !c.has("--list") && !c.has("--remove") {
			c.args = append(c.args, "--add")
			c.args = append(c.args, c.vals("--ignore")...)
		}
		return c.listEdit("firewall", "excluded_jails", "--ignore")
	case c.has("--status"):
		return c.printSection("firewall", "bruteforce", "bf_threshold", "bf_window_minutes", "ban_minutes", "excluded_jails")
	case c.has("--restart"):
		return c.callJSON("fw.apply", nil, nil)
	}
	return c.toggle("firewall", "bruteforce", "intrusion defense (brute force protection)")
}

var wafModules = map[string]string{
	"scanner": "upload_scan", "upload-scan": "upload_scan", "webshell": "webshell", "bots": "bad_bots", "crawler": "bad_bots",
	"seo-bots": "seo_bots", "ai-bots": "ai_bots", "wordpress": "wordpress", "sensitive": "sensitive_files", "bruteforce": "bruteforce",
	"php-upload": "block_php_upload",
}

func cliWAF(c *cli) error {
	if c.has("--whitelist") {
		ids := c.vals("--add")
		rm := c.vals("--remove")
		if len(ids) == 0 && len(rm) == 0 {
			return c.printSection("waf", "disabled_rules")
		}
		sec, err := c.section("waf")
		if err != nil {
			return err
		}
		cur := map[int]bool{}
		for _, v := range strList(sec["disabled_rules"]) {
			n, _ := strconv.Atoi(v)
			cur[n] = true
		}
		for _, v := range ids {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid rule ID %q", v)
			}
			cur[n] = true
		}
		for _, v := range rm {
			n, _ := strconv.Atoi(v)
			delete(cur, n)
		}
		list := []int{}
		for n := range cur {
			list = append(list, n)
		}
		sort.Ints(list)
		if c.has("--domain") {
			fmt.Fprintln(c.out, "note: rules are whitelisted server-wide; to skip a whole site use: xgcli waf --whitelist-domain --add DOMAIN")
		}
		return c.set("waf", map[string]any{"disabled_rules": list})
	}
	if c.has("--whitelist-domain") {
		return c.listEdit("waf", "whitelist_domains", "--whitelist-domain")
	}
	if c.has("--whitelist-ip") {
		return c.listEdit("waf", "whitelist_ips", "--whitelist-ip")
	}
	on, ok := c.enableFlag()
	if !ok {
		return c.printSection("waf")
	}
	mods := c.vals("--enable")
	if !on {
		mods = c.vals("--disable")
	}
	if len(mods) == 0 {
		return c.set("waf", map[string]any{"enabled": on})
	}
	f := map[string]any{}
	for _, m := range mods {
		field, ok := wafModules[m]
		if !ok {
			return fmt.Errorf("unknown WAF module %q", m)
		}
		f[field] = on
	}
	return c.set("waf", f)
}

func cliSuspend(c *cli) error {
	on, ok := c.enableFlag()
	if !ok {
		return c.printSection("auto_suspend")
	}
	mods := c.vals("--enable")
	if !on {
		mods = c.vals("--disable")
	}
	if len(mods) == 0 {
		return c.set("auto_suspend", map[string]any{"enabled": on})
	}
	f := map[string]any{}
	for _, m := range mods {
		switch m {
		case "virus":
			f["enabled"] = on
		case "domain":
			f["on_domain_blacklist"] = on
		default:
			return fmt.Errorf("unknown value %q (virus, domain)", m)
		}
	}
	return c.set("auto_suspend", f)
}

func cliRootkit(c *cli) error {
	if c.has("--run") {
		var r struct {
			Warnings int `json:"warnings"`
		}
		if err := c.callJSON("monitor.rootkit", nil, &r); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "rootkit check finished: %d warnings (see the Process & Cron Monitor page)\n", r.Warnings)
		return nil
	}
	return c.toggle("rootkit", "enabled", "rootkit check")
}

func cliProcess(c *cli) error {
	switch {
	case c.has("--whitelist-users"):
		return c.listEdit("processes", "whitelist_users", "--whitelist-users")
	case c.has("--whitelist"):
		return c.listEdit("processes", "whitelist_strings", "--whitelist")
	}
	if on, ok, err := c.onOff("--kill"); err != nil {
		return err
	} else if ok {
		return c.set("processes", map[string]any{"kill": on})
	}
	return c.toggle("processes", "enabled", "process monitor")
}

func cliCron(c *cli) error {
	if c.has("--whitelist-users") {
		return c.listEdit("cron", "whitelist_users", "--whitelist-users")
	}
	return c.toggle("cron", "enabled", "cron monitor")
}

func cliOSM(c *cli) error {
	for flag, field := range map[string]string{"--whitelist-ips": "whitelist_ips", "--whitelist-email": "whitelist_senders",
		"--whitelist-cwd-prefix": "whitelist_paths", "--spam-pattern": "spam_patterns"} {
		if c.has(flag) {
			return c.listEdit("osm", field, flag)
		}
	}
	f := map[string]any{}
	for flag, field := range map[string]string{"--minute-threshold": "per_minute", "--hourly-threshold": "per_hour"} {
		if v := c.val(flag); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("%s takes a number", flag)
			}
			f[field] = n
		}
	}
	if v := c.val("--action"); v != "" {
		f["action"] = v
	}
	if on, ok := c.enableFlag(); ok {
		f["enabled"] = on
	}
	if len(f) == 0 {
		return c.printSection("osm")
	}
	return c.set("osm", f)
}

func cliReputation(c *cli) error {
	if c.has("--check") {
		ip := c.val("--check")
		var r struct {
			Reports map[string]struct {
				ListedOn int `json:"listed_on"`
				Results  []struct {
					RBL    string `json:"rbl"`
					Listed bool   `json:"listed"`
				} `json:"results"`
			} `json:"reports"`
		}
		if err := c.callJSON("reputation.check", map[string]any{"IP": ip}, &r); err != nil {
			return err
		}
		for addr, rep := range r.Reports {
			fmt.Fprintf(c.out, "%s: listed on %d lists\n", addr, rep.ListedOn)
			for _, x := range rep.Results {
				if x.Listed {
					fmt.Fprintf(c.out, "  %s\n", x.RBL)
				}
			}
		}
		return nil
	}
	if c.has("--result") {
		data, err := c.call("reputation.get", nil)
		if err != nil {
			return err
		}
		var v any
		_ = json.Unmarshal(data, &v)
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if c.has("--add-ip") || c.has("--remove-ip") {
		if c.has("--add-ip") {
			c.args = append(c.args, "--add")
			c.args = append(c.args, c.vals("--add-ip")...)
		} else {
			c.args = append(c.args, "--remove")
			c.args = append(c.args, c.vals("--remove-ip")...)
		}
		return c.listEdit("reputation", "ips", "--add-ip")
	}
	if c.has("--list-hosts") {
		return c.printSection("reputation", "rbls")
	}
	return c.toggle("reputation", "enabled", "IP reputation monitoring")
}

func cliDBScan(c *cli) error {
	if c.has("--scan") || c.has("--update") {
		if err := c.callJSON("cms.scan", nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "website and database scan started (see the portal's DB Scanner page)")
		return nil
	}
	if c.has("--whitelist") {
		sec, err := c.section("scanner")
		if err != nil {
			return err
		}
		type ex struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		}
		var cur []ex
		b, _ := json.Marshal(sec["db_whitelist"])
		_ = json.Unmarshal(b, &cur)
		for _, id := range c.vals("--add") {
			cur = append(cur, ex{ID: strings.TrimPrefix(id, "DB."), Reason: c.raw("--reason")})
		}
		if rm := c.vals("--remove"); len(rm) > 0 {
			var keep []ex
			for _, x := range cur {
				if !contains(rm, x.ID) && !contains(rm, "DB."+x.ID) {
					keep = append(keep, x)
				}
			}
			cur = keep
		}
		if cur == nil {
			cur = []ex{}
		}
		return c.set("scanner", map[string]any{"db_whitelist": cur})
	}
	return c.toggle("cms", "db_scan", "database scanner")
}

func cliNotification(c *cli) error {
	f := map[string]any{}
	if v := c.val("--primary-email"); v != "" {
		f["email"] = v
	}
	if v := c.val("--secondary-email"); v != "" {
		f["extra_email"] = v
	}
	names := map[string]string{"virus": "on_virus", "suspicious": "on_suspicious", "binary": "on_binary", "iprep": "on_blacklist",
		"ban": "on_ban", "daily_report": "daily_report"}
	userNames := map[string]string{"infected_files": "user_infected", "account_suspension": "user_suspension", "wp_autoupdate": "user_patches"}
	apply := func(list []string, on bool, m map[string]string) error {
		for _, x := range list {
			field, ok := m[x]
			if !ok {
				return fmt.Errorf("unknown notification %q", x)
			}
			f[field] = on
		}
		return nil
	}
	if c.has("--enable") || c.has("--disable") {
		on := c.has("--enable")
		list := c.vals("--enable")
		if !on {
			list = c.vals("--disable")
		}
		if len(list) == 0 {
			for _, v := range []string{"virus", "iprep"} {
				list = append(list, v)
			}
		}
		if err := apply(list, on, names); err != nil {
			return err
		}
	}
	if err := apply(c.vals("--enable-user"), true, userNames); err != nil {
		return err
	}
	if err := apply(c.vals("--disable-user"), false, userNames); err != nil {
		return err
	}
	if v := c.val("--cms-threats-user"); v != "" {
		f["user_outdated"] = v
	}
	if v := c.vals("--excluded-users"); len(v) > 0 {
		f["exclude_users"] = v
	}
	if len(f) == 0 {
		return c.printSection("notifications")
	}
	return c.set("notifications", f)
}

func cliCMS(c *cli) error {
	switch {
	case c.has("--wp-whitelist"):
		return c.listEdit("cms", "exclude_users", "--wp-whitelist")
	case c.has("--plugin-blacklist"):
		return c.listEdit("cms", "blacklist_plugins", "--plugin-blacklist")
	case c.has("--scan"):
		if err := c.callJSON("cms.scan", nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "CMS scan started")
		return nil
	}
	f := map[string]any{}
	for flag, field := range map[string]string{"--wp-checksum": "core_check", "--wp-cron": "wp_cron", "--wp-auto-update": "auto_update",
		"--wp-addon-check": "enabled", "--vulns": "vulns"} {
		on, ok, err := c.onOff(flag)
		if err != nil {
			return err
		}
		if ok {
			f[field] = on
		}
	}
	if v := c.val("--interval"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.New("--interval takes hours (1, 2, 3, 4, 6, 8 or 12)")
		}
		f["wp_cron_hours"] = n
	}
	if len(f) == 0 {
		return c.printSection("cms")
	}
	return c.set("cms", f)
}

func cliUpload(c *cli) error {
	if on, ok, err := c.onOff("--block-php"); err != nil {
		return err
	} else if ok {
		return c.set("waf", map[string]any{"block_php_upload": on})
	}
	if c.has("--whitelist") {
		return errors.New("uploads are checked by the malware engine; whitelist a file with: xgcli whitelist --file PATH")
	}
	if on, ok := c.enableFlag(); ok {
		return c.set("waf", map[string]any{"upload_scan": on})
	}
	return c.printSection("waf", "upload_scan", "block_php_upload")
}

// Exported settings never contain secrets (API keys and tokens are masked
// by the agent and skipped on import).
func cliConfig(c *cli) error {
	switch {
	case c.has("--export"):
		s, err := c.settings()
		if err != nil {
			return err
		}
		name := c.raw("--export")
		if name == "" {
			name = "xmartguard-settings-" + time.Now().Format("20060102") + ".json"
		}
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(name, append(b, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "settings exported to", name)
		return nil
	case c.has("--import"):
		src := c.raw("--import")
		var raw []byte
		var err error
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			res, herr := (&http.Client{Timeout: time.Minute}).Get(src)
			if herr != nil {
				return herr
			}
			defer res.Body.Close()
			raw, err = io.ReadAll(io.LimitReader(res.Body, 4<<20))
		} else {
			raw, err = os.ReadFile(src)
		}
		if err != nil {
			return err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("not a settings file: %w", err)
		}
		if err := c.callJSON("settings.set", doc, nil); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "settings imported from", src)
		return nil
	}
	s, err := c.settings()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func cliUpdate(c *cli) error {
	fmt.Fprintln(c.out, "XMart Guard", version.Version)
	fmt.Fprintln(c.out, "Agents are updated from the portal (server » Update agent, or automatically when the portal is updated).")
	return nil
}

func cliUsage(w io.Writer) {
	fmt.Fprint(w, `
 __  ____  __            _      ____                     _
 \ \/ /  \/  | __ _ _ __| |_   / ___|_   _  __ _ _ __ __| |
  \  /| |\/| |/ _`+"`"+` | '__| __| | |  _| | | |/ _`+"`"+` | '__/ _`+"`"+` |
  /  \| |  | | (_| | |  | |_  | |_| | |_| | (_| | | | (_| |
 /_/\_\_|  |_|\__,_|_|   \__|  \____|\__,_|\__,_|_|  \__,_|

XMart Guard `+version.Version+`

Usage:  xgcli COMMAND [--options]      (run as root)

  status                          protection overview
  scanner [--enable|--disable] [--realtime enable|disable]
  dailyscan | weeklyscan [--enable|--disable]
  ai-scan [--enable|--disable] [--provider builtin|portal] [--scope suspicious|all]
          [--learn enable|disable] [--act enable|disable] [--restore-clean enable|disable] [--max-per-hour N] [--sync] [--check LOG_ID]
  watch --list                    directories the scanner watches
  whitelist --user|--file  --list | --add X[,Y] | --remove X[,Y]
  blacklist --file          --list | --add X | --remove X
  file-action [--virus A] [--suspicious A] [--binary A] [--symbolic-link enable|disable]   A: email|disable|quarantine
  cleanup [--enable|--disable]    replace infected WordPress core files with the official ones
  feeds [--enable|--disable]      public malware signatures (Linux Malware Detect, YARA web shell rules)
  trim [--enable|--disable] [--max 20]   remove only injected code the AI located

  scan --all | --path DIR | --daily | --weekly [--no-wait]
  scan --list | --result ID [--page N --limit N --export FILE.csv] | --stop ID | --delete ID
  logs [--status S] [--category C] [--file TEXT] [--page N --limit N] [--export FILE.csv]
  view LOG_ID                     show a detected file (">" marks injected lines)
  log-action --restore|--quarantine|--delete|--disable|--trim|--clear|--ignore
             [--log-id ID[,ID]] [--user U] [--file TEXT] [--signature S] [--scan-id ID] [--from '-24 hours'] [--to now]

  fw [--status|--enable|--disable|--restart] [--provider iptables|nftables]
     [--captcha|--ipdb|--ipdb-log|--ipdb-captcha|--ipdb-report|--port-filter|--dos|--waf-ban|--bruteforce
      |--log-blocked|--block-ai-bots|--block-seo-bots|--block-bad-bots  enable|disable]
     [--allow-country|--deny-country|--ignore-country  CODE | --remove CODE | --list]
     [--port tcp-in|tcp-out|udp-in|udp-out  --list | --add PORT | --remove PORT] [--dos-threshold N]
  ip --check IP | --unblock IP
     --allow|--deny|--ignore IP[,IP|FILE] [--reason TEXT] | --remove IP | --list
     --temp-allow|--temp-ban IP [--expiry 30m|2h|7d] [--reason TEXT] | --remove IP | --list
     --allow-source|--deny-source FILE|URL      --ddns NAME | --ddns --remove NAME | --ddns --list
  lfd [--enable|--disable|--status|--restart|--list-jails] [--ignore JAIL | --ignore --remove JAIL | --ignore --list]
  waf [--enable|--disable [scanner,webshell,bots,seo-bots,ai-bots,wordpress,sensitive,bruteforce,php-upload]]
      [--whitelist --add RULE_ID | --remove RULE_ID] [--whitelist-domain --add DOMAIN] [--whitelist-ip --add IP]
  bot-check [--enable|--disable]
  account-suspend [--enable|--disable [virus,domain]]
  rootkit [--enable|--disable|--run]
  process-monitor [--enable|--disable] [--kill enable|disable] [--whitelist|--whitelist-users --list|--add X|--remove X]
  cron-monitor [--enable|--disable] [--whitelist-users --list|--add U|--remove U]
  osm [--enable|--disable] [--minute-threshold N] [--hourly-threshold N] [--action notify|hold|suspend]
      [--whitelist-ips|--whitelist-email|--whitelist-cwd-prefix|--spam-pattern  --add X|--remove X]
  ip-reputation [--enable|--disable] [--check IP] [--result] [--add-ip IP] [--remove-ip IP] [--list-hosts]
  dbscan [--enable|--disable] [--scan] [--whitelist --add ID|--remove ID]
  notification [--primary-email E] [--secondary-email E] [--enable|--disable virus,suspicious,binary,iprep,ban,daily_report]
               [--enable-user|--disable-user infected_files,account_suspension,wp_autoupdate] [--cms-threats-user weekly|monthly|never]
  cms [--wp-checksum|--wp-cron|--wp-auto-update|--wp-addon-check|--vulns enable|disable] [--interval H] [--scan]
      [--wp-whitelist --add U|--remove U] [--plugin-blacklist --add SLUG|--remove SLUG]
  upload-scanner [--enable|--disable] [--block-php enable|disable]
  config [--show] [--export FILE] [--import FILE|URL]
  cloud                           portal connection status
  update                          version and update information
  version
`)
}
