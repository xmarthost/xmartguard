// Command xmartguard-agent is the XMart Guard server agent.
//
//	xmartguard-agent enroll --server URL --token TOKEN [--insecure]
//	xmartguard-agent run
//	xmartguard-agent status
//	xmartguard-agent unenroll
//	xmartguard-agent info
//	xmartguard-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/core"
	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/identity"
	"github.com/xmarthost/xmartguard/agent/internal/local"
	"github.com/xmarthost/xmartguard/agent/internal/panel"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
	"github.com/xmarthost/xmartguard/agent/internal/version"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun()
	case "status":
		err = cmdStatus()
	case "unenroll":
		err = cmdUnenroll()
	case "info":
		err = printJSON(sysinfo.Collect())
	case "check":
		err = cmdCheck(os.Args[2:])
	case "scan-upload":
		// Used by the WAF upload approver: exit 1 if the file is malware.
		os.Exit(cmdScanUpload(os.Args[2:]))
	case "ai-train":
		err = cmdAITrain(os.Args[2:])
	case "ai-score":
		err = cmdAIScore(os.Args[2:])
	case "cleanup":
		// Used by uninstall.sh: remove firewall rules from every provider and
		// unhook the WAF rules from the web server.
		_ = firewall.FindIPTables().Remove()
		_ = firewall.FindNFT().Remove()
		waf.RemoveInclude(waf.Detect())
		fmt.Println("firewall rules and WAF include removed")
	case "panel":
		err = cmdPanel(os.Args[2:])
	case "panel-cgi":
		fs := flag.NewFlagSet("panel-cgi", flag.ContinueOnError)
		mode := fs.String("mode", "whm", "whm | cpanel")
		fragment := fs.Bool("fragment", false, "omit <html> wrapper")
		raw := fs.Bool("raw", false, "no CGI headers")
		if err = fs.Parse(os.Args[2:]); err == nil {
			if *mode != "whm" && *mode != "cpanel" {
				err = errors.New("--mode must be whm or cpanel")
			} else {
				panel.ServeCGI(*mode, *fragment, *raw, os.Getenv, os.Stdin, os.Stdout)
			}
		}
	case "panel-api":
		// Used by the cPanel page: request JSON on stdin, response JSON on stdout.
		body, rerr := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if rerr != nil {
			err = rerr
		} else {
			os.Stdout.Write(panel.Relay(body))
		}
	case "call":
		err = cmdCall(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version.Version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `XMart Guard agent `+version.Version+`

Usage:
  xmartguard-agent enroll --server URL --token TOKEN [--insecure]
  xmartguard-agent run          run the agent (used by systemd)
  xmartguard-agent status       show enrollment status
  xmartguard-agent unenroll     remove this server from the portal
  xmartguard-agent info         print detected host inventory
  xmartguard-agent cleanup      remove all XMart Guard firewall rules
  xmartguard-agent check PATH.. scan files/directories locally and print detections (--json, --misses)
  xmartguard-agent panel install|uninstall|status   manage the WHM/cPanel plugins
  xmartguard-agent call ACTION ['{"json":"params"}']  call the running agent (root)
  xmartguard-agent version
`)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "portal URL, e.g. https://xmartguard.com")
	token := fs.String("token", "", "one-time enrollment token")
	insecure := fs.Bool("insecure", false, "skip TLS verification (testing only)")
	force := fs.Bool("force", false, "re-enroll even if already enrolled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *token == "" {
		return errors.New("--server and --token are required")
	}
	u, err := config.NormalizeURL(*server)
	if err != nil {
		return err
	}
	if cfg, err := config.Load(); err == nil && !*force {
		return fmt.Errorf("already enrolled as %s with %s (use --force to re-enroll)", cfg.ServerID, cfg.ServerURL)
	}
	id, err := identity.Generate()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serverID, err := client.Enroll(ctx, u, *token, *insecure, id)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if err := id.Save(config.KeyPath()); err != nil {
		return err
	}
	cfg := &config.Config{ServerURL: u, ServerID: serverID, InsecureTLS: *insecure}
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Printf("Enrolled. Server ID: %s\n", serverID)
	return nil
}

func load() (*config.Config, *identity.Identity, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("not enrolled (%v)", err)
	}
	id, err := identity.Load(config.KeyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read identity key: %w", err)
	}
	return cfg, id, nil
}

func cmdRun() error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, id, err := load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("starting xmartguard-agent", "version", version.Version, "portal", cfg.ServerURL)

	a, err := core.New(cfg, log)
	if err != nil {
		return err
	}
	defer a.DB.Close()
	// Exit non-zero so systemd (Restart=on-failure) starts the new binary.
	a.ExitForUpdate = func() { a.Mailer.Flush(); os.Exit(3) }
	a.Start(ctx)
	go func() {
		if err := a.LocalServer().Run(ctx); err != nil {
			log.Warn("local control socket unavailable", "err", err)
		}
	}()
	// Install the WHM/cPanel plugins (or refresh them for this version).
	if _, optOut := os.Stat(panel.OptOutPath); panel.Detected() && optOut != nil {
		if err := panel.EnsureBin(); err != nil {
			log.Warn("cannot link agent binary for the panel plugins", "err", err)
		} else if _, err := panel.Install(); err != nil {
			log.Warn("panel plugin install failed", "err", err)
		}
	}

	s := &client.Session{Cfg: cfg, ID: id, Log: log, Collector: sysinfo.NewCollector(), Security: a.SecuritySummary}
	a.Session = s
	s.Handlers = a.Handlers()
	s.Handlers["ping"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"pong": true, "version": version.Version, "time": time.Now().Unix()}, nil
	}
	s.Handlers["inventory"] = func(context.Context, json.RawMessage) (any, error) { return sysinfo.Collect(), nil }
	s.Handlers["live"] = func(_ context.Context, p json.RawMessage) (any, error) {
		var in struct {
			Seconds int `json:"seconds"`
		}
		_ = json.Unmarshal(p, &in)
		if in.Seconds <= 0 || in.Seconds > 900 {
			in.Seconds = 120
		}
		s.SetLive(time.Duration(in.Seconds) * time.Second)
		return map[string]any{"live_seconds": in.Seconds}, nil
	}
	err = s.Run(ctx)
	a.Mailer.Flush()
	if errors.Is(err, client.ErrRevoked) {
		log.Error("this server was removed from the portal; stopping. Re-install to enroll again.")
		// Exit 0 so systemd does not restart-loop (unit uses Restart=on-failure).
		return nil
	}
	return err
}

func cmdStatus() error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("Status: not enrolled")
		return nil
	}
	return printJSON(map[string]any{
		"status":    "enrolled",
		"server_id": cfg.ServerID,
		"portal":    cfg.ServerURL,
		"version":   version.Version,
	})
}

func cmdUnenroll() error {
	cfg, id, err := load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Unenroll(ctx, cfg, id); err != nil {
		return err
	}
	fmt.Println("Server removed from portal.")
	return nil
}

// cmdCheck scans paths offline with the default policy (no quarantine).
// cmdScanUpload scans one uploaded file; exit 0 = clean, 1 = block.
func cmdScanUpload(args []string) int {
	if len(args) != 1 {
		return 0
	}
	info, err := os.Stat(args[0])
	if err != nil || info.Size() > 32<<20 {
		return 0
	}
	det, _ := scanner.NewOffline().CheckFile(args[0], info, settings.Scanner{MaxFileSizeMB: 32})
	if det != nil && det.Category == scanner.CatVirus {
		fmt.Printf("XMartGuard blocked malware upload: %s\n", det.Signature)
		return 1
	}
	return 0
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON lines")
	misses := fs.Bool("misses", false, "print files that were NOT detected instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: xmartguard-agent check [--json] [--misses] PATH...")
	}
	cfg := settings.Defaults().Scanner
	cfg.MaxFileSizeMB = 20
	sc := scanner.NewOffline()
	var files, found int
	for _, root := range fs.Args() {
		_ = filepath.WalkDir(root, func(path string, d iofs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			files++
			det, _ := sc.CheckFile(path, info, cfg)
			if det != nil {
				found++
			}
			switch {
			case *misses && det == nil:
				fmt.Println(path)
			case !*misses && det != nil && *asJSON:
				b, _ := json.Marshal(map[string]string{"path": path, "category": det.Category, "signature": det.Signature})
				fmt.Println(string(b))
			case !*misses && det != nil:
				fmt.Printf("%-11s %-40s %s\n", det.Category, det.Signature, path)
			}
			return nil
		})
	}
	fmt.Fprintf(os.Stderr, "scanned %d files, %d detected (%.1f%%)\n", files, found, 100*float64(found)/float64(max(files, 1)))
	return nil
}

func cmdPanel(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: xmartguard-agent panel install|uninstall|status")
	}
	switch args[0] {
	case "install":
		done, err := panel.Install()
		for _, d := range done {
			fmt.Println("installed:", d)
		}
		return err
	case "uninstall":
		if err := panel.Uninstall(); err != nil {
			return err
		}
		fmt.Println("panel plugins removed")
	case "status":
		fmt.Printf("cpanel detected: %v\nplugin installed: %v\n", panel.Detected(), panel.Installed())
	default:
		return errors.New("usage: xmartguard-agent panel install|uninstall|status")
	}
	return nil
}

func cmdCall(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: xmartguard-agent call ACTION ['{json params}']")
	}
	params := json.RawMessage("{}")
	if len(args) == 2 {
		if !json.Valid([]byte(args[1])) {
			return errors.New("params must be valid JSON")
		}
		params = json.RawMessage(args[1])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	data, err := local.Call(ctx, args[0], params)
	if err != nil {
		return err
	}
	var v any
	_ = json.Unmarshal(data, &v)
	return printJSON(v)
}
