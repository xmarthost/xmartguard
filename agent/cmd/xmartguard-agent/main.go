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
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/identity"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
	"github.com/xmarthost/xmartguard/agent/internal/version"
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
	s := &client.Session{Cfg: cfg, ID: id, Log: log, Collector: sysinfo.NewCollector()}
	s.Handlers = map[string]client.Handler{
		"ping": func(context.Context, json.RawMessage) (any, error) {
			return map[string]any{"pong": true, "version": version.Version, "time": time.Now().Unix()}, nil
		},
		"inventory": func(context.Context, json.RawMessage) (any, error) { return sysinfo.Collect(), nil },
		"metrics": func(context.Context, json.RawMessage) (any, error) {
			return s.Collector.Collect(10), nil
		},
		"live": func(_ context.Context, p json.RawMessage) (any, error) {
			var in struct {
				Seconds int `json:"seconds"`
			}
			_ = json.Unmarshal(p, &in)
			if in.Seconds <= 0 || in.Seconds > 900 {
				in.Seconds = 120
			}
			s.SetLive(time.Duration(in.Seconds) * time.Second)
			return map[string]any{"live_seconds": in.Seconds}, nil
		},
	}
	err = s.Run(ctx)
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
