package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ml"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// cmdAITrain retrains the built-in AI scanner from quarantined malware and
// clean code, e.g.:
//
//	xmartguard-agent ai-train --malicious /opt/xmartguard/data/quarantine \
//	    --clean /home/*/public_html/wp-admin --out /etc/xmartguard/ai-model.bin
func cmdAITrain(args []string) error {
	fs := flag.NewFlagSet("ai-train", flag.ContinueOnError)
	var bad, good multiFlag
	fs.Var(&bad, "malicious", "folder of malicious files (repeatable)")
	fs.Var(&good, "clean", "folder of clean code (repeatable)")
	perDir := fs.Int("per-dir", 4000, "at most this many clean files per --clean folder")
	out := fs.String("out", ml.LocalModelPath, "where to write the model")
	holdout := fs.Float64("holdout", 0.2, "share of samples held out for testing")
	epochs := fs.Int("epochs", ml.DefaultParams.Epochs, "training passes")
	lr := fs.Float64("lr", ml.DefaultParams.LR, "learning rate")
	l2 := fs.Float64("l2", ml.DefaultParams.L2, "L2 regularisation")
	posBias := fs.Float64("pos-bias", ml.DefaultParams.PosBias, "class balance exponent")
	verbose := fs.Bool("v", false, "list the worst mistakes on held-out files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(bad) == 0 || len(good) == 0 {
		return errors.New("give at least one --malicious and one --clean folder")
	}
	// Clean code first: a quarantined file identical to known-clean code
	// was a false positive of whatever quarantined it, not malware.
	seen := map[[32]byte]bool{}
	var samples []ml.Sample
	var nb, ng int
	for _, d := range good {
		s, err := ml.Collect(d, 0, *perDir, seen)
		if err != nil {
			return err
		}
		ng += len(s)
		samples = append(samples, s...)
	}
	// Quarantines hold false positives too: a file named like a clean
	// library file that the signature engine does not detect is skipped.
	cleanNames := map[string]bool{}
	for _, x := range samples {
		cleanNames[filepath.Base(x.Path)] = true
	}
	engine := scanner.NewOffline()
	cfg := settings.Defaults().Scanner
	keep := func(p string) bool {
		name := strings.TrimLeft(filepath.Base(p), "0123456789")
		name = strings.TrimPrefix(name, "-")
		if !cleanNames[name] {
			return true
		}
		info, err := os.Stat(p)
		if err != nil {
			return false
		}
		d, _ := engine.CheckFile(p, info, cfg)
		return d != nil
	}
	for _, d := range bad {
		s, dropped, err := ml.CollectMalicious(d, seen, keep)
		if err != nil {
			return err
		}
		if dropped > 0 {
			fmt.Printf("%s: skipped %d probable false positives (identical to, or named like, clean code the signature engine does not flag)\n", d, dropped)
		}
		nb += len(s)
		samples = append(samples, s...)
	}
	fmt.Printf("training on %d malicious and %d clean unique files\n", nb, ng)
	m, metrics := ml.TrainWith(samples, "xg-ml-"+time.Now().UTC().Format("20060102"), *holdout, 1,
		ml.Params{Epochs: *epochs, LR: *lr, L2: *l2, PosBias: *posBias})
	fmt.Println(metrics)
	if *verbose {
		fmt.Println("clean files scored highest:")
		for _, l := range metrics.TopFalsePos {
			fmt.Println("  " + l)
		}
		fmt.Println("malicious files missed:")
		for _, l := range metrics.Missed {
			fmt.Println("  " + l)
		}
	}
	fmt.Printf("thresholds: suspicious %.4f, malicious %.4f\n", m.Suspicious, m.Malicious)
	data, err := m.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("model written to %s (%d KB); restart the agent to use it\n", *out, len(data)/1024)
	return nil
}

func cmdAIScore(args []string) error {
	m, err := ml.Default()
	if err != nil {
		return err
	}
	for _, p := range args {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Printf("%s: %v\n", p, err)
			continue
		}
		sc := m.Score(b)
		fmt.Printf("%s: %s (%.1f%%) %s\n", p, m.Verdict(sc), sc*100, strings.Join(m.Explain(b, 5), ", "))
	}
	return nil
}
