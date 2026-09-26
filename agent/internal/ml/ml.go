// Package ml is XMart Guard's built-in AI scanner: a logistic-regression
// model over code features that scores how likely a PHP/JS file is
// malicious. It runs inside the agent with no network access and no API
// costs, and it is retrained from real quarantine data (see Train and the
// "xmartguard-agent ai-train" command), so it improves as more quarantined
// files are collected.
package ml

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/xmarthost/xmartguard/agent/internal/config"
)

// Buckets is the size of the hashed feature space.
const Buckets = 1 << 17

// MaxBytes is how much of a file is read for scoring.
const MaxBytes = 1 << 20

// Model holds the weights.
type Model struct {
	Version string
	Bias    float32
	Weights []float32 // len Buckets
	// Thresholds tuned on held-out clean code: Suspicious keeps the false
	// positive rate near 0.5%, Malicious near 0.02%.
	Suspicious float32
	Malicious  float32
}

//go:embed model.bin
var embedded []byte

var (
	defOnce  sync.Once
	defModel *Model
	defErr   error
)

// Default returns the model shipped with the agent (or the one an admin
// trained, when /etc/xmartguard/ai-model.bin exists).
func Default() (*Model, error) {
	defOnce.Do(func() {
		if raw, err := os.ReadFile(LocalModelPath); err == nil {
			if m, err := Decode(raw); err == nil {
				defModel = m
				return
			}
		}
		defModel, defErr = Decode(embedded)
	})
	return defModel, defErr
}

// LocalModelPath is where a locally trained model is loaded from.
var LocalModelPath = filepath.Join(config.Dir(), "ai-model.bin")

const magic = "XGML1"

// Encode serializes a model (gzip-compressed).
func (m *Model) Encode() ([]byte, error) {
	var raw bytes.Buffer
	raw.WriteString(magic)
	ver := []byte(m.Version)
	_ = binary.Write(&raw, binary.LittleEndian, uint16(len(ver)))
	raw.Write(ver)
	for _, f := range []float32{m.Bias, m.Suspicious, m.Malicious} {
		_ = binary.Write(&raw, binary.LittleEndian, f)
	}
	_ = binary.Write(&raw, binary.LittleEndian, m.Weights)
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Decode reads a model written by Encode.
func Decode(data []byte) (*Model, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 16<<20))
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(raw)
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(r, head); err != nil || string(head) != magic {
		return nil, errors.New("ml: not a model file")
	}
	var n uint16
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	ver := make([]byte, n)
	if _, err := io.ReadFull(r, ver); err != nil {
		return nil, err
	}
	m := &Model{Version: string(ver), Weights: make([]float32, Buckets)}
	for _, p := range []*float32{&m.Bias, &m.Suspicious, &m.Malicious} {
		if err := binary.Read(r, binary.LittleEndian, p); err != nil {
			return nil, err
		}
	}
	if err := binary.Read(r, binary.LittleEndian, m.Weights); err != nil {
		return nil, errors.New("ml: truncated model")
	}
	return m, nil
}

// Score returns the probability (0..1) that content is malicious.
func (m *Model) Score(content []byte) float64 {
	return m.scoreFeatures(Features(content))
}

func (m *Model) scoreFeatures(f []uint32) float64 {
	z := float64(m.Bias)
	for _, i := range f {
		z += float64(m.Weights[i])
	}
	return sigmoid(z)
}

// Verdict maps a score to malicious / suspicious / clean.
func (m *Model) Verdict(score float64) string {
	switch {
	case score >= float64(m.Malicious):
		return "malicious"
	case score >= float64(m.Suspicious):
		return "suspicious"
	}
	return "clean"
}

// Explain lists the features that pushed the score up the most, as short
// human-readable names (for the finding's reason).
func (m *Model) Explain(content []byte, n int) []string {
	type kv struct {
		name string
		w    float32
	}
	seen := map[uint32]bool{}
	var top []kv
	forEachFeature(content, func(name string) {
		i := hash(name)
		if seen[i] {
			return
		}
		seen[i] = true
		if w := m.Weights[i]; w > 0 {
			top = append(top, kv{name, w})
		}
	})
	for i := 0; i < len(top); i++ {
		for j := i + 1; j < len(top); j++ {
			if top[j].w > top[i].w {
				top[i], top[j] = top[j], top[i]
			}
		}
	}
	var out []string
	for i := 0; i < len(top) && len(out) < n; i++ {
		out = append(out, top[i].name)
	}
	return out
}

func sigmoid(z float64) float64 {
	if z > 30 {
		return 1
	}
	if z < -30 {
		return 0
	}
	return 1 / (1 + math.Exp(-z))
}

func hash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32() % Buckets
}
