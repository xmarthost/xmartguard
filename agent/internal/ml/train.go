package ml

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Sample is one training file.
type Sample struct {
	Path     string
	Features []uint32
	Label    float64 // 1 malicious, 0 clean
}

// codeExt are the extensions collected from clean folders.
var codeExt = map[string]bool{".php": true, ".phtml": true, ".inc": true, ".js": true, ".php5": true, ".php7": true}

// LooksLikeCode reports whether content is text code worth scoring.
func LooksLikeCode(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	s := b
	if len(s) > 4096 {
		s = s[:4096]
	}
	// Binary or encrypted content (e.g. quarantine stores that encode files)
	// is not source code.
	ctrl := 0
	for _, c := range s {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			ctrl++
		}
	}
	if ctrl*100 > len(s) {
		return false
	}
	return strings.Contains(string(s), "<?") || strings.Contains(string(s), "function") || strings.Contains(string(s), "eval") ||
		strings.Contains(string(s), "=>") || strings.Contains(string(s), "var ") || strings.Contains(string(s), "document.")
}

// Collect reads samples from dir. Malicious folders take every file that
// contains code (quarantined malware hides in .jpg or .ico too); clean
// folders take code files by extension, at most perDir of them. Files are
// de-duplicated by content so copies never land on both sides of a split.
func Collect(dir string, label float64, perDir int, seen map[[32]byte]bool) ([]Sample, error) {
	var out []Sample
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" && label == 0) {
				return filepath.SkipDir
			}
			return nil
		}
		if perDir > 0 && len(out) >= perDir {
			return filepath.SkipAll
		}
		if label == 0 && !codeExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		b, _ := io.ReadAll(io.LimitReader(f, MaxBytes))
		f.Close()
		if len(b) < 20 || !LooksLikeCode(b) {
			return nil
		}
		sum := sha256.Sum256(b)
		if seen[sum] {
			return nil
		}
		seen[sum] = true
		out = append(out, Sample{Path: p, Features: Features(b), Label: label})
		return nil
	})
	return out, err
}

// CollectMalicious reads quarantined files. Files whose content was already
// seen among clean code are counted as dropped false positives.
// keep, when set, can reject a file (probable false positive of the tool
// that quarantined it); rejected files count as dropped too.
func CollectMalicious(dir string, seen map[[32]byte]bool, keep func(path string) bool) ([]Sample, int, error) {
	known := make(map[[32]byte]bool, len(seen))
	for k := range seen {
		known[k] = true
	}
	var dropped int
	var out []Sample
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := readHead(p)
		if err != nil || len(b) < 20 || !LooksLikeCode(b) {
			return nil
		}
		sum := sha256.Sum256(b)
		if known[sum] || (keep != nil && !keep(p)) {
			dropped++
			return nil
		}
		if seen[sum] {
			return nil
		}
		seen[sum] = true
		out = append(out, Sample{Path: p, Features: Features(b), Label: 1})
		return nil
	})
	return out, dropped, err
}

func readHead(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxBytes))
}

// Metrics summarises a model on held-out samples.
type Metrics struct {
	Malicious, Clean   int
	Detected, FalsePos int // at the suspicious threshold
	DetectedHigh       int // at the malicious threshold
	FalsePosHigh       int
	// Worst mistakes, for review.
	TopFalsePos []string
	Missed      []string
}

func (m Metrics) String() string {
	return fmt.Sprintf("held-out: %d malicious, %d clean | suspicious threshold: detected %.1f%%, false positives %.3f%% | malicious threshold: detected %.1f%%, false positives %.3f%%",
		m.Malicious, m.Clean, pct(m.Detected, m.Malicious), pct(m.FalsePos, m.Clean), pct(m.DetectedHigh, m.Malicious), pct(m.FalsePosHigh, m.Clean))
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

// Params tune training.
type Params struct {
	Epochs  int
	LR      float64
	L2      float64
	PosBias float64 // exponent on the class-balance weight (1 = fully balanced)
}

// DefaultParams were chosen on the reference corpus.
var DefaultParams = Params{Epochs: 12, LR: 0.2, L2: 1e-6, PosBias: 0.5}

// Train fits a model with class-balanced logistic regression (SGD with L2),
// holding out a share of the samples to set thresholds and report metrics.
func Train(samples []Sample, version string, holdout float64, seed int64) (*Model, Metrics) {
	return TrainWith(samples, version, holdout, seed, DefaultParams)
}

// TrainWith is Train with explicit parameters.
func TrainWith(samples []Sample, version string, holdout float64, seed int64, pr Params) (*Model, Metrics) {
	r := rand.New(rand.NewSource(seed))
	r.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	cut := int(float64(len(samples)) * (1 - holdout))
	train, test := samples[:cut], samples[cut:]

	var pos, neg float64
	for _, s := range train {
		if s.Label == 1 {
			pos++
		} else {
			neg++
		}
	}
	wPos, wNeg := 1.0, 1.0
	if pos > 0 && neg > 0 {
		wPos = math.Pow((pos+neg)/(2*pos), pr.PosBias)
		wNeg = math.Pow((pos+neg)/(2*neg), pr.PosBias)
	}
	w := make([]float64, Buckets)
	var b float64
	l2 := pr.L2
	lr := pr.LR
	for epoch := 0; epoch < pr.Epochs; epoch++ {
		r.Shuffle(len(train), func(i, j int) { train[i], train[j] = train[j], train[i] })
		for _, s := range train {
			z := b
			for _, i := range s.Features {
				z += w[i]
			}
			g := sigmoid(z) - s.Label
			if s.Label == 1 {
				g *= wPos
			} else {
				g *= wNeg
			}
			// Scale by feature count so long files do not dominate.
			step := lr * g / math.Sqrt(float64(len(s.Features)+1))
			b -= step
			for _, i := range s.Features {
				w[i] -= step + lr*l2*w[i]
			}
		}
		lr *= 0.75
	}
	m := &Model{Version: version, Bias: float32(b), Weights: make([]float32, Buckets)}
	for i, v := range w {
		m.Weights[i] = float32(v)
	}
	// Thresholds from held-out clean scores.
	var clean, bad []float64
	type scored struct {
		path string
		sc   float64
	}
	var cleanS, badS []scored
	for _, s := range test {
		sc := m.scoreFeatures(s.Features)
		if s.Label == 1 {
			bad = append(bad, sc)
			badS = append(badS, scored{s.Path, sc})
		} else {
			clean = append(clean, sc)
			cleanS = append(cleanS, scored{s.Path, sc})
		}
	}
	sort.Float64s(clean)
	q := func(p float64, floor float64) float32 {
		if len(clean) == 0 {
			return float32(floor)
		}
		v := clean[int(math.Min(float64(len(clean)-1), p*float64(len(clean))))]
		return float32(math.Max(floor, math.Min(0.999, v+1e-6)))
	}
	m.Suspicious = q(0.995, 0.5)
	m.Malicious = q(0.9995, 0.9)
	if m.Malicious < m.Suspicious {
		m.Malicious = m.Suspicious
	}
	var mt Metrics
	for _, sc := range bad {
		mt.Malicious++
		if sc >= float64(m.Suspicious) {
			mt.Detected++
		}
		if sc >= float64(m.Malicious) {
			mt.DetectedHigh++
		}
	}
	for _, sc := range clean {
		mt.Clean++
		if sc >= float64(m.Suspicious) {
			mt.FalsePos++
		}
		if sc >= float64(m.Malicious) {
			mt.FalsePosHigh++
		}
	}
	sort.Slice(cleanS, func(i, j int) bool { return cleanS[i].sc > cleanS[j].sc })
	for i := 0; i < len(cleanS) && i < 15 && cleanS[i].sc >= float64(m.Suspicious); i++ {
		mt.TopFalsePos = append(mt.TopFalsePos, fmt.Sprintf("%.3f %s", cleanS[i].sc, cleanS[i].path))
	}
	sort.Slice(badS, func(i, j int) bool { return badS[i].sc < badS[j].sc })
	for i := 0; i < len(badS) && i < 15 && badS[i].sc < float64(m.Suspicious); i++ {
		mt.Missed = append(mt.Missed, fmt.Sprintf("%.3f %s", badS[i].sc, badS[i].path))
	}
	return m, mt
}
