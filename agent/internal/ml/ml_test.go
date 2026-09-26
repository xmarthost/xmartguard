package ml

import (
	"strings"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	m := &Model{Version: "t1", Bias: -2, Weights: make([]float32, Buckets), Suspicious: 0.6, Malicious: 0.95}
	m.Weights[hash("c:eval")] = 3
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil || back.Version != "t1" || back.Weights[hash("c:eval")] != 3 || back.Malicious != 0.95 {
		t.Fatalf("roundtrip: %v %+v", err, back)
	}
	if _, err := Decode([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestFeatures(t *testing.T) {
	src := []byte("<?php\n$data = $_POST['x'];\nfoo($data);\n")
	names := map[string]bool{}
	forEachFeature(src, func(n string) { names[n] = true })
	for _, want := range []string{"$_post", "c:foo", "h:c:foo", "s:phptags:1"} {
		if !names[want] {
			t.Errorf("missing feature %q in %v", want, names)
		}
	}
	if names["$data"] {
		t.Error("ordinary variable names must be collapsed")
	}
}

// A toy corpus: the model must separate request-driven dynamic calls from
// ordinary code after training.
func TestTrainSeparates(t *testing.T) {
	var samples []Sample
	for i := 0; i < 200; i++ {
		bad := "<?php $f = $_REQUEST['a']; $f($_POST['b']); // " + strings.Repeat("x", i%7)
		good := "<?php function render_item($item) { return esc_html($item->title) . ' ' . " + strings.Repeat("'y'.", i%5) + "''; }"
		samples = append(samples, Sample{Features: Features([]byte(bad)), Label: 1}, Sample{Features: Features([]byte(good)), Label: 0})
	}
	m, mt := Train(samples, "toy", 0.25, 1)
	if mt.Detected < mt.Malicious*9/10 || mt.FalsePos > 0 {
		t.Fatalf("metrics %s", mt)
	}
	if m.Verdict(m.Score([]byte("<?php $g = $_REQUEST['q']; $g($_POST['z']);"))) == "clean" {
		t.Fatal("dynamic call from request data scored clean")
	}
}

func TestEmbeddedModelLoads(t *testing.T) {
	m, err := Decode(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version == "" || len(m.Weights) != Buckets {
		t.Fatalf("model: %q %d", m.Version, len(m.Weights))
	}
	// Plain WordPress-style template code stays clean.
	clean := []byte("<?php\n/**\n * Template part\n */\nget_header();\nif ( have_posts() ) {\n\twhile ( have_posts() ) {\n\t\tthe_post();\n\t\tthe_title( '<h1>', '</h1>' );\n\t\tthe_content();\n\t}\n}\nget_footer();\n")
	if v := m.Verdict(m.Score(clean)); v != "clean" {
		t.Fatalf("template scored %s (%.3f)", v, m.Score(clean))
	}
}
