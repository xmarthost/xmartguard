package scanner

import (
	"strings"
	"testing"
)

// Samples are assembled at runtime from split fragments so this test file is
// not itself flagged by antivirus tools. They mirror obfuscation techniques
// seen in real webshells, written here from scratch.
func asm(parts ...string) []byte { return []byte(strings.Join(parts, "")) }

func TestHeuristicsDetectFamilies(t *testing.T) {
	php := "<?php "
	cases := map[string][]byte{
		"eval-base64":  asm(php, "ev", "al(base", "64_decode('", strings.Repeat("QUJD", 90), "'));"),
		"eval-input":   asm(php, "@ev", "al($_PO", "ST['x']);"),
		"assert-input": asm(php, "as", "sert($_RE", "QUEST['c']);"),
		"preg-e":       asm(php, "preg_repl", "ace('/.*/e', $_GET['x'], '');"),
		"create-func":  asm(php, "$f=create_fun", "ction('', $_POST['c']); $f();"),
		"command-inj":  asm(php, "sys", "tem($_GET['cmd']);"),
		"backtick":     asm(php, "$o = `", "id $_GET[x]`;"),
		"var-func":     asm(php, "$a=$_PO", "ST['f']; $a($_POST['c']);"),
		"globals":      asm(php, "$GLOB", "ALS['x']['y'](base64_decode($_POST['z']));"),
		"goto":         asm(php, strings.Repeat("goto l1; l1: ", 10), "ev", "al($_GET['x']);"),
		"gzinflate":    asm(php, "ev", "al(gzinf", "late(base64_decode('", strings.Repeat("QUJD", 90), "')));"),
		"uploader":     asm(php, "move_uploa", "ded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);"),
		"halt":         asm(php, "ev", "al(base64_decode($x)); __halt_com", "piler();DATA"),
		"chr-decoder":  asm(php, "$s='';", strings.Repeat("$s.=chr(0x41);", 30), " ev", "al($s);"),
		"filedropper":  asm(php, "file_put_con", "tents('x.php', chr(60).$_POST['c']);"),
		"js-miner":     []byte("var m = new Coin" + "Hive.Anonymous('key');"),
	}
	for name, content := range cases {
		ext := ".php"
		if strings.HasPrefix(name, "js") {
			ext = ".js"
		}
		if d := analyze(ext, content); d == nil {
			t.Errorf("%s: NOT detected", name)
		} else if d.Category != CatVirus {
			t.Errorf("%s: category %s, want virus", name, d.Category)
		}
	}
}

func TestHeuristicsNoFalsePositives(t *testing.T) {
	php := "<?php\n"
	clean := map[string][]byte{
		"wordpress": []byte(php + "function my_theme_setup(){ add_theme_support('title-tag'); } add_action('after_setup_theme','my_theme_setup');"),
		"plugin":    []byte(php + "namespace Acme;\nclass Widget { public function render($a){ return esc_html($a); } }"),
		"config":    []byte(php + "define('DB_NAME','wp'); define('DB_USER','root'); $table_prefix='wp_';"),
		"form":      []byte(php + "$name = sanitize_text_field($_POST['name']); wp_mail('a@b.c', 'Hi', $name);"),
		"base64ok":  []byte(php + "$logo = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');"),
		"upload-ok": []byte(php + "$dest = '/uploads/' . md5(uniqid()) . '.jpg'; move_uploaded_file($_FILES['f']['tmp_name'], $dest);"),
	}
	for name, content := range clean {
		if d := analyzePHP(content); d != nil {
			t.Errorf("%s: false positive %s", name, d.signature)
		}
	}
}

func TestHashDB(t *testing.T) {
	if hashDB.Count() < 100 {
		t.Fatalf("baseline hash DB too small: %d", hashDB.Count())
	}
	// A size with no entry is cheaply skipped.
	if hashDB.SizeKnown(7) {
		t.Skip("unlikely size present; skipping")
	}
	if SignatureCount() <= len(Rules) {
		t.Fatal("signature count should include hashes")
	}
}
