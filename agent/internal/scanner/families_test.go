package scanner

import (
	"archive/zip"
	"os"
	"strings"
	"testing"
)

// Minimal, inert samples of each behaviour (they only need the shape the
// rules look for; none of them does anything when run).
func TestFamiliesDetect(t *testing.T) {
	cases := []struct{ name, ext, src, want string }{
		{"silent loader", ".php", `<?php if(@is_file("/home/u/public_html/.cache/x.ico"))@include_once "/home/u/public_html/.cache/x.ico";`, "PHP.Loader.SilentInclude"},
		{"include image", ".php", `<?php @include "/home/u/public_html/wp-content/uploads/logo.png";`, "PHP.Loader.IncludeNonPHP"},
		{"include hidden", ".php", `<?php include __DIR__ . '/.settings.php';`, "PHP.Loader.HiddenInclude"},
		{"function table", ".php", `<?php $a=t(1)($b); $c=t(2)($d); $e=t(3)($f); $g=t(4)($h); $i=t(5)($j); $k=t(6)($l); eval($k);`, "PHP.Obfuscated.FunctionTable"},
		{"xor decoder", ".php", `<?php function d($s,$k){$o='';for($i=0;$i<strlen($s);$i++){$o.=chr(ord($s[$i])^$k);}return $o;} $f=d($_POST['a'],22); $f($_POST['b']);`, "PHP.Obfuscated.CharDecoder"},
		{"eval template", ".php", `<?php $x = base64_decode($p); eval("?>".$x);`, "PHP.Obfuscated.EvalTemplate"},
		{"wp admin login", ".php", `<?php require 'wp-load.php'; $u = get_users(array('role'=>'administrator')); wp_set_auth_cookie($u[0]->ID);`, "PHP.Backdoor.WPAdminLogin"},
		{"split name", ".php", `<?php $g = 'gz'.'in'.'fla'.'te'; $f = $g; $f($data);`, "PHP.Obfuscated.SplitFunctionName"},
		{"ua cloaking", ".php", `<?php $ua=$_SERVER['HTTP_USER_AGENT']; if (preg_match('/googlebot|bingbot/i',$ua)) { include 'page.html'; exit; }`, "PHP.SEO.UserAgentCloaking"},
		{"remote content hook", ".php", `<?php add_action('template_redirect', function(){ $r = wp_remote_get($u, ['sslverify' => false]); echo wp_remote_retrieve_body($r); exit; });`, "PHP.Injector.RemoteContent"},
		{"user.ini loader", ".ini", "auto_prepend_file = \"/home/u/public_html/wp-content/.x.ico\"\n", "PHP.Config.AutoPrependLoader"},
		{"redirect page in png", ".png", "<!DOCTYPE html><html><body>spam<script>window.location.href='https://spam.example/'</script></body></html>", "Disguised.MarkupInImage"},
		{"frame page in jpg", ".jpg", "<html><body><iframe src='https://phish.example/login'></iframe></body></html>", "Disguised.MarkupInImage"},
	}
	for _, c := range cases {
		d := analyze(c.ext, []byte(c.src))
		if d == nil || d.Signature != c.want {
			t.Errorf("%s: got %+v, want %s", c.name, d, c.want)
		}
	}
}

// Legitimate code that earlier versions (or loose rules) flagged.
func TestFamiliesNoFalsePositives(t *testing.T) {
	clean := map[string]string{
		// preg_replace patterns with quotes and letters but no /e modifier.
		"preg without e": `<?php $s = preg_replace( '/<defs>.*?<\/defs>/s', '', $svg ); $s = preg_replace( '/\s*clip-path="[^"]*"/', '', $s );`,
		// Methods named exec next to request data.
		"exec method": `<?php $id = (int) $_GET['id']; Hook::exec('actionClearCache', ['id' => $id]); $this->db->exec($sql);`,
		// eval of a local variable near unrelated request data.
		"eval local": `<?php $page = $_GET['page'] ?? 1; $code = file_get_contents(__DIR__.'/tpl.php'); $out = eval($code);`,
		// Request logging to stdout.
		"stdout log": `<?php $uri = $_SERVER['REQUEST_URI']; file_put_contents('php://stdout', "[" . date('c') . "] " . $uri . "\n");`,
		// Twig-style cache loading of a computed path.
		"cache include": `<?php if (is_file($key)) { @include_once $key; }`,
		// Ruleset file with a ".json.php" suffix.
		"json php suffix": `<?php return require($rulesetPath . $fileName . '.json.php');`,
		// Wordfence firewall bootstrap.
		"wordfence ini": "auto_prepend_file = '/home/u/public_html/wordfence-waf.php'\n",
		// Freemius SDK: two-piece names that dodge the WordPress.org scanner.
		"freemius split": `<?php $fn = 'base64' . '_decode'; $data = $fn( $payload ); $inc = 'requir' . 'e_once';`,
		// PhpParser pretty printer: the statement only inside a string.
		"halt in string": `<?php function p($node){ if ($x) { eval($y); } return '__halt_compiler();' . $node->remaining; }`,
		// create_function on the plugin's own data.
		"create_function local": `<?php $page = $_GET['page']; $all = array_map(create_function('$a', 'return $a[0];'), $rows);`,
		// Ajax dispatch to the object's own methods.
		"method dispatch": `<?php $method = $_POST['subaction']; if (method_exists($this, $method)) { $this->$method($_POST); }`,
		// Contact form to a fixed address.
		"contact form": `<?php $name = $_POST['name']; $msg = $_POST['message']; mail('info@example.com', 'Contact from ' . $name, $msg);`,
		// Laravel compiled Blade view with hash-named variables.
		"blade view": "<?php $__componentOriginal2dde6d1a8d73f7e3c7a0c5dc4bb3c3a2 = $component; $__componentOriginal8e1a2b3c4d5e6f708192a3b4c5d6e7f8 = $x; $__componentOriginal1a2b3c4d5e6f70812a3b4c5d6e7f8091 = $y; $__componentOriginala1b2c3d4e5f60718293a4b5c6d7e8f90 = $z; eval($q); ?>\n<?php /**PATH /home/u/app/resources/views/home.blade.php ENDPATH**/ ?>",
		// Inline CSS/SVG includes in themes.
		"inline svg": `<?php include get_template_directory() . '/icons/menu.svg'; include __DIR__ . '/inline.css';`,
	}
	for name, src := range clean {
		ext := ".php"
		if name == "wordfence ini" {
			ext = ".ini"
		}
		if d := analyze(ext, []byte(src)); d != nil {
			t.Errorf("%s: false positive %+v", name, d)
		}
	}
	// HTML pages that image importers saved as .jpg (server100: 508 of them,
	// all cleared by the AI): a CDN challenge with scripts and a redirect,
	// and a plain page with analytics scripts.
	for name, page := range map[string]string{
		"cdn challenge": `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={cType:'managed'};window.location.href=window.location.href;</script></body></html>`,
		"scripts only":  `<html><head><script async src="https://www.googletagmanager.com/gtag/js"></script><script>dataLayer=[];</script></head><body>Template preview</body></html>`,
	} {
		if d := analyze(".jpg", []byte(page)); d != nil {
			t.Errorf("%s saved as .jpg: false positive %+v", name, d)
		}
	}
	// A stats cache (no extension) holding logged attack URLs.
	if d := analyze("", []byte("GET /x.php?c=<?php eval($_POST[1]); ?> 404\nGET /y 200\n")); d != nil {
		t.Errorf("stats cache flagged: %+v", d)
	}
	// A cached 404 page saved as an avatar image.
	if d := analyze(".jpg", []byte("<!DOCTYPE html><html><body>Not Found</body></html>")); d != nil {
		t.Errorf("cached error page flagged: %+v", d)
	}
	// A real PNG header is never markup.
	if d := markupInImage(".png", []byte("\x89PNG\r\n\x1a\n....")); d != nil {
		t.Errorf("png flagged: %+v", d)
	}
}

func TestCapHeuristicInTestsAndPhar(t *testing.T) {
	v := &Detection{CatVirus, "PHP.Backdoor.CommandInjection"}
	if d := capHeuristic("/home/u/public_html/vendor/x/tests/FooTest.php", ".php", v); d.Category != CatSuspicious {
		t.Errorf("tests dir not capped: %+v", d)
	}
	if d := capHeuristic("/home/u/public_html/tool.phar", ".phar", v); d.Category != CatSuspicious {
		t.Errorf("phar not capped: %+v", d)
	}
	if d := capHeuristic("/home/u/public_html/x.php", ".php", v); d.Category != CatVirus {
		t.Errorf("normal file capped: %+v", d)
	}
}

func TestImagesAndArchives(t *testing.T) {
	if d := analyze(".jpg", []byte("\xff\xd8\xff\xe0JFIF<?php @eval($_POST['x']); ?>")); d == nil || d.Signature != "Disguised.PHPInImage" || d.Category != CatVirus {
		t.Fatalf("php backdoor in jpg: %+v", d)
	}
	if d := analyze(".gif", []byte("GIF89a<?php echo 1; ?>")); d != nil && d.Category == CatVirus {
		t.Fatalf("harmless polyglot as virus: %+v", d)
	}
	if d := analyze(".jpg", []byte("\xff\xd8\xff\xe0JFIF....<script>window.location='https://spam.example'</script>")); d == nil || d.Signature != "Disguised.ScriptInImage" {
		t.Fatalf("script in jpg: %+v", d)
	}
	if d := analyze(".png", []byte("\x89PNG\r\n\x1a\n...tEXtComment <script> is a word")); d != nil {
		t.Fatalf("harmless png flagged: %+v", d)
	}

	dir := t.TempDir()
	mk := func(name string, files map[string]string) string {
		p := dir + "/" + name
		f, _ := os.Create(p)
		w := zip.NewWriter(f)
		for n, c := range files {
			x, _ := w.Create(n)
			x.Write([]byte(c))
		}
		w.Close()
		f.Close()
		return p
	}
	bad := mk("plugin.zip", map[string]string{"plugin/readme.txt": "hi", "plugin/x.php": "<?php @eval($_POST['a']); ?>"})
	if d := scanZip(bad, 1000); d == nil || !strings.HasPrefix(d.Signature, "Archive.") {
		t.Fatalf("zip with shell: %+v", d)
	}
	good := mk("backup.zip", map[string]string{"site/index.php": "<?php require 'wp-blog-header.php';", "site/tests/eval.php": "<?php @eval($_POST['a']);"})
	if d := scanZip(good, 1000); d != nil {
		t.Fatalf("clean zip flagged: %+v", d)
	}
}
