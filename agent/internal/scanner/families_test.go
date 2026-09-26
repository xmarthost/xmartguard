package scanner

import "testing"

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
		{"html in png", ".png", "<!DOCTYPE html><html><body>spam</body></html>", "Disguised.MarkupInImage"},
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
