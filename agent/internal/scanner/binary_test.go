package scanner

import "testing"

// Botnet binaries hidden in a WordPress site of an addon domain (DeepSeek
// MCP reports, 2026-10-17), next to programs plugins ship legitimately.
func TestBinaryPlaces(t *testing.T) {
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0}
	cases := map[string]string{
		"/home/acct1/addon.example.com/wp-includes/sodium_compat/src/Core/SecretStream/.a1b2c3":                         "Binary.ELF.InWordPressCore",
		"/home/acct1/addon.example.com/wp-content/plugins/woocommerce/assets/js/.mini-cart-title-items-counter-block/x": "Binary.ELF.HiddenInWebsite",
		"/home/acct1/addon.example.com/wp-content/plugins/woocommerce/.cache/polkitd":                                   "Binary.ELF.HiddenInWebsite",
		"/home/acct1/addon.example.com/bridgemgr":                                                                       "Binary.ELF.InWebOrTempDir",
		"/home/u/example.com/gdm3":                                                                                    "Binary.ELF.FakeSystemService",
		"/home/u/public_html/wp-content/uploads/kthreadd":                                                             "Binary.ELF.FakeSystemService",
		"/home/u/public_html/wp-content/plugins/woocommerce/wpbooster":                                                "Binary.ELF.InWordPressContent",
		"/home/u/public_html/ffmpeg":                                                                                  "Binary.ELF.InWebOrTempDir",
		// A program hidden in a plugin's Composer folder (2026-10-19).
		"/home/u/tutorials.example.com/wp-content/plugins/wp-rocket/vendor/monolog/monolog/src/Monolog/Handler/SyslogUdp/16e2277f8b31_A": "Binary.ELF.InWordPressContent",
	}
	for p, want := range cases {
		d, _ := binaryCheck(p, elf)
		if d == nil || d.Signature != want {
			t.Errorf("%s: %+v, want %s", p, d, want)
		}
	}
	// Developer tools in the account's own folders are not flagged.
	for _, p := range []string{"/home/u/.local/bin/node", "/home/u/node-v18.17.0-linux-x64/bin/node", "/home/u/bin/composer", "/home/u/.nvm/versions/node/v20/bin/node"} {
		if d, _ := binaryCheck(p, elf); d != nil {
			t.Errorf("%s flagged %s", p, d.Signature)
		}
	}
	// Programs and libraries websites ship on purpose are not flagged:
	// image optimizers' tools, npm, Python and Composer packages, native
	// modules and shared libraries, Android build output (scan of
	// 2026-10-18: quarantining them broke EWWW and Node/Python apps).
	for _, p := range []string{
		"/home/u/public_html/wp-content/ewww/jpegtran", "/home/u/public_html/wp-content/ewww/pngquant",
		"/home/u/public_html/wp-content/plugins/webp-express/vendor/rosell-dk/webp-convert/src/Convert/Converters/Binaries/cwebp-120-linux-x86-64",
		"/home/u/public_html/news/app/ThirdParty/webp-convert/vendor/rosell-dk/webp-convert/src/Convert/Converters/Binaries/cwebp-060-fbsd",
		"/home/u/public_html/app/node_modules/.bin/esbuild", "/home/u/star.example.com/backend/node_modules_old/@esbuild/linux-x64/bin/esbuild",
		"/home/u/askmedicalfacts.com/venv/lib/python3.12/site-packages/pydantic_core/_core.cpython-312-x86_64-linux-gnu.so",
		"/home/u/vet.example.com/vendor/phpstan/phpstan/phpstan_turbo-8.5.so", "/home/u/store.example.pk/cscart/app/payments/lib/x.so",
		"/home/u/public_html/node-app/rollup.linux-x64-gnu.node", "/home/u/public_html/x/bare-fs.bare",
		"/home/u/app.example.pk/android/app/.cxx/Debug/x/CMakeFiles/3.22/CompilerIdCXX/CMakeDetermineCompilerABI_CXX.bin",
	} {
		if d, _ := binaryCheck(p, elf); d != nil {
			t.Errorf("%s flagged %s", p, d.Signature)
		}
	}
	// A hidden library is still malware.
	if d, _ := binaryCheck("/home/u/public_html/wp-content/.cache/libx.so", elf); d == nil || d.Signature != "Binary.ELF.HiddenInWebsite" {
		t.Errorf("hidden library: %+v", d)
	}
}
