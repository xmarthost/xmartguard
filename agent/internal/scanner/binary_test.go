package scanner

import "testing"

// Botnet binaries hidden in a WordPress site of an addon domain (DeepSeek
// MCP reports, 2026-10-17), next to programs plugins ship legitimately.
func TestBinaryPlaces(t *testing.T) {
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3e, 0}
	cases := map[string]string{
		"/home/murtajez/murtajez.com/wp-includes/sodium_compat/src/Core/SecretStream/.a1b2c3":                                                      "Binary.ELF.InWordPressCore",
		"/home/murtajez/murtajez.com/wp-content/plugins/woocommerce/assets/js/.mini-cart-title-items-counter-block/x":                              "Binary.ELF.HiddenInWebsite",
		"/home/murtajez/murtajez.com/wp-content/plugins/woocommerce/.cache/polkitd":                                                                "Binary.ELF.HiddenInWebsite",
		"/home/u/public_html/app/node_modules/.bin/esbuild":                                                                                        "Binary.ELF.InWebOrTempDir",
		"/home/murtajez/murtajez.com/bridgemgr":                                                                                                    "Binary.ELF.InWebOrTempDir",
		"/home/u/example.com/gdm3":                                                                                                                 "Binary.ELF.FakeSystemService",
		"/home/u/public_html/wp-content/uploads/kthreadd":                                                                                          "Binary.ELF.FakeSystemService",
		"/home/u/public_html/wp-content/plugins/webp-express/vendor/rosell-dk/webp-convert/src/Convert/Converters/Binaries/cwebp-120-linux-x86-64": "Binary.ELF.InWordPressContent",
		"/home/u/public_html/ffmpeg":                                                                                                               "Binary.ELF.InWebOrTempDir",
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
	// The plugins' own tools stay "binary" (the administrator's binary action), not virus.
	if d, _ := binaryCheck("/home/u/public_html/wp-content/ewww/jpegtran", elf); d == nil || d.Category != CatBinary {
		t.Errorf("EWWW jpegtran: %+v", d)
	}
	if d, _ := binaryCheck("/home/u/public_html/wp-content/ewww/jpegtran", elf); d == nil || d.Category != CatBinary {
		t.Errorf("EWWW: %+v", d)
	}
}
