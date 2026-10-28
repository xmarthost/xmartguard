package scanner

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Malware families from server1 (2026-10-28 evidence pack: none of its 101
// files had a finding). xPGuard's own rules, built from how each works:
//
//   - fake plugins (decoy name with a 4-hex suffix, "corestudio"): a class
//     whose hook names, option keys and URLs are cut into ~100 short string
//     pieces ('wp'.'_foo'.'ter'), fetching a script from a C2 or, failing
//     that, from a Polygon contract (EtherHiding), injected site-wide;
//   - "woocommerce_inputs": a loader whose names are all md5 hashes
//     ($var_<32 hex>, fn_<32 hex>), a plugin reading its C2 domain from a
//     public Telegram channel page and creating admin users, and a footer
//     link injector fed by the C2's /api/links;
//   - a bank phishing kit (Mercantil, Chile): pages posting by fetch() to a
//     PHP backend that sends what victims type to a Telegram bot;
//   - casino SEO spam: 118 copies of the site's own WordPress pages filled
//     with casino offers, and a must-use plugin printing a hidden block of
//     casino links on every page;
//   - a file named by 32 hex holding only a base64 URL (a loader's C2).

var (
	// reSplitPiece: two short quoted word pieces joined by a dot.
	reSplitPiece = regexp.MustCompile(`'[A-Za-z_]{1,6}'\s*\.\s*'[A-Za-z_]{1,6}'`)
	// reHashName: identifiers named by an md5 hash.
	reHashName = regexp.MustCompile(`\$var_[0-9a-f]{32}\b|\bfn_[0-9a-f]{32}\s*\(`)
	reNetFetch = regexp.MustCompile(`\b(?:curl_exec|file_get_contents|wp_remote_(?:get|post)|fsockopen)\s*\(`)
	// reTgChannel: a public Telegram channel's web preview, read as a dead
	// drop for the C2 address.
	reTgChannel = regexp.MustCompile(`t\.me/s/`)
	reAddUser   = regexp.MustCompile(`\bwp_(?:insert|create)_user\s*\(`)
	reIncludeV  = regexp.MustCompile(`\b(?:include|require)(?:_once)?\s*\(?\s*\$`)
	// Footer links bought from a C2.
	reApiLinks   = regexp.MustCompile(`/api/links\b`)
	reNoVerify   = regexp.MustCompile(`['"]sslverify['"]\s*=>\s*false`)
	reFooterHook = regexp.MustCompile(`add_action\s*\(\s*['"](?:wp_footer|wp_body_open|wp_head)['"]`)

	// Telegram exfiltration, also through settings keys.
	reTgExfil = regexp.MustCompile(`(?i)api\.telegram\.org/bot|\btg_(?:token|chat)\b|['"]chat_id['"]`)
	reVictim  = regexp.MustCompile(`(?i)REMOTE_ADDR|HTTP_USER_AGENT|ip-api\.com|\bisp\b|client_ip`)
	// What a kit asks a victim for (English and Spanish).
	reSecretWord = regexp.MustCompile(`(?i)\b(?:cvv|cvc|clave|clv|otp|sms|codigo|pin|tarjeta|card_?number|password|contrase(?:n|ñ)a)\b`)
	// A script a page names (its form's action, a fetch() or a variable).
	reKitPost = regexp.MustCompile(`['"]([A-Za-z0-9_-]{1,40}\.php)(?:\?[^'"]{0,80})?['"]`)

	reGambling = regexp.MustCompile(`(?i)\b(?:online casinos?|casinos?|free spins|no deposit|deposit bonus|welcome bonus|slots?|betting|bookmakers?|gamstop|sportsbook|roulette|blackjack|jackpots?|wagering)\b`)
	// An element hidden from visitors by its own style (shown to search
	// engines): clipped, one pixel, or far off screen. Themes hide menus by
	// class or with display:none, not like this.
	reHiddenBlock = regexp.MustCompile(`(?i)style\s*=\s*["'][^"'>]{0,300}(?:clip\s*:\s*rect\(\s*0|(?:width|height)\s*:\s*[01]px|(?:left|top)\s*:\s*-\d{4,}px)`)
	reLink        = regexp.MustCompile(`(?i)<a\s[^>]*href\s*=`)
	reSiblingHTML = regexp.MustCompile(`__DIR__\s*\.\s*['"]/([A-Za-z0-9_.-]{1,60}\.html?)['"]`)
	reReadFile    = regexp.MustCompile(`\b(?:readfile|file_get_contents|include|require)\b`)

	// A plugin hiding itself from the plugin list and its deactivate link.
	reHidesPlugin  = regexp.MustCompile(`add_filter\s*\(\s*['"]all_plugins['"]`)
	reHidesActions = regexp.MustCompile(`['"]plugin_action_links_['"]\s*\.\s*plugin_basename\s*\(\s*__FILE__`)
	reWritesFile   = regexp.MustCompile(`\bfile_put_contents\s*\(`)

	reGamblingName = regexp.MustCompile(`casino|spins|bonus|slots?\b|betting|deposit|gamstop|poker|jackpot|wager|roulette|blackjack|bingo|gambl`)

	reHexName = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// kitFamilies judges content alone (see analyze).
func kitFamilies(ext string, content []byte) *Detection {
	php := bytes.Contains(content, []byte("<?"))
	if php && len(content) < 512<<10 {
		if len(reSplitPiece.FindAllIndex(content, 40)) >= 40 && bytes.Contains(content, []byte("add_action")) {
			return &Detection{CatVirus, "PHP.Obfuscated.SplitStrings"}
		}
		if n := len(reHashName.FindAllIndex(content, 20)); n >= 20 || n >= 10 && reNetFetch.Match(content) {
			return &Detection{CatVirus, "PHP.Obfuscated.HashNames"}
		}
		if reTgChannel.Match(content) && reNetFetch.Match(content) && (reAddUser.Match(content) || reIncludeV.Match(content)) {
			return &Detection{CatVirus, "PHP.Backdoor.TelegramDeadDrop"}
		}
		// Hidden from the plugin list, downloading and running code
		// (management plugins that hide themselves do not include what
		// they download from the same file).
		if len(content) < 64<<10 && reHidesPlugin.Match(content) && reHidesActions.Match(content) &&
			reNetFetch.Match(content) && reWritesFile.Match(content) && (reIncludeV.Match(content) || reAddUser.Match(content)) {
			return &Detection{CatVirus, "PHP.Backdoor.HiddenPluginLoader"}
		}
		if reApiLinks.Match(content) && reNoVerify.Match(content) && reFooterHook.Match(content) {
			return &Detection{CatVirus, "PHP.SEOSpam.RemoteFooterLinks"}
		}
		if phishBackend(content) {
			return &Detection{CatVirus, "Phishing.Collector.Telegram"}
		}
	}
	if ext == ".html" || ext == ".htm" || ext == ".php" {
		if hiddenGambling(content) {
			return &Detection{CatVirus, "HTML.SEOSpam.HiddenGambling"}
		}
	}
	return nil
}

// phishBackend: a script sending to a Telegram bot what a visitor typed,
// with the visitor's address or browser, asking for three kinds of secret,
// a card's or a bank login's among them (a plugin sending one-time codes by
// Telegram asks for no card).
func phishBackend(content []byte) bool {
	if !reTgExfil.Match(content) || !reVictim.Match(content) {
		return false
	}
	kinds := map[string]bool{}
	for _, m := range reSecretWord.FindAll(content, 200) {
		w := strings.ToLower(string(m))
		switch w {
		case "clv":
			w = "clave"
		case "cvc":
			w = "cvv"
		case "codigo":
			w = "sms"
		}
		kinds[w] = true
	}
	return len(kinds) >= 3 && (kinds["cvv"] || kinds["tarjeta"] || kinds["clave"] || kinds["card_number"] || kinds["cardnumber"])
}

// hiddenGambling: an element hidden from visitors holding a list of casino
// links (right after the hiding style).
func hiddenGambling(content []byte) bool {
	for _, m := range reHiddenBlock.FindAllIndex(content, 20) {
		w := content[m[1]:min(len(content), m[1]+16<<10)]
		if len(reGambling.FindAllIndex(w, 10)) >= 10 && len(reLink.FindAllIndex(w, 15)) >= 15 {
			return true
		}
	}
	return false
}

// kitByPlace judges content with the file's place (see contentVerdict).
func kitByPlace(path, ext string, content []byte) *Detection {
	base := filepath.Base(path)
	low := strings.ToLower(path)
	switch {
	case ext == "" && reHexName.MatchString(base) && len(content) < 512:
		// Only a base64 URL: a loader's C2 address.
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content))); err == nil &&
			(bytes.HasPrefix(b, []byte("https://")) || bytes.HasPrefix(b, []byte("http://"))) {
			return &Detection{CatVirus, "Dropper.Base64URL"}
		}
	case ext == ".html" || ext == ".htm":
		// A page of a phishing kit: it posts to a backend next to it.
		if reSecretWord.Match(content) {
			seen := map[string]bool{}
			for _, m := range reKitPost.FindAllSubmatch(content, 40) {
				name := string(m[1])
				if seen[name] || len(seen) == 5 {
					continue
				}
				seen[name] = true
				if b, err := readSmall(filepath.Join(filepath.Dir(path), name)); err == nil && phishBackend(b) {
					return &Detection{CatVirus, "Phishing.KitPage"}
				}
			}
		}
		// A copy of the site's own WordPress page filled with casino offers,
		// named for what it sells (not a page cache, which keeps the site's
		// real pages under wp-content).
		if !strings.Contains(low, "/wp-content/") && reGamblingName.MatchString(strings.ToLower(base)) && bytes.Count(content, []byte("wp-content")) >= 5 &&
			len(reGambling.FindAllIndex(content, 40)) >= 40 {
			return &Detection{CatVirus, "HTML.SEOSpam.GamblingDoorway"}
		}
	case ext == ".php" && strings.Contains(low, "/wp-content/mu-plugins/"):
		// A must-use plugin printing a hidden casino block kept next to it.
		if m := reSiblingHTML.FindSubmatch(content); m != nil && reReadFile.Match(content) && reFooterHook.Match(content) {
			if b, err := readSmall(filepath.Join(filepath.Dir(path), string(m[1]))); err == nil && hiddenGambling(b) {
				return &Detection{CatVirus, "PHP.SEOSpam.HiddenGamblingPrinter"}
			}
		}
	}
	return nil
}

// readSmall reads a file of at most 256 KB.
func readSmall(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 256<<10 {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(path)
}
