package scanner

import (
	"bytes"
	"regexp"
)

// Defacement pages: after a takeover the site's index page is replaced by a
// "Hacked by …" page. The claim sits in the page title or a big heading,
// and the page carries the defacer's usual furniture (greetings to other
// groups, a team name, scrolling text, background music). An article
// about a hack is a long page of a site's theme, never a short page with
// that furniture.

var (
	reDefaceClaim = regexp.MustCompile(`(?is)<(?:title|h1|h2|center|font)[^>]*>[^<]{0,80}\b(?:h[a4]ck[e3]d|d[e3]f[a4]c[e3]d|0wn[e3]d|pwn[e3]d)\s+by\b`)
	reDefaceKit   = regexp.MustCompile(`(?i)\bgreetz?\b|\bgreets\s+to\b|\bcyber\s*(?:army|team|force|ghost|squad)\b|security\s+is\s+(?:just\s+)?an?\s+illusion|<marquee\b|<(?:audio|embed|iframe)[^>]*(?:autoplay|youtube)|\bwe\s+are\s+(?:anonymous|legion)\b|\bexpect\s+us\b|\bnothing\s+is\s+secure\b`)
)

// defacement reports a defacement page.
func defacement(ext string, content []byte) *Detection {
	switch ext {
	case ".html", ".htm", ".php", ".shtml":
	default:
		return nil
	}
	if len(content) > 64<<10 || !bytes.Contains(bytes.ToLower(content[:min(len(content), 4096)]), []byte("by")) {
		return nil
	}
	if !reDefaceClaim.Match(content) {
		return nil
	}
	if len(reDefaceKit.FindAll(content, 2)) >= 1 {
		return &Detection{CatVirus, "HTML.Defacement"}
	}
	// The claim alone, on a page with nothing else on it.
	if len(content) <= 2048 {
		return &Detection{CatSuspicious, "HTML.Defacement.Claim"}
	}
	return nil
}
