package waf

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// commentPost is a comment sent to wp-comments-post.php (inert fixtures:
// example domains only).
type commentPost struct {
	name                  string
	origin, referer       bool
	comment, author, site string
	spam                  bool
}

var commentPosts = []commentPost{
	// The SEO spam that reached a customer's moderation queue: a keyword
	// as the name, an HTML link in the text and the same shop as website.
	{"HTML link plus website", true, true, `Go and sing to me.<a href="https://dolls.example/goods/p3025.html">cheap dolls</a>I'm dying for some music,`, "リアルドール", "https://dolls.example/category/c34.html", true},
	{"HTML link with entities", true, true, `nice &lt;a href=&quot;https://pills.example/&quot;&gt;pills&lt;/a&gt;`, "Buy Pills", "pills.example", true},
	{"BBCode links", true, true, `[url=https://casino.example]best casino[/url] [link=https://casino.example/b]bonus[/link]`, "casino", "", true},
	{"Many links", true, true, "good list https://a.example/1 https://b.example/2\nhttp://c.example/3 and ftp://d.example/4", "John", "", true},
	{"Posted by a script", false, false, "Thanks for sharing", "Mike", "", true},

	// Real visitors.
	{"Plain thanks", true, true, "Thanks, the cron fix worked on my cPanel account!", "Ali", "", false},
	{"Urdu comment", true, false, "بہت شکریہ، مسئلہ حل ہو گیا", "مریم", "", false},
	{"Own blog as website", true, true, "I wrote about the same error, the PHP path was wrong in my case.", "Sara", "https://sara.example.blog", false},
	{"One pasted link", true, true, "The docs are here: https://docs.example.com/cron and they helped.", "Bilal", "https://bilal.example", false},
	{"Three links", true, true, "See https://a.example/x, https://b.example/y and https://c.example/z", "Omar", "", false},
	{"Explains HTML without a website", true, true, `Use <a href="https://example.com">text</a> in the widget.`, "Dev", "", false},
	{"Referer stripped by privacy settings", true, false, "Great guide", "Hina", "", false},
	{"Time with colons", true, true, "Runs at 10:30, then 11:45:00 and 12:00:00 — https://a.example/ok", "Asad", "", false},
}

// ruleChains returns, for each rule id, the variables and regexes of its
// chained @rx conditions.
func ruleChains(out string, id int) [][2]string {
	reCond := regexp.MustCompile(`^\s+SecRule (\S+) "@rx (.*?)" "`)
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "SecRule ") || !strings.Contains(l, fmt.Sprintf("id:%d,", id)) {
			continue
		}
		var conds [][2]string
		for _, c := range lines[i+1:] {
			if !strings.HasPrefix(c, "  ") {
				break
			}
			if m := reCond.FindStringSubmatch(c); m != nil {
				conds = append(conds, [2]string{m[1], m[2]})
			}
		}
		return conds
	}
	return nil
}

// TestCommentSpamRules checks the comment spam rules on spam that reached
// customers and on real comments: spam matches, real comments never do.
func TestCommentSpamRules(t *testing.T) {
	out := Render(settings.WAF{Enabled: true, WordPress: true}, Options{Dir: "/r"})
	// New: they only watch until approved in the portal.
	for _, id := range []int{IDCommentScript, IDCommentLinks, IDCommentLinks + 1000, IDCommentManyLinks} {
		if l := ruleLine(out, id); l == "" || strings.Contains(l, "deny") {
			t.Fatalf("rule %d missing or blocking before approval: %s", id, l)
		}
	}
	approved := Render(settings.WAF{Enabled: true, WordPress: true}, Options{Dir: "/r", Intel: (&Intel{Enforce: []int{IDCommentScript, IDCommentLinks, IDCommentManyLinks}}).Clean()})
	if l := ruleLine(approved, IDCommentLinks+1000); !strings.Contains(l, "deny,status:403") {
		t.Fatalf("approved rule does not block: %s", l)
	}

	entity := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&amp;", "&")
	matches := func(id int, p commentPost) bool {
		conds := ruleChains(out, id)
		if len(conds) == 0 {
			t.Fatalf("rule %d has no conditions", id)
		}
		for _, c := range conds {
			v := map[string]string{"ARGS_POST:comment": p.comment, "ARGS_POST:url": p.site}[c[0]]
			v = strings.ToLower(entity.Replace(v))
			if !regexp.MustCompile(c[1]).MatchString(v) {
				return false
			}
		}
		return true
	}
	for _, p := range commentPosts {
		hit := !p.origin && !p.referer
		for _, id := range []int{IDCommentLinks, IDCommentLinks + 1000, IDCommentManyLinks} {
			hit = hit || matches(id, p)
		}
		if hit != p.spam {
			t.Errorf("%s: matched %v, spam %v", p.name, hit, p.spam)
		}
	}
	// The script rule needs both headers missing.
	if l := strings.Join(strings.Split(out, "\n"), "\n"); !strings.Contains(l, `SecRule &REQUEST_HEADERS:Origin "@eq 0" "t:none,chain"`) || !strings.Contains(l, `SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none"`) {
		t.Fatal("script rule does not test the missing headers")
	}
}

// TestCommentSpamOnApache sends the same comments through Apache with
// ModSecurity, the OWASP CRS and the comment rules approved.
func TestCommentSpamOnApache(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	approved := func(m *Manager) {
		m.Intel = func() *Intel {
			return &Intel{Enforce: []int{IDShopScrape, IDCartSpam, IDNoUAPost, IDCommentScript, IDCommentLinks, IDCommentManyLinks}}
		}
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","wordpress":true,"generic":true,"bad_bots":true,"sensitive_files":true}}`, "off", approved)
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	ua := "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
	for _, p := range commentPosts {
		hdr := []string{ua}
		if p.origin {
			hdr = append(hdr, "Origin: https://blog.example.com")
		}
		if p.referer {
			hdr = append(hdr, "Referer: https://blog.example.com/resolving-a-cron-job/")
		}
		body := "comment=" + urlEncode(p.comment) + "&author=" + urlEncode(p.author) + "&email=" + urlEncode("reader@example.com") +
			"&url=" + urlEncode(p.site) + "&submit=Post+Comment&comment_post_ID=42&comment_parent=0"
		got := sendBody(t, "blog.example.com", "POST", "/wp-comments-post.php", "application/x-www-form-urlencoded", body, hdr...)
		if (got == 403) != p.spam || got == 0 {
			t.Errorf("%s: got %d, spam %v", p.name, got, p.spam)
		}
	}
}
