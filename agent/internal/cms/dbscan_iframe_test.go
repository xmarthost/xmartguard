package cms

import "testing"

// Iframes from a live server's database scan that were reported as hidden
// and are not: WordPress's own post embeds, embed codes with marginheight=0,
// GiveWP donation forms.
func TestHiddenIframeFalsePositives(t *testing.T) {
	for name, v := range map[string]string{
		"WordPress embed":     `<blockquote class="wp-embedded-content" data-secret="lD6WU4stK5"><a href="https://globaldistrix.com/hello-world/">Hello world!</a></blockquote><iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" title="&#8220;Hello world!&#8221; &#8212; WHOLESELLER" src="https://globaldistrix.com/hello-world/embed/#?secret=qhZh1thBYU#?secret=lD6WU4stK5" data-secret="lD6WU4stK5" width="500" height="282" frameborder="0" marginwidth="0" marginheight="0" scrolling="no"></iframe>`,
		"embed without slash": `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" src="https://example.org/post-2/embed#?secret=abc" width="500" height="282"></iframe>`,
		"plain permalink":     `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" src="https://example.org/?p=12&embed=true#?secret=abc" width="500" height="282"></iframe>`,
		"SlideShare":          `<iframe style="border: 1px solid #CCC; border-width: 1px; margin-bottom: 5px; max-width: 100%;" src="//www.slideshare.net/slideshow/embed_code/key/ycHKVaPdSnP92m" width="595" height="700" frameborder="0" marginwidth="0" marginheight="0" scrolling="no" allowfullscreen="allowfullscreen"> </iframe>`,
		"Amazon widget":       `<iframe sandbox="allow-popups allow-scripts allow-modals allow-forms allow-same-origin" style="width:120px;height:240px;" marginwidth="0" marginheight="0" scrolling="no" frameborder="0" src="//ws-na.amazon-adsystem.com/widgets/q?ServiceVersion=20070822&OneJS=1"></iframe>`,
		"unquoted embed":      `<iframe src=//cdn.crichd.pro/embed2.php?id=ptvsp width=100% height=520 frameborder=0 scrolling=no allowfullscreen=true marginheight=0 marginwidth=0></iframe>`,
		"GiveWP form":         "<iframe\n\t\t\t\tname=\"give-embed-form\"\n\t\t\t\tsrc=\"https://cgg.carbonsmartgrowth.com/give/donation-form?giveDonationFormInIframe=1\"\n\t\t\t\tdata-autoScroll=\"0\"\n\t\t\t\tonload=\"if( 'undefined' !== typeof Give ) { Give.initializeIframeResize(this) }\"\n\t\t\t\tstyle=\"border: 0;visibility: hidden;min-height: 598px;\"></iframe>",
	} {
		if d := ScanValueDetail(v); d.Signature != "" {
			t.Errorf("%s: reported as %s", name, d.Signature)
		}
	}
}

// Injected hidden iframes are still found, also dressed up as an embed.
func TestHiddenIframeStillFound(t *testing.T) {
	for name, v := range map[string]string{
		"zero size":              `<p>Hi</p><iframe src="https://evil-traffic.example/in.php" width="0" height="0" frameborder="0"></iframe>`,
		"zero width only":        `<iframe width=0 height=10 src="//evil.example/x"></iframe>`,
		"zero px":                `<iframe width="0px" height="1" src="//evil.example/x"></iframe>`,
		"display none":           `<iframe style="display:none" src="https://evil.example/"></iframe>`,
		"visibility hidden":      `<iframe style="visibility: hidden" src="https://evil.example/"></iframe>`,
		"fake embed, no sandbox": `<iframe class="wp-embedded-content" style="visibility: hidden;" src="https://evil.example/p/embed/"></iframe>`,
		"fake embed, not /embed": `<iframe class="wp-embedded-content" sandbox="allow-scripts" style="visibility: hidden;" src="https://evil.example/in.php"></iframe>`,
		"fake embed, /embedded":  `<iframe class="wp-embedded-content" sandbox="allow-scripts" style="visibility: hidden;" src="https://evil.example/embedded.php"></iframe>`,
	} {
		if d := ScanValueDetail(v); d.Signature != "DB.Injected.HiddenIframe" {
			t.Errorf("%s: not found (%q)", name, d.Signature)
		}
	}
}
