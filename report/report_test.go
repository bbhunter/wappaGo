package report

import (
	"strings"
	"testing"

	"github.com/EasyRecon/wappaGo/structure"
)

// TestCardEscapesXSS pins the report XSS fix: attacker-controlled fields (page
// title, scanned URL, detected technology names) must be HTML-escaped, so a
// malicious scanned site cannot inject script into the operator's report.
func TestCardEscapesXSS(t *testing.T) {
	data := structure.Data{
		Url: "https://evil.test/",
		Infos: structure.Host{
			Title:       `</title><script>alert(1)</script>`,
			Status_code: 200,
			Screenshot:  "evil.png",
			Technologies: []structure.Technologie{
				{Name: `<img src=x onerror=alert(2)>`, Version: "1.0"},
			},
		},
	}

	out := card(data, "screens")

	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Errorf("page title injected a raw <script> tag into the report:\n%s", out)
	}
	if strings.Contains(out, "<img src=x onerror=alert(2)>") {
		t.Errorf("technology name injected raw HTML into the report:\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected the script tag to be HTML-escaped, got:\n%s", out)
	}
}
