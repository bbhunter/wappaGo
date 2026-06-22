package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestReportRendersFullPage exercises the whole report with varied hosts and
// writes a sample to the temp dir for manual inspection.
func TestReportRendersFullPage(t *testing.T) {
	datas := []structure.Data{
		{
			Url: "https://example.com",
			Infos: structure.Host{
				Status_code: 200, Scheme: "https", Data: "example.com",
				Title: "Example Domain — Home", IP: "93.184.216.34", CDN: "Cloudflare",
				Content_type: "text/html", Content_length: 24576,
				Response_time: 142 * time.Millisecond, Ports: []string{"80", "443"},
				Screenshot: "abc123.png",
				Technologies: []structure.Technologie{
					{Name: "Nginx", Version: "1.21.0", Cpe: "cpe:2.3:a:nginx:nginx", Confidence: "100"},
					{Name: "PHP", Version: "8.1"},
					{Name: "jQuery", Version: "3.6.0"},
				},
				CertVhost: []string{"example.com", "www.example.com", "*.example.com"},
				Cname:     []string{"example.com.cdn.cloudflare.net"},
			},
		},
		{
			Url: "https://shop.example.com",
			Infos: structure.Host{
				Status_code: 301, Scheme: "https", Data: "shop.example.com",
				Title: "Redirecting…", IP: "93.184.216.35",
				Location: "https://www.example.com/shop", Ports: []string{"443"},
			},
		},
		{
			Url: "https://api.example.com",
			Infos: structure.Host{
				Status_code: 500, Scheme: "https", Data: "api.example.com",
				IP: "10.0.0.7", Content_type: "application/json", Content_length: 312,
				Response_time: 2300 * time.Millisecond, Ports: []string{"443", "8443"},
			},
		},
		{
			Url: "http://legacy.example.com",
			Infos: structure.Host{
				Status_code: 404, Scheme: "http", Data: "legacy.example.com",
				Title: `</title><script>alert(document.domain)</script>`, IP: "203.0.113.9",
				Technologies: []structure.Technologie{{Name: `<b>Evil</b>`}},
			},
		},
	}

	counts := map[string]int{}
	techs := map[string]bool{}
	for _, d := range datas {
		counts[statusClass(d.Infos.Status_code)]++
		for _, te := range d.Infos.Technologies {
			techs[te.Name] = true
		}
	}
	var b strings.Builder
	b.WriteString(pageHead)
	b.WriteString(renderSummary(len(datas), len(techs), counts))
	b.WriteString(`<main class="grid" id="grid">`)
	for _, d := range datas {
		b.WriteString(card(d, "screenshots"))
	}
	b.WriteString(pageFoot)
	page := b.String()

	for _, want := range []string{
		"<!doctype html>", "</html>", `id="lightbox"`, `id="filter"`,
		"example.com", "93.184.216.34", "Cloudflare", "24.0 KB", "142 ms", "2.30 s",
		"cert SANs", "*.example.com", "cname", `class="stamp">301`, `class="stamp">500`,
		"https://www.example.com/shop", "1.21.0",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered report is missing %q", want)
		}
	}
	if strings.Contains(page, "<script>alert(document.domain)</script>") {
		t.Errorf("full page leaked an unescaped <script> from a host title")
	}
	if strings.Contains(page, "<b>Evil</b>") {
		t.Errorf("full page leaked unescaped HTML from a technology name")
	}

	out := filepath.Join(os.TempDir(), "wappago_sample_report.html")
	if err := os.WriteFile(out, []byte(page), 0644); err == nil {
		t.Logf("sample report written to %s (%d bytes)", out, len(page))
	}
}
