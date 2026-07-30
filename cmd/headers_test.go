package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EasyRecon/wappaGo/structure"
)

// TestSetBrowserHeadersOnWire confirms the raw probe sends a real browser
// fingerprint over the wire instead of Go's default "Go-http-client" UA — the
// single biggest reason WappaGo was tripping WAFs.
func TestSetBrowserHeadersOnWire(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	id := fallbackIdentity()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	setBrowserHeaders(req, id)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if ua := got.Get("User-Agent"); ua != id.UserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, id.UserAgent)
	}
	if strings.Contains(got.Get("User-Agent"), "Go-http-client") {
		t.Errorf("default Go User-Agent leaked")
	}
	for _, hdr := range []string{"Accept", "Accept-Language", "Sec-Fetch-Mode", "Upgrade-Insecure-Requests"} {
		if got.Get(hdr) == "" {
			t.Errorf("missing browser header %q", hdr)
		}
	}
	if v := got.Get("Sec-Ch-Ua"); !strings.Contains(v, `v="`+id.Major+`"`) {
		t.Errorf("Sec-CH-UA = %q, want it derived from the identity's major %q", v, id.Major)
	}
}

// TestProbeSecChUaMatchesTheBrowsers pins the second half of the identity fix.
// The User-Agent was made coherent between probe and browser, but the probe kept
// emitting a hardcoded Chrome-110-era Sec-CH-UA — brands in the opposite order to
// what Chrome sends, and "Not_A Brand";v="24" instead of "Not)A;Brand";v="99".
// A WAF comparing the two clients saw two different browsers.
func TestProbeSecChUaMatchesTheBrowsers(t *testing.T) {
	id := identity{UserAgent: structure.DefaultUserAgent, Major: "150", Full: "150.0.0.0", Platform: "Windows"}

	req, _ := http.NewRequest("GET", "https://example.test", nil)
	setBrowserHeaders(req, id)
	probe := req.Header.Get("Sec-Ch-Ua")

	// Rebuild what Chrome is told to report, from the same metadata.
	var browser []string
	for _, b := range id.metadata().Brands {
		browser = append(browser, `"`+b.Brand+`";v="`+b.Version+`"`)
	}
	want := strings.Join(browser, ", ")

	if probe != want {
		t.Errorf("probe and browser disagree on Sec-CH-UA:\n  probe   = %s\n  browser = %s", probe, want)
	}
	if strings.Contains(probe, "Not_A Brand") {
		t.Errorf("probe still sends the stale Chrome-110 brand spelling: %s", probe)
	}
	if got := req.Header.Get("Sec-Ch-Ua-Platform"); got != `"Windows"` {
		t.Errorf("Sec-CH-UA-Platform = %q, want it from the identity", got)
	}
}

func TestChromeMajor(t *testing.T) {
	cases := map[string]string{
		structure.DefaultUserAgent:               "131",
		"... Chrome/120.0.6099.71 Safari/537.36": "120",
		"Mozilla/5.0 Firefox/124.0":              "",
		"":                                       "",
	}
	for ua, want := range cases {
		if got := chromeMajor(ua); got != want {
			t.Errorf("chromeMajor(%q) = %q, want %q", ua, got, want)
		}
	}
}
