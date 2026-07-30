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

	req, _ := http.NewRequest("GET", srv.URL, nil)
	setBrowserHeaders(req, structure.DefaultUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if ua := got.Get("User-Agent"); ua != structure.DefaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, structure.DefaultUserAgent)
	}
	if strings.Contains(got.Get("User-Agent"), "Go-http-client") {
		t.Errorf("default Go User-Agent leaked")
	}
	for _, hdr := range []string{"Accept", "Accept-Language", "Sec-Fetch-Mode", "Upgrade-Insecure-Requests"} {
		if got.Get(hdr) == "" {
			t.Errorf("missing browser header %q", hdr)
		}
	}
	if v := got.Get("Sec-Ch-Ua"); !strings.Contains(v, `v="131"`) {
		t.Errorf("Sec-CH-UA = %q, want it derived from Chrome 131", v)
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
