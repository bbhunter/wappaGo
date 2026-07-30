package cmd

import "testing"

// TestResolveLocation pins the redirect fix. A relative Location used to be
// handed to chromedp.Navigate verbatim, which failed and aborted the entire
// action chain — the host came back with no title, no screenshot and zero
// technologies, with the error discarded.
func TestResolveLocation(t *testing.T) {
	cases := []struct {
		name     string
		probed   string
		location string
		want     string
	}{
		{"absolute stays put", "https://example.com", "https://www.example.com/", "https://www.example.com/"},
		{"root-relative", "https://stackoverflow.com", "/questions", "https://stackoverflow.com/questions"},
		{"path-relative", "https://example.com/a/b", "c/d", "https://example.com/a/c/d"},
		{"protocol-relative", "https://example.com", "//cdn.example.net/x", "https://cdn.example.net/x"},
		{"scheme upgrade", "http://example.com:8080", "https://example.com/", "https://example.com/"},
		{"keeps the port", "http://example.com:8080", "/admin", "http://example.com:8080/admin"},
		{"surrounding whitespace", "https://example.com", "  /trimmed  ", "https://example.com/trimmed"},

		// A scanned host must not be able to steer the operator's browser off
		// the web; these all fall back to the URL that was probed.
		{"refuses file", "https://example.com", "file:///C:/Windows/win.ini", "https://example.com"},
		{"refuses javascript", "https://example.com", "javascript:alert(1)", "https://example.com"},
		{"refuses data", "https://example.com", "data:text/html,<script>1</script>", "https://example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveLocation(tc.probed, tc.location); got != tc.want {
				t.Errorf("resolveLocation(%q, %q) = %q, want %q", tc.probed, tc.location, got, tc.want)
			}
		})
	}
}
