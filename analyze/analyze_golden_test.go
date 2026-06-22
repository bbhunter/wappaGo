package analyze

import (
	"sort"
	"testing"

	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/projectdiscovery/retryabledns"
)

// fixtureResultGlobal mimics the shape of the merged Wappalyzer fingerprint DB
// for a handful of technologies that can be detected without a live browser:
// only the html / headers / scriptSrc / meta signal sources are used, plus an
// "implies" edge. This lets Run() execute end-to-end (goquery parse + the
// regex matchers + CheckRequired + DedupTechno) with no chromedp context.
//
// It is the regression guard for the regex-precompilation refactor: the exact
// set of detected technologies and their versions must not change.
func fixtureResultGlobal() map[string]interface{} {
	return map[string]interface{}{
		"Nginx": map[string]interface{}{
			"cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
			"headers": map[string]interface{}{
				"Server": "nginx(?:/([\\d.]+))?\\;version:\\1",
			},
			"implies": "Reverse proxy",
		},
		"Reverse proxy": map[string]interface{}{}, // referenced only via implies
		"jQuery": map[string]interface{}{
			"scriptSrc": "jquery-([\\d.]+)\\.js\\;version:\\1",
		},
		"WordPress": map[string]interface{}{
			"meta": map[string]interface{}{
				"generator": "WordPress ?([\\d.]+)?\\;version:\\1",
			},
			"html": "wp-content",
		},
	}
}

func technologyVersions(techs []structure.Technologie) map[string]string {
	out := map[string]string{}
	for _, te := range techs {
		// keep the first non-empty version seen for a name
		if prev, ok := out[te.Name]; ok && prev != "" {
			continue
		}
		out[te.Name] = te.Version
	}
	return out
}

func technologyNames(techs []structure.Technologie) []string {
	var out []string
	for _, te := range techs {
		out = append(out, te.Name+"@"+te.Version)
	}
	sort.Strings(out)
	return out
}

func TestRunGoldenDetection(t *testing.T) {
	a := Analyze{
		ResultGlobal: fixtureResultGlobal(),
		Body: `<html><head>` +
			`<meta name="generator" content="WordPress 6.2">` +
			`</head><body class="wp-content">hello world</body></html>`,
		Resp: structure.Response{
			Headers: map[string][]string{"Server": {"nginx/1.21.0"}},
		},
		SrcList: []string{"https://code.jquery.com/jquery-3.6.0.js"},
	}

	got := technologies.DedupTechno(a.Run())
	gotVersions := technologyVersions(got)

	want := map[string]string{
		"Nginx":         "1.21.0", // version from header capture group
		"Reverse proxy": "",       // implied by Nginx, no version
		"jQuery":        "3.6.0",  // version from scriptSrc capture group
		"WordPress":     "6.2",    // version from meta generator capture group
	}

	if len(gotVersions) != len(want) {
		t.Fatalf("detected %d technologies, want %d: got %v", len(gotVersions), len(want), technologyNames(got))
	}
	for name, ver := range want {
		if gotVersions[name] != ver {
			t.Errorf("technology %q version = %q, want %q (all: %v)", name, gotVersions[name], ver, technologyNames(got))
		}
	}

	// The CPE attached to a fingerprint must survive detection.
	for _, te := range got {
		if te.Name == "Nginx" && te.Cpe == "" {
			t.Errorf("Nginx detected without its CPE")
		}
	}
}

// TestRunGoldenURLAndDNS covers the matchers converted from regexp.MatchString
// to the cached compileCI (url, dns) and pins the panic-safety contract: a
// PCRE-only pattern that Go's RE2 engine rejects must be skipped silently
// rather than aborting the scan.
func TestRunGoldenURLAndDNS(t *testing.T) {
	rg := map[string]interface{}{
		"AdminPanel": map[string]interface{}{
			"url": "example\\.com/admin",
		},
		"GoogleWorkspace": map[string]interface{}{
			"dns": map[string]interface{}{
				"TXT": "include:_spf\\.google\\.com",
			},
		},
		"BrokenPCRE": map[string]interface{}{
			// Go RE2 rejects look-ahead; must be skipped, not matched, not panic.
			"html": "foo(?=bar)",
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body:         `<html><body>foobar example</body></html>`,
		Hote:         structure.Host{Location: "https://example.com/admin"},
		DnsData:      &retryabledns.DNSData{TXT: []string{"v=spf1 include:_spf.google.com ~all"}},
	}

	got := technologies.DedupTechno(a.Run())
	gotVersions := technologyVersions(got)

	want := []string{"AdminPanel", "GoogleWorkspace"}
	if len(gotVersions) != len(want) {
		t.Fatalf("detected %v, want exactly %v", technologyNames(got), want)
	}
	for _, name := range want {
		if _, ok := gotVersions[name]; !ok {
			t.Errorf("missing detection %q (got %v)", name, technologyNames(got))
		}
	}
	if _, ok := gotVersions["BrokenPCRE"]; ok {
		t.Errorf("BrokenPCRE matched; an invalid RE2 pattern must be skipped")
	}
}

// TestImpliesMissingTechnoNoPanic pins the crash-containment hardening: an
// "implies" edge pointing at a technology absent from the DB must add that
// technology without panicking (the original AddTechno/NewTechno asserted the
// missing map entry and crashed the whole scan).
func TestImpliesMissingTechnoNoPanic(t *testing.T) {
	rg := map[string]interface{}{
		"Thing": map[string]interface{}{
			"html":    "thing-marker",
			"implies": "GhostTech", // intentionally not present in the DB
		},
	}
	a := Analyze{ResultGlobal: rg, Body: `<html><body>thing-marker</body></html>`}

	got := technologies.DedupTechno(a.Run()) // must not panic
	names := technologyVersions(got)
	if _, ok := names["Thing"]; !ok {
		t.Errorf("Thing not detected (got %v)", technologyNames(got))
	}
	if _, ok := names["GhostTech"]; !ok {
		t.Errorf("implied GhostTech not added (got %v)", technologyNames(got))
	}
}

// TestRequiresGate pins the requires-vs-implies behaviour change: a technology
// with a "requires" precondition is kept only when the required technology is
// independently detected, and is dropped otherwise (the old code added the
// required techno unconditionally, producing false positives).
func TestRequiresGate(t *testing.T) {
	rg := map[string]interface{}{
		"WPPlugin": map[string]interface{}{
			"html":     "wp-plugin-marker",
			"requires": "WordPress",
		},
		"WordPress": map[string]interface{}{
			"meta": map[string]interface{}{"generator": "WordPress"},
		},
	}

	// WordPress present -> the plugin survives the gate.
	a := Analyze{
		ResultGlobal: rg,
		Body: `<html><head><meta name="generator" content="WordPress"></head>` +
			`<body>wp-plugin-marker</body></html>`,
	}
	got := technologies.FilterRequired(technologies.DedupTechno(a.Run()), rg)
	names := technologyVersions(got)
	for _, want := range []string{"WordPress", "WPPlugin"} {
		if _, ok := names[want]; !ok {
			t.Errorf("expected %q kept when WordPress is present (got %v)", want, technologyNames(got))
		}
	}

	// WordPress absent -> the plugin is dropped, and nothing is fabricated.
	b := Analyze{
		ResultGlobal: rg,
		Body:         `<html><body>wp-plugin-marker</body></html>`,
	}
	got2 := technologies.FilterRequired(technologies.DedupTechno(b.Run()), rg)
	names2 := technologyVersions(got2)
	if _, ok := names2["WPPlugin"]; ok {
		t.Errorf("WPPlugin should be dropped when required WordPress is absent (got %v)", technologyNames(got2))
	}
	if _, ok := names2["WordPress"]; ok {
		t.Errorf("WordPress must not be fabricated by a requires edge (got %v)", technologyNames(got2))
	}
}

// TestCompileCICachesAndToleratesBadPatterns documents the contract the
// matchers rely on: valid patterns compile (and are cached), invalid RE2
// patterns return ok=false instead of panicking.
func TestCompileCICachesAndToleratesBadPatterns(t *testing.T) {
	re1, ok := compileCI(`nginx/([\d.]+)`)
	if !ok || re1 == nil {
		t.Fatalf("valid pattern failed to compile")
	}
	re2, _ := compileCI(`nginx/([\d.]+)`)
	if re1 != re2 {
		t.Errorf("compileCI did not return the cached *regexp.Regexp for an identical pattern")
	}
	if _, ok := compileCI(`(?P<name>`); ok {
		t.Errorf("invalid pattern reported ok=true; expected graceful failure")
	}
	if !re1.MatchString("nginx/1.21.0") {
		t.Errorf("cached regex lost its semantics")
	}
}
