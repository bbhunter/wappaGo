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

// TestIconIsCarriedThrough pins the icon field: it is copied from the database
// for detected and implied technologies alike, and omitted (rather than
// invented) for fingerprints that declare none.
func TestIconIsCarriedThrough(t *testing.T) {
	rg := map[string]interface{}{
		"Nginx": map[string]interface{}{
			"icon":    "Nginx.svg",
			"headers": map[string]interface{}{"Server": "nginx"},
			"implies": "Reverse proxy",
		},
		"Reverse proxy": map[string]interface{}{"icon": "ReverseProxy.svg"},
		"NoIcon": map[string]interface{}{
			"html": "no-icon-marker",
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body:         `<html><body>no-icon-marker</body></html>`,
		Resp:         structure.Response{Headers: map[string][]string{"Server": {"nginx"}}},
	}

	icons := map[string]string{}
	for _, te := range technologies.DedupTechno(a.Run()) {
		icons[te.Name] = te.Icon
	}
	for name, want := range map[string]string{
		"Nginx":         "Nginx.svg",
		"Reverse proxy": "ReverseProxy.svg", // reached through implies
		"NoIcon":        "",
	} {
		got, ok := icons[name]
		if !ok {
			t.Errorf("%q not detected (got %v)", name, icons)
			continue
		}
		if got != want {
			t.Errorf("%q icon = %q, want %q", name, got, want)
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

// TestHeaderKeyCasing pins the header-lookup fix. Wappalyzer keys its header
// fingerprints however upstream wrote them ("x-powered-by", "server"), while
// a.Resp.Headers is an http.Header clone and is therefore canonical
// ("X-Powered-By", "Server"). Indexing the fingerprint with the response's key
// silently disabled 43% of the header database, so every one of these forms
// must now match.
func TestHeaderKeyCasing(t *testing.T) {
	rg := map[string]interface{}{
		// lowercase key + version marker, as Vercel/Ktor ship it
		"LowerWithVersion": map[string]interface{}{
			"headers": map[string]interface{}{"x-engine": `Ktor/([\d.]+)\;version:\1`},
		},
		// lowercase key, presence only
		"LowerPresence": map[string]interface{}{
			"headers": map[string]interface{}{"x-vercel-cache": ""},
		},
		// mixed case that canonicalises differently ("X-Aspnet-Version")
		"MixedCase": map[string]interface{}{
			"headers": map[string]interface{}{"X-AspNet-Version": `([\d.]+)`},
		},
		// already canonical: the one spelling that worked before
		"Canonical": map[string]interface{}{
			"headers": map[string]interface{}{"Server": `nginx/([\d.]+)\;version:\1`},
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Resp: structure.Response{
			Headers: map[string][]string{
				"X-Engine":           {"Ktor/2.3.4"},
				"X-Vercel-Cache":     {"HIT"},
				"X-Aspnet-Version":   {"4.0.30319"},
				"Server":             {"nginx/1.21.0"},
				"X-Unrelated-Header": {"noise"},
			},
		},
	}

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	for name, wantVer := range map[string]string{
		"LowerWithVersion": "2.3.4",
		"LowerPresence":    "",
		"MixedCase":        "",
		"Canonical":        "1.21.0",
	} {
		ver, ok := got[name]
		if !ok {
			t.Errorf("%q not detected — header lookup missed its fingerprint key (got %v)", name, got)
			continue
		}
		if ver != wantVer {
			t.Errorf("%q version = %q, want %q", name, ver, wantVer)
		}
	}
	if len(got) != 4 {
		t.Errorf("detected %d technologies, want 4: %v", len(got), got)
	}
}

// TestHeaderRepeatedValues covers the second half of the same fix: a header can
// repeat, and only values[0] used to be examined (which also panicked on an
// empty value slice).
func TestHeaderRepeatedValues(t *testing.T) {
	rg := map[string]interface{}{
		"Varnish": map[string]interface{}{
			"headers": map[string]interface{}{"via": `varnish \(Varnish/([\d.]+)\)\;version:\1`},
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Resp: structure.Response{
			Headers: map[string][]string{
				"Via":    {"1.1 google", "1.1 varnish (Varnish/7.1)"},
				"Empty":  {},
				"Server": {"nginx"},
			},
		},
	}

	got := technologyVersions(technologies.DedupTechno(a.Run())) // must not panic
	if got["Varnish"] != "7.1" {
		t.Errorf("Varnish version = %q, want %q (only the first header value was inspected)", got["Varnish"], "7.1")
	}
}

// TestFinalHeadersPreferredOverProbe pins the redirect fix on the header side:
// with -follow-redirect off the raw probe stops at the 30x, so its headers
// describe the redirector, not the page Chrome renders and analyses. A host
// redirecting http->https therefore reported none of its header-based
// technologies. CDP also newline-joins repeated headers, which must be split
// back apart.
func TestFinalHeadersPreferredOverProbe(t *testing.T) {
	rg := map[string]interface{}{
		"Nginx":   map[string]interface{}{"headers": map[string]interface{}{"Server": `nginx/([\d.]+)\;version:\1`}},
		"Varnish": map[string]interface{}{"headers": map[string]interface{}{"via": `(\d+(?:\.\d+)?)\s+varnish\;version:\1`}},
	}

	a := Analyze{
		ResultGlobal: rg,
		Body:         "<html></html>",
		// The probe only saw the redirector: no Server, no Via.
		Resp: structure.Response{Headers: map[string][]string{"Location": {"https://example.com/"}}},
	}
	// What Chrome reported for the final document, in CDP's shape.
	a.SetFinalHeaders("https://example.com/", map[string]interface{}{
		"server": "nginx/1.25.3",
		"via":    "1.1 google\n1.1 varnish",
	})

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	if got["Nginx"] != "1.25.3" {
		t.Errorf("Nginx = %q, want %q — the final page's headers must be used", got["Nginx"], "1.25.3")
	}
	if got["Varnish"] != "1.1" {
		t.Errorf("Varnish = %q, want %q — repeated headers must be split on newline", got["Varnish"], "1.1")
	}

	// With no Chrome headers at all, the probe's are still used.
	b := Analyze{
		ResultGlobal: rg,
		Body:         "<html></html>",
		Resp:         structure.Response{Headers: map[string][]string{"Server": {"nginx/1.21.0"}}},
	}
	if got := technologyVersions(technologies.DedupTechno(b.Run())); got["Nginx"] != "1.21.0" {
		t.Errorf("fallback to probe headers broken: %v", got)
	}
}

// TestHeadersAreMergedNotReplaced pins the union: Chrome never reports Alt-Svc
// (it consumes it), and that header is the only signal for HTTP/3, so preferring
// Chrome's set outright silently dropped it. Chrome must still win on headers
// present in both, since its view is the page that was actually analysed.
func TestHeadersAreMergedNotReplaced(t *testing.T) {
	rg := map[string]interface{}{
		"HTTP/3": map[string]interface{}{"headers": map[string]interface{}{"Alt-Svc": "h3"}},
		"Nginx":  map[string]interface{}{"headers": map[string]interface{}{"Server": `nginx/([\d.]+)\;version:\1`}},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body:         "<html></html>",
		Resp: structure.Response{Headers: map[string][]string{
			"Alt-Svc": {`h3=":443"; ma=86400`}, // only the probe sees this
			"Server":  {"nginx/1.21.0"},        // stale: this was the redirector
		}},
	}
	a.SetFinalHeaders("https://example.com/", map[string]interface{}{
		"server": "nginx/1.25.3", // the page actually analysed
	})

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	if _, ok := got["HTTP/3"]; !ok {
		t.Errorf("probe-only header lost: %v", got)
	}
	if got["Nginx"] != "1.25.3" {
		t.Errorf("Nginx = %q, want %q — Chrome must win where both have the header", got["Nginx"], "1.25.3")
	}
}

// TestUrlMatchesScannedURL pins the url-family fix: patterns are matched
// against the URL that was scanned, not against the Location header, and no
// longer require the host to have redirected.
func TestUrlMatchesScannedURL(t *testing.T) {
	rg := map[string]interface{}{
		"AdminPanel": map[string]interface{}{"url": `example\.com/admin`},
		"Ionos":      map[string]interface{}{"url": `^https?://[^/]+\.ionos\.(space|live)`},
	}

	// No redirect at all: both fingerprints used to be skipped outright.
	a := Analyze{ResultGlobal: rg, Url: "https://example.com/admin", Body: "<html></html>"}
	if got := technologyVersions(technologies.DedupTechno(a.Run())); len(got) != 1 || got["AdminPanel"] != "" {
		t.Errorf("AdminPanel not detected on a non-redirecting host: %v", got)
	}

	b := Analyze{ResultGlobal: rg, Url: "https://foo.ionos.space", Body: "<html></html>"}
	if got := technologyVersions(technologies.DedupTechno(b.Run())); len(got) != 1 || got["Ionos"] != "" {
		t.Errorf("Ionos not detected: %v", got)
	}

	// The redirect target is still considered.
	c := Analyze{
		ResultGlobal: rg,
		Url:          "https://other.test",
		Hote:         structure.Host{Location: "https://example.com/admin"},
		Body:         "<html></html>",
	}
	if got := technologyVersions(technologies.DedupTechno(c.Run())); len(got) != 1 {
		t.Errorf("redirect target ignored: %v", got)
	}

	// Neither matches -> nothing detected.
	d := Analyze{ResultGlobal: rg, Url: "https://unrelated.test/", Body: "<html></html>"}
	if got := technologyVersions(technologies.DedupTechno(d.Run())); len(got) != 0 {
		t.Errorf("false positive: %v", got)
	}
}

// TestMetaMatchesPropertyAttribute pins the meta fix: Wappalyzer keys meta
// fingerprints on either attribute, and only meta[name=] used to be searched, so
// every og:/twitter:/fb: fingerprint was unreachable.
func TestMetaMatchesPropertyAttribute(t *testing.T) {
	rg := map[string]interface{}{
		"OpenGraph": map[string]interface{}{
			"meta": map[string]interface{}{"og:site_name": ""},
		},
		"Generator": map[string]interface{}{
			"meta": map[string]interface{}{"generator": `Hugo ([\d.]+)\;version:\1`},
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body: `<html><head>` +
			`<meta property="og:site_name" content="Example">` +
			`<meta name="generator" content="Hugo 0.157.0">` +
			`</head><body></body></html>`,
	}

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	if _, ok := got["OpenGraph"]; !ok {
		t.Errorf("meta[property] fingerprint not matched: %v", got)
	}
	if got["Generator"] != "0.157.0" {
		t.Errorf("meta[name] version = %q, want %q", got["Generator"], "0.157.0")
	}
}

// TestTextMatchesRenderedTextOnly pins the html-vs-text split: a "text" pattern
// must match the page's rendered text, not its markup, or it fires on attribute
// values and URLs that are invisible to a visitor.
func TestTextMatchesRenderedTextOnly(t *testing.T) {
	rg := map[string]interface{}{
		"MarkupOnly": map[string]interface{}{"text": "data-vendor"},
		"RealText":   map[string]interface{}{"text": "Powered by Acme"},
		"HtmlFamily": map[string]interface{}{"html": "data-vendor"},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body:         `<html><body data-vendor="acme"><p>Powered by Acme</p></body></html>`,
	}

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	if _, ok := got["RealText"]; !ok {
		t.Errorf("visible text not matched: %v", got)
	}
	if _, ok := got["HtmlFamily"]; !ok {
		t.Errorf("html family must still see the markup: %v", got)
	}
	if _, ok := got["MarkupOnly"]; ok {
		t.Errorf("a text pattern matched an attribute value: %v", got)
	}
}

// TestDomTextUsesElementText pins the dom fix: the pattern is matched against
// the selected element, not against the whole document.
func TestDomTextUsesElementText(t *testing.T) {
	rg := map[string]interface{}{
		"Widget": map[string]interface{}{
			"dom": map[string]interface{}{
				".version": map[string]interface{}{"text": `v([\d.]+)\;version:\1`},
			},
		},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body: `<html><body><span class="other">v9.9.9</span>` +
			`<span class="version">v1.2.3</span></body></html>`,
	}

	got := technologyVersions(technologies.DedupTechno(a.Run()))
	if got["Widget"] != "1.2.3" {
		t.Errorf("version = %q, want %q — the pattern must read the selected element, not the page", got["Widget"], "1.2.3")
	}
}

// TestBadFingerprintShapesDoNotPanic feeds every matcher a value of the wrong
// JSON type. The database is third-party data fetched at startup, so a shape
// change must degrade detection, not crash the scan.
func TestBadFingerprintShapesDoNotPanic(t *testing.T) {
	rg := map[string]interface{}{
		"BadHeaders":    map[string]interface{}{"headers": "should-be-an-object"},
		"BadMeta":       map[string]interface{}{"meta": []interface{}{"should-be-an-object"}},
		"BadDom":        map[string]interface{}{"dom": map[string]interface{}{"div": "should-be-an-object"}},
		"BadCert":       map[string]interface{}{"certIssuer": []interface{}{1, 2, 3}},
		"BadDns":        map[string]interface{}{"dns": "should-be-an-object"},
		"BadUrl":        map[string]interface{}{"url": 42},
		"BadScriptSrc":  map[string]interface{}{"scriptSrc": map[string]interface{}{"a": "b"}},
		"BadHtml":       map[string]interface{}{"html": map[string]interface{}{"a": "b"}},
		"BadXhr":        map[string]interface{}{"xhr": 3.14},
		"NotAnObject":   "this technology is not a map at all",
		"NilEverything": map[string]interface{}{"headers": nil, "html": nil, "meta": nil},
	}
	a := Analyze{
		ResultGlobal: rg,
		Body:         `<html><body><div>hello</div></body></html>`,
		Resp:         structure.Response{Headers: map[string][]string{"Server": {"nginx"}}},
		SrcList:      []string{"https://cdn.test/x.js"},
		Url:          "https://example.com",
		CertIssuer:   "Some CA",
		// DnsData deliberately nil: resolution failure must not panic either.
	}

	got := technologies.DedupTechno(a.Run()) // must not panic
	if len(got) != 0 {
		t.Errorf("malformed fingerprints produced detections: %v", technologyNames(got))
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
