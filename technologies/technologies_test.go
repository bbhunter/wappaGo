package technologies

import (
	"reflect"
	"testing"

	"github.com/EasyRecon/wappaGo/structure"
)

func names(techs []structure.Technologie) []string {
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		out = append(out, t.Name)
	}
	return out
}

// TestSplitMarkers pins the marker parsing shared by implies/requires/excludes.
func TestSplitMarkers(t *testing.T) {
	cases := []struct {
		in                        string
		name, version, confidence string
	}{
		{"PHP", "PHP", "", ""},
		{`PHP\;confidence:75`, "PHP", "", "75"},
		{`Magento\;version:2`, "Magento", "2", ""},
		{`Foo\;version:3\;confidence:50`, "Foo", "3", "50"},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		name, version, confidence := SplitMarkers(tc.in)
		if name != tc.name || version != tc.version || confidence != tc.confidence {
			t.Errorf("SplitMarkers(%q) = (%q,%q,%q), want (%q,%q,%q)",
				tc.in, name, version, confidence, tc.name, tc.version, tc.confidence)
		}
	}
}

// TestImpliesStripsMarkers pins the fix for technologies being reported with a
// marker glued to their name. The live database ships `PHP\;confidence:75`, and
// AddTechno used to take that whole string as the technology's name.
func TestImpliesStripsMarkers(t *testing.T) {
	db := map[string]interface{}{
		"HHVM": map[string]interface{}{
			"implies": `PHP\;confidence:75`,
		},
		"GoMage": map[string]interface{}{
			"implies": []interface{}{`Magento\;version:2`, "PHP"},
		},
		"PHP":     map[string]interface{}{"cpe": "cpe:2.3:a:php:php"},
		"Magento": map[string]interface{}{},
	}

	got := CheckRequired("HHVM", db, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 implied techno, got %v", names(got))
	}
	if got[0].Name != "PHP" {
		t.Errorf("implied name = %q, want %q (marker not stripped)", got[0].Name, "PHP")
	}
	if got[0].Confidence != "75" {
		t.Errorf("implied confidence = %q, want %q", got[0].Confidence, "75")
	}
	if got[0].Cpe == "" {
		t.Errorf("cpe not resolved: the lookup must use the cleaned name")
	}

	got = CheckRequired("GoMage", db, nil)
	if want := []string{"Magento", "PHP"}; !reflect.DeepEqual(names(got), want) {
		t.Errorf("implied names = %v, want %v", names(got), want)
	}
	if got[0].Version != "2" {
		t.Errorf("Magento version = %q, want %q", got[0].Version, "2")
	}
}

// TestRequiresGateSeesCleanedImpliesName covers the knock-on effect: a requires
// edge can only ever name the clean technology, so a marker left on an implied
// name silently broke the gate too.
func TestRequiresGateSeesCleanedImpliesName(t *testing.T) {
	db := map[string]interface{}{
		"HHVM":      map[string]interface{}{"implies": `PHP\;confidence:75`},
		"PHP":       map[string]interface{}{},
		"SomeAddon": map[string]interface{}{"requires": "PHP"},
	}
	detected := []structure.Technologie{{Name: "HHVM"}, {Name: "SomeAddon"}}
	detected = CheckRequired("HHVM", db, detected)

	kept := names(FilterRequired(DedupTechno(detected), db))
	for _, want := range []string{"HHVM", "PHP", "SomeAddon"} {
		found := false
		for _, k := range kept {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q was dropped; kept = %v", want, kept)
		}
	}
}

// TestDedupTechnoIsOrderIndependent pins the determinism fix: Run() iterates the
// database with a Go map range, so detections arrive in a random order on every
// run. Merging must not depend on it.
func TestDedupTechnoIsOrderIndependent(t *testing.T) {
	forward := []structure.Technologie{
		{Name: "Bootstrap", Version: "3.4"},
		{Name: "Bootstrap", Version: "3.4.1", Cpe: "cpe:boot"},
		{Name: "Bootstrap", Confidence: "50"},
	}
	reverse := []structure.Technologie{
		{Name: "Bootstrap", Confidence: "50"},
		{Name: "Bootstrap", Version: "3.4.1", Cpe: "cpe:boot"},
		{Name: "Bootstrap", Version: "3.4"},
	}

	a, b := DedupTechno(forward), DedupTechno(reverse)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("dedup depends on input order:\n forward = %+v\n reverse = %+v", a, b)
	}
	if len(a) != 1 {
		t.Fatalf("expected 1 merged entry, got %+v", a)
	}
	if a[0].Version != "3.4.1" {
		t.Errorf("version = %q, want the most specific %q", a[0].Version, "3.4.1")
	}
	if a[0].Confidence != "50" {
		t.Errorf("confidence = %q, want it merged in", a[0].Confidence)
	}
	if a[0].Cpe != "cpe:boot" {
		t.Errorf("cpe = %q, want it merged in", a[0].Cpe)
	}
}

// TestFilterExcluded pins the newly-honoured "excludes" edge: 43 technologies in
// the live database declare one and none of them were applied, so mutually
// exclusive pairs were both reported.
func TestFilterExcluded(t *testing.T) {
	db := map[string]interface{}{
		"Apache HTTP Server": map[string]interface{}{"excludes": "Nginx"},
		"Nginx":              map[string]interface{}{},
		"jQuery":             map[string]interface{}{},
		"Zepto":              map[string]interface{}{"excludes": []interface{}{"jQuery"}},
	}

	got := names(FilterExcluded([]structure.Technologie{
		{Name: "Apache HTTP Server"}, {Name: "Nginx"}, {Name: "jQuery"},
	}, db))
	if want := []string{"Apache HTTP Server", "jQuery"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (Nginx must be excluded by Apache)", got, want)
	}

	got = names(FilterExcluded([]structure.Technologie{{Name: "Zepto"}, {Name: "jQuery"}}, db))
	if want := []string{"Zepto"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (array form of excludes)", got, want)
	}

	// Nothing excluded -> the slice is returned untouched.
	in := []structure.Technologie{{Name: "jQuery"}, {Name: "Nginx"}}
	if got := names(FilterExcluded(in, db)); !reflect.DeepEqual(got, []string{"jQuery", "Nginx"}) {
		t.Errorf("got %v, want both kept", got)
	}

	// An unknown technology must not panic or drop anything.
	if got := names(FilterExcluded([]structure.Technologie{{Name: "Ghost"}}, db)); len(got) != 1 {
		t.Errorf("unknown technology was dropped: %v", got)
	}
}

// TestFilterExcludedKeepsMutualPairs pins the mutual-exclusion rule. The live
// database ships three pairs that exclude each other (Angular/AngularJS,
// HTTP/2/SPDY, Lodash/Underscore.js); applying both directions would delete
// both, reporting neither instead of resolving the conflict.
func TestFilterExcludedKeepsMutualPairs(t *testing.T) {
	db := map[string]interface{}{
		"Angular":       map[string]interface{}{"excludes": "AngularJS"},
		"AngularJS":     map[string]interface{}{"excludes": "Angular"},
		"Lodash":        map[string]interface{}{"excludes": []interface{}{"Underscore.js"}},
		"Underscore.js": map[string]interface{}{"excludes": []interface{}{"Lodash"}},
		"HTTP/3":        map[string]interface{}{"excludes": "HTTP/2"},
		"HTTP/2":        map[string]interface{}{},
	}

	got := names(FilterExcluded([]structure.Technologie{{Name: "Angular"}, {Name: "AngularJS"}}, db))
	if !reflect.DeepEqual(got, []string{"Angular", "AngularJS"}) {
		t.Errorf("mutual pair annihilated: got %v, want both kept", got)
	}

	got = names(FilterExcluded([]structure.Technologie{{Name: "Lodash"}, {Name: "Underscore.js"}}, db))
	if len(got) != 2 {
		t.Errorf("mutual array-form pair annihilated: got %v", got)
	}

	// One-way exclusion still applies.
	got = names(FilterExcluded([]structure.Technologie{{Name: "HTTP/3"}, {Name: "HTTP/2"}}, db))
	if !reflect.DeepEqual(got, []string{"HTTP/3"}) {
		t.Errorf("one-way exclusion broken: got %v, want [HTTP/3]", got)
	}
}

// TestNamesOfHandlesEveryShape guards the shared normaliser against the three
// JSON shapes the database actually uses.
func TestNamesOfHandlesEveryShape(t *testing.T) {
	if got := namesOf("A"); !reflect.DeepEqual(got, []string{"A"}) {
		t.Errorf("string form: %v", got)
	}
	if got := namesOf([]interface{}{"A", `B\;version:1`, 42}); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Errorf("array form: %v (non-strings must be skipped)", got)
	}
	if got := namesOf(map[string]interface{}{"A": nil}); !reflect.DeepEqual(got, []string{"A"}) {
		t.Errorf("object form: %v", got)
	}
	if got := namesOf(nil); got != nil {
		t.Errorf("nil form: %v", got)
	}
}
