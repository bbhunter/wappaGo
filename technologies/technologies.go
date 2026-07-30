package technologies

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"dario.cat/mergo"
	"github.com/EasyRecon/wappaGo/lib"
	"github.com/EasyRecon/wappaGo/structure"
)

func CheckRequired(technoName string, technoList map[string]interface{}, tech []structure.Technologie) []structure.Technologie {
	entry, ok := technoList[technoName].(map[string]interface{})
	if !ok {
		return tech
	}
	// Only "implies" adds technologies (X implies Y means Y is also present).
	// "requires" is a precondition, NOT an assertion: it is enforced after all
	// detection by FilterRequired, so it is intentionally ignored here.
	implies, ok := entry["implies"]
	if !ok {
		return tech
	}
	switch v := implies.(type) {
	case string:
		tech = AddTechno(v, tech, technoList)
	case []interface{}:
		for _, item := range v {
			if strItem, ok := item.(string); ok {
				tech = AddTechno(strItem, tech, technoList)
			}
		}
	case map[string]interface{}:
		for key := range v {
			tech = AddTechno(key, tech, technoList)
		}
	}
	return tech
}

// SplitMarkers separates a Wappalyzer value from its "\;version:" /
// "\;confidence:" markers and returns the bare value plus the two fields.
//
// Markers appear on implies edges too, not just on match patterns: the live
// database ships "PHP\;confidence:75" and "Magento\;version:2". Those used to
// be taken as technology names verbatim, so results carried entries literally
// called `PHP\;confidence:75` — which also broke the requires gate, since no
// requires edge can ever name that string.
func SplitMarkers(value string) (name string, version string, confidence string) {
	parts := strings.Split(value, "\\;")
	name = parts[0]
	for _, marker := range parts[1:] {
		switch {
		case strings.HasPrefix(marker, "version:"):
			version = strings.TrimPrefix(marker, "version:")
		case strings.HasPrefix(marker, "confidence:"):
			confidence = strings.TrimPrefix(marker, "confidence:")
		}
	}
	return name, version, confidence
}

// New builds a Technologie for name, copying the descriptive fields the
// fingerprint database carries for it.
//
// Every step is guarded: the technology may be absent from the database (an
// implied edge can point at one that is not shipped) or carry a non-string
// value, and asserting either used to panic.
func New(name string, technoList map[string]interface{}) structure.Technologie {
	techno := structure.Technologie{Name: name}
	entry, ok := technoList[name].(map[string]interface{})
	if !ok {
		return techno
	}
	if cpe, ok := entry["cpe"].(string); ok {
		techno.Cpe = cpe
	}
	if icon, ok := entry["icon"].(string); ok {
		techno.Icon = icon
	}
	return techno
}

func AddTechno(name string, tech []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	cleanName, version, confidence := SplitMarkers(name)
	technoTemp := New(cleanName, technoList)
	technoTemp.Version = version
	technoTemp.Confidence = confidence
	tech = append(tech, technoTemp)
	return tech
}

// shards are the 27 files the fingerprint database is split into.
var shards = []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}

// maxShardBytes caps a single shard. The largest real shard is under 400 KB;
// this only exists so a hostile or broken origin cannot stream forever into
// memory (http.Get has no size limit of its own).
const maxShardBytes = 32 << 20

// downloadClient bounds the whole fetch. http.DefaultClient has no timeout at
// all, so a slow-loris origin used to hang the tool before the scan even began.
var downloadClient = &http.Client{Timeout: 60 * time.Second}

// Load downloads the fingerprint database, parses it into memory, and deletes
// the on-disk copy before returning.
//
// The shards exist on disk only for the few milliseconds between download and
// parse: nothing reads them afterwards, so keeping the temp directory alive for
// the whole scan (as the previous `defer os.RemoveAll(folder)` in main and
// wrapper did) served no purpose and leaked the directory outright whenever the
// download failed early.
func Load() (map[string]interface{}, error) {
	folder, err := DownloadTechnologies()
	// DownloadTechnologies may return a usable folder alongside an error; clean
	// it up either way.
	if folder != "" {
		defer os.RemoveAll(folder)
	}
	if err != nil {
		return nil, err
	}
	result := LoadTechnologiesFiles(folder)
	if len(result) == 0 {
		return nil, fmt.Errorf("fingerprint database is empty (nothing usable downloaded from %s)", structure.TechnologiesRoot)
	}
	return result, nil
}

func DownloadTechnologies() (string, error) {
	// Create the working dir under the system temp location, not the current
	// working directory, so the downloaded fingerprint shards never land in
	// (and get accidentally committed to) the repository.
	folder, err := os.MkdirTemp("", "wappago-")
	if err != nil {
		return "", err
	}
	for _, f := range shards {
		url := fmt.Sprintf("%v/%v.json", structure.TechnologiesRoot, f)
		resp, err := downloadClient.Get(url)
		if err != nil {
			// Return the folder so the caller can still clean it up.
			return folder, err
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxShardBytes))
		resp.Body.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %v.json: read error: %v\n", f, err)
			continue
		}
		// A 404/HTML error page must not be written as fingerprint data and
		// then merged silently — skip any shard that didn't return 200 OK.
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "skip %v.json: unexpected status %d\n", f, resp.StatusCode)
			continue
		}
		file, err := os.OpenFile(
			folder+"/"+f+".json",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %v.json: %v\n", f, err)
			continue
		}
		file.Write(body)
		file.Close()

	}
	return folder, nil
}

func LoadTechnologiesFiles(folder string) map[string]interface{} {
	resultGlobal := make(map[string]interface{})
	for _, s := range lib.Find(folder, ".json") {
		result, err := loadTechnologyFile(s)
		if err != nil {
			// A corrupt or unreadable shard is skipped (and reported) instead
			// of being merged as empty/garbage and silently degrading detection.
			fmt.Fprintf(os.Stderr, "skip %v: %v\n", s, err)
			continue
		}
		if err := mergo.Merge(&resultGlobal, result); err != nil {
			fmt.Fprintf(os.Stderr, "merge %v: %v\n", s, err)
		}
	}
	return resultGlobal
}

// loadTechnologyFile reads and parses a single fingerprint shard. The file is
// fully read and closed before returning, so descriptors are released per
// iteration rather than piling up until LoadTechnologiesFiles returns.
func loadTechnologyFile(path string) (map[string]interface{}, error) {
	byteValue, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(byteValue, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// DedupTechno collapses repeated detections of the same technology into one
// entry, merging the fields each detection contributed.
//
// The merge must not depend on the order detections arrive in. Run() iterates
// the fingerprint database with a Go map range, so the order in which signal
// families (html, scriptSrc, js, meta, …) fire is randomised on every run. The
// old code kept whichever non-empty Version landed first, so 86 technologies in
// the live database — anything carrying a version marker in two families, e.g.
// Bootstrap or AngularJS — reported a version that changed between runs on
// byte-identical input. Picking the most specific value instead makes the
// output reproducible.
func DedupTechno(technologies []structure.Technologie) []structure.Technologie {
	var output []structure.Technologie
	index := make(map[string]int, len(technologies))
	for _, tech := range technologies {
		i, seen := index[tech.Name]
		if !seen {
			index[tech.Name] = len(output)
			output = append(output, tech)
			continue
		}
		output[i].Version = moreSpecific(output[i].Version, tech.Version)
		output[i].Confidence = moreSpecific(output[i].Confidence, tech.Confidence)
		if output[i].Cpe == "" {
			output[i].Cpe = tech.Cpe
		}
		if output[i].Icon == "" {
			output[i].Icon = tech.Icon
		}
	}
	return output
}

// moreSpecific picks deterministically between two candidate values: the longer
// one wins ("1.21.0" over "1.21"), ties broken lexicographically so the result
// never depends on argument order.
func moreSpecific(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case len(a) != len(b):
		if len(a) > len(b) {
			return a
		}
		return b
	case a >= b:
		return a
	default:
		return b
	}
}

// FilterExcluded applies Wappalyzer "excludes": when a detected technology
// declares that another cannot coexist with it, the excluded one is dropped.
//
// 43 technologies in the live database carry an excludes edge and none of them
// were honoured, so mutually exclusive pairs (a CMS and the platform it is
// commonly confused with, competing analytics scripts) were both reported.
// Exclusion is evaluated in one pass against the originally detected set, so the
// result never depends on iteration order.
//
// Mutually exclusive pairs are left alone. The database ships three
// (Angular/AngularJS, HTTP/2/SPDY, Lodash/Underscore.js); applying both
// directions would delete both technologies, which throws away evidence instead
// of resolving it. When the data contradicts itself, keeping both and letting the
// operator judge beats silently reporting neither.
func FilterExcluded(techs []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	if len(techs) == 0 {
		return techs
	}
	excludes := func(name string) []string {
		entry, ok := technoList[name].(map[string]interface{})
		if !ok {
			return nil
		}
		return namesOf(entry["excludes"])
	}

	excluded := make(map[string]bool)
	for _, t := range techs {
		for _, name := range excludes(t.Name) {
			if lib.Contains(excludes(name), t.Name) {
				continue // mutual: not a resolvable conflict
			}
			excluded[name] = true
		}
	}
	if len(excluded) == 0 {
		return techs
	}
	kept := techs[:0:0]
	for _, t := range techs {
		if !excluded[t.Name] {
			kept = append(kept, t)
		}
	}
	return kept
}

// FilterRequired enforces Wappalyzer "requires" preconditions: a detected
// technology is kept only if every technology it requires is also present in
// the result set. Unlike "implies" (which asserts a dependency), "requires"
// gates the detection itself, so this drops false positives such as a plugin
// reported without the platform it depends on.
//
// It iterates to a fixpoint so a chain (A requires B requires C) collapses
// correctly when the root is missing. "requiresCategory" is not enforced
// because categories are not loaded.
func FilterRequired(techs []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	for {
		detected := make(map[string]bool, len(techs))
		for _, t := range techs {
			detected[t.Name] = true
		}
		kept := techs[:0:0]
		for _, t := range techs {
			if requiresSatisfied(t.Name, technoList, detected) {
				kept = append(kept, t)
			}
		}
		if len(kept) == len(techs) {
			return kept
		}
		techs = kept
	}
}

func requiresSatisfied(name string, technoList map[string]interface{}, detected map[string]bool) bool {
	entry, ok := technoList[name].(map[string]interface{})
	if !ok {
		return true
	}
	requires, ok := entry["requires"]
	if !ok {
		return true
	}
	for _, req := range namesOf(requires) {
		if !detected[req] {
			return false
		}
	}
	return true
}

// namesOf normalises a Wappalyzer cross-reference value ("requires",
// "excludes", "implies") into a list of technology names. The value may be a
// bare string, an array, or an object keyed by name, and entries may carry
// "\;version:"/"\;confidence:" markers that are not part of the name.
func namesOf(value interface{}) []string {
	switch v := value.(type) {
	case string:
		name, _, _ := SplitMarkers(v)
		return []string{name}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				name, _, _ := SplitMarkers(s)
				out = append(out, name)
			}
		}
		return out
	case map[string]interface{}:
		var out []string
		for k := range v {
			name, _, _ := SplitMarkers(k)
			out = append(out, name)
		}
		return out
	}
	return nil
}
