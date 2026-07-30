package analyze

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// regexCache memoises the compiled, case-insensitive form of every Wappalyzer
// pattern encountered during a run. The fingerprint database is iterated once
// per analysed page, so without this cache each pattern is recompiled on every
// page (and, in the original code, twice per match: once for MatchString and
// once for MustCompile). Compilation therefore dropped from O(pages*patterns)
// to O(patterns) total.
var (
	regexCacheMu sync.RWMutex
	regexCache   = make(map[string]*regexp.Regexp)
)

// compileCI returns the cached, case-insensitive *regexp.Regexp for pattern.
//
// Each distinct pattern is compiled at most once for the whole process. If the
// pattern is not valid RE2 — Wappalyzer occasionally ships PCRE-only constructs
// such as look-around that Go's regexp engine rejects — compileCI caches the
// failure and returns (nil, false) so the caller skips the pattern instead of
// panicking (the original code used regexp.MustCompile, which crashed the
// whole scan on the first such pattern).
func compileCI(pattern string) (*regexp.Regexp, bool) {
	key := "(?i)" + pattern

	regexCacheMu.RLock()
	re, cached := regexCache[key]
	regexCacheMu.RUnlock()
	if cached {
		return re, re != nil
	}

	re, err := regexp.Compile(key)
	if err != nil {
		re = nil // remember the failure so the bad pattern is never retried
	}
	regexCacheMu.Lock()
	regexCache[key] = re
	regexCacheMu.Unlock()
	return re, re != nil
}

// versionFromMarker extracts a technology version from regex submatch groups
// using a Wappalyzer "\;version:\N" marker. parts is the pattern string split
// on "\;" (so parts[0] is the regex and parts[1], if present, is the marker).
//
// It reproduces the original behaviour exactly but is bounds-checked: an
// out-of-range capture group or a missing/short marker yields "" instead of
// panicking with an index-out-of-range (which previously aborted the scan).
func versionFromMarker(parts []string, groups [][]string) string {
	if len(parts) <= 1 || !strings.HasPrefix(parts[1], "version") {
		return ""
	}
	versionGrp := strings.Split(parts[1], "\\")
	if len(versionGrp) <= 1 {
		return ""
	}
	offset, err := strconv.Atoi(versionGrp[1])
	if err != nil {
		return ""
	}
	if len(groups) == 0 || offset < 0 || offset >= len(groups[0]) {
		return ""
	}
	return groups[0][offset]
}
