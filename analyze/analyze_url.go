package analyze

import (
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
)

// analyze_url_main matches the fingerprint's "url" patterns against the URL
// that was actually scanned.
//
// It used to run only when Hote.Location was non-empty — that field is set for
// a 301/302 and nothing else — and matched against the Location header rather
// than the page URL. So all 78 "url" fingerprints in the database were skipped
// for every host that did not redirect, and matched the wrong string for those
// that did. The redirect target is still considered when there is one, since
// that is where the browser ended up.
func (a *Analyze) analyze_url_main(technoName string, key string) {
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	targets := a.urlTargets()
	if len(targets) == 0 {
		return
	}
	switch v := entry[key].(type) {
	case string:
		a.analyze_url(technoName, v, targets)
	case []interface{}:
		for _, url := range v {
			if s, ok := url.(string); ok {
				a.analyze_url(technoName, s, targets)
			}
		}
	}
}

// urlTargets is the scanned URL plus the redirect target when they differ.
func (a *Analyze) urlTargets() []string {
	var out []string
	if a.Url != "" {
		out = append(out, a.Url)
	}
	if a.Hote.Location != "" && a.Hote.Location != a.Url {
		out = append(out, a.Hote.Location)
	}
	return out
}

func (a *Analyze) analyze_url(technoName string, regexStr string, targets []string) {
	// url patterns carry version/confidence markers like every other family.
	regex := strings.Split(regexStr, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return
	}
	for _, target := range targets {
		if !re.MatchString(target) {
			continue
		}
		technoTemp := a.NewTechno(technoName)
		technoTemp.Version = versionFromMarker(regex, re.FindAllStringSubmatch(target, -1))
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		return
	}
}
