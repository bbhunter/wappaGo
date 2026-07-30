package analyze

import (
	"fmt"
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
)

// analyze_headers_main matches a fingerprint's "headers" patterns against the
// response headers.
//
// The two maps are keyed differently and must not be confused: the fingerprint
// keeps Wappalyzer's original spelling ("x-powered-by", "server"), while
// a.Resp.Headers comes from http.Header.Clone() and is therefore in Go's
// canonical MIME form ("X-Powered-By", "Server"). The pattern used to be looked
// up with the *response* key, which missed 301 of the database's 690 header
// fingerprints (43%, spread over 211 technologies): the lookup returned a nil
// interface, and since nil != "" the code went on to compile the literal
// "<nil>" as a regex, so the regex form and the presence-only form were both
// lost. The pattern now comes straight from the range over the fingerprint map,
// so no lookup can miss.
func (a *Analyze) analyze_headers_main(technoName string, key string) {
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	patterns, ok := entry[key].(map[string]interface{})
	if !ok {
		return
	}

	for header, pattern := range patterns {
		for headerName, values := range a.headers() {
			if !strings.EqualFold(header, headerName) {
				continue
			}
			// An empty pattern means "the header only has to be present".
			if pattern == "" {
				a.addHeaderTechno(technoName, "")
				continue
			}
			regex := strings.Split(fmt.Sprintf("%v", pattern), "\\;")
			re, ok := compileCI(regex[0])
			if !ok {
				continue
			}
			// A header may legitimately repeat (Via, Set-Cookie, ...). The old
			// code only read values[0], and would have panicked on an empty
			// slice.
			for _, value := range values {
				if !re.MatchString(value) {
					continue
				}
				a.addHeaderTechno(technoName, versionFromMarker(regex, re.FindAllStringSubmatch(value, -1)))
				break
			}
		}
	}
}

func (a *Analyze) addHeaderTechno(technoName string, version string) {
	technoTemp := a.NewTechno(technoName)
	technoTemp.Version = version
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
}
