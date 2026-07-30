package analyze

import (
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
)

// analyze_scriptSrc_main matches the fingerprint's script-src patterns against
// every <script src> on the page.
//
// The loops used to be nested the other way round, with the page's src list on
// the outside, so the pattern list was re-split and re-looked-up once per
// script tag — 64k iterations and several MB of garbage on a page with 30
// scripts. Patterns depend only on the fingerprint, so they are derived once.
func (a *Analyze) analyze_scriptSrc_main(technoName string, key string) {
	if len(a.SrcList) == 0 {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	for _, pattern := range namesOfValue(entry[key]) {
		a.analyze_scriptSrc(technoName, pattern)
	}
}

func (a *Analyze) analyze_scriptSrc(technoName string, regexStr string) {
	regex := strings.Split(regexStr, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return
	}
	for _, scriptSrc := range a.SrcList {
		if !re.MatchString(scriptSrc) {
			continue
		}
		technoTemp := a.NewTechno(technoName)
		technoTemp.Version = versionFromMarker(regex, re.FindAllStringSubmatch(scriptSrc, -1))
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		return
	}
}
