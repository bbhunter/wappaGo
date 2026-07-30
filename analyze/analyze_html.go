package analyze

import (
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
)

// analyze_html_main matches the "html" and "text" families.
//
// They are not the same haystack: "html" matches the raw markup, while "text"
// is meant to match the page's rendered text. Both used to run against the full
// markup, so a "text" pattern could match an attribute value, a URL or a
// comment and report a technology that is not visible on the page at all.
func (a *Analyze) analyze_html_main(technoName string, key string) {
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	haystack := a.Body
	if key == "text" {
		haystack = a.text()
	}
	if haystack == "" {
		return
	}
	for _, pattern := range namesOfValue(entry[key]) {
		a.analyze_html(technoName, pattern, haystack)
	}
}

// text returns the document's rendered text, computed once per page.
func (a *Analyze) text() string {
	if a.textCache == "" && a.Doc != nil {
		a.textCache = a.Doc.Text()
	}
	return a.textCache
}

func (a *Analyze) analyze_html(technoName string, regexStr string, haystack string) {
	regex := strings.Split(regexStr, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return
	}
	// FindStringSubmatch, not FindAllStringSubmatch: only the first match is
	// ever consumed, and scanning the whole body for every remaining match was
	// pure waste on large pages.
	groups := re.FindStringSubmatch(haystack)
	if groups == nil {
		return
	}
	technoTemp := a.NewTechno(technoName)
	technoTemp.Version = versionFromMarker(regex, [][]string{groups})
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
}
