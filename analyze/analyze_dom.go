package analyze

import (
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

// analyze_dom_main matches the fingerprint's "dom" family. The value is either
// a selector (string), a list of selectors, or a map of selector -> spec where
// the spec describes an attribute, a property, or the element's text.
func (a *Analyze) analyze_dom_main(technoName string, key string, doc *goquery.Document) {
	if doc == nil {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}

	switch spec := entry[key].(type) {
	case string:
		a.domSelectorPresent(technoName, spec, doc)

	case []interface{}:
		for _, selector := range spec {
			if s, ok := selector.(string); ok {
				a.domSelectorPresent(technoName, s, doc)
			}
		}

	case map[string]interface{}:
		for domKey, domArray := range spec {
			domSpec, ok := domArray.(map[string]interface{})
			if !ok {
				continue
			}
			for domKeyElement, domElement := range domSpec {
				switch element := domElement.(type) {
				case string:
					// Match the selected element's own text. This used to
					// re-scan the ENTIRE page body once per matched element, so
					// a bare "div" selector turned a single fingerprint into
					// thousands of full-document regex scans (~10 s on a normal
					// page).
					doc.Find(domKey).EachWithBreak(func(i int, s *goquery.Selection) bool {
						return !a.analyze_dom_valued(technoName, element, s)
					})
				case map[string]interface{}:
					for domKeyElement2, domElement2 := range element {
						if domKeyElement == "attributes" {
							doc.Find(domKey).EachWithBreak(func(i int, s *goquery.Selection) bool {
								return !a.analyze_dom_attribute(technoName, domKeyElement2, domElement2, s)
							})
						} else {
							a.analyze_dom_exist(technoName, domKeyElement2, domKey)
						}
					}
				}
			}
		}
	}
}

// domSelectorPresent records the technology when the selector matches anything.
func (a *Analyze) domSelectorPresent(technoName string, selector string, doc *goquery.Document) {
	if doc.Find(selector).Length() == 0 {
		return
	}
	technoTemp := a.NewTechno(technoName)
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
}

func (a *Analyze) analyze_dom_exist(technoName string, domKeyElement2 string, domKey string) {
	var res interface{}
	if a.Ctx == nil {
		return
	}
	chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(a.Ctx)
	if res == true {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}

func (a *Analyze) analyze_dom_attribute(technoName string, attrName string, pattern interface{}, s *goquery.Selection) bool {
	if attrName == "" {
		return false
	}
	attrValue, exists := s.Attr(attrName)
	if !exists || attrValue == "" {
		return false
	}
	patternStr, ok := pattern.(string)
	if !ok {
		return false
	}
	// An empty pattern means the attribute only has to be present.
	if patternStr == "" {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		return true
	}
	regex := strings.Split(patternStr, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return false
	}
	groups := re.FindStringSubmatch(attrValue)
	if groups == nil {
		return false
	}
	technoTemp := a.NewTechno(technoName)
	technoTemp.Version = versionFromMarker(regex, [][]string{groups})
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	return true
}

// analyze_dom_valued matches a dom spec's text/value pattern against the
// selected element.
func (a *Analyze) analyze_dom_valued(technoName string, pattern string, s *goquery.Selection) bool {
	if pattern == "" {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		return true
	}
	regex := strings.Split(pattern, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return false
	}
	groups := re.FindStringSubmatch(s.Text())
	if groups == nil {
		return false
	}
	technoTemp := a.NewTechno(technoName)
	technoTemp.Version = versionFromMarker(regex, [][]string{groups})
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	return true
}
