package analyze

import (
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
)

// analyze_meta_main matches the fingerprint's "meta" patterns against the
// document's <meta> tags.
//
// Only meta[name=...] used to be searched. Wappalyzer keys its meta
// fingerprints on either attribute, and every Open Graph / Twitter Card style
// entry (og:*, twitter:*, fb:*) is published as meta[property=...], so those
// fingerprints could never match.
func (a *Analyze) analyze_meta_main(technoName string, key string, doc *goquery.Document) {
	if doc == nil {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	metas, ok := entry[key].(map[string]interface{})
	if !ok {
		return
	}

	for metaKey, metaProperties := range metas {
		selector := `meta[name="` + metaKey + `" i], meta[property="` + metaKey + `" i]`
		patterns := namesOfValue(metaProperties)
		if len(patterns) == 0 {
			continue
		}
		doc.Find(selector).EachWithBreak(func(i int, s *goquery.Selection) bool {
			for _, pattern := range patterns {
				if a.analyze_meta(s, pattern, technoName) {
					return false // matched; stop scanning further meta tags
				}
			}
			return true
		})
	}
}

func (a *Analyze) analyze_meta(s *goquery.Selection, pattern string, technoName string) bool {
	metaValue, _ := s.Attr("content")
	if metaValue == "" {
		return false
	}
	regex := strings.Split(pattern, "\\;")
	re, ok := compileCI(regex[0])
	if !ok {
		return false
	}
	groups := re.FindStringSubmatch(metaValue)
	if groups == nil {
		return false
	}
	technoTemp := a.NewTechno(technoName)
	technoTemp.Version = versionFromMarker(regex, [][]string{groups})
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	return true
}
