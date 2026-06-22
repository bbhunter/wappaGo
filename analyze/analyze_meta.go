package analyze

import (
	"fmt"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"

)


func (a *Analyze)analyze_meta_main(technoName string,key string,doc *goquery.Document){

	for metaKey, metaProperties := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		doc.Find("meta[name=\"" + metaKey + "\" i]").Each(func(i int, s *goquery.Selection) {
			if fmt.Sprintf("%T", metaProperties) == "string" {
				a.analyze_meta(s,metaProperties,technoName)
			} else {
				for _, metaPropertiess := range metaProperties.([]interface{}) {
					a.analyze_meta(s,metaPropertiess,technoName)
				}
			}
		})
	}
}


func  (a *Analyze) analyze_meta(s *goquery.Selection,metaProperties interface{},technoName string){
	metaValue, _ := s.Attr("content")
	regex := strings.Split(fmt.Sprintf("%v", metaProperties), "\\;")
	re, ok := compileCI(regex[0])
	if ok && re.MatchString(metaValue) {
		technoTemp := a.NewTechno(technoName)
		regexGroup := re.FindAllStringSubmatch(metaValue, -1)
		technoTemp.Version = versionFromMarker(regex, regexGroup)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}