package analyze


import (
	"fmt"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)



func (a *Analyze)analyze_dom_main(technoName string,key string, doc *goquery.Document){
	if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
		doc.Find(a.ResultGlobal[technoName].(map[string]interface{})[key].(string)).Each(func(i int, s *goquery.Selection) {
			technoTemp := a.NewTechno(technoName)
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		})
	} else if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "map[string]interface {}" {
		for domKey, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
			for domKeyElement, domElement := range domArray.(map[string]interface{}) {
				if fmt.Sprintf("%T", domElement) == "string" {
					doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
						a.analyze_dom_valued(technoName,domElement)
					})
				} else if fmt.Sprintf("%T", domElement) == "map[string]interface {}" {
					for domKeyElement2, domElement2 := range domElement.(map[string]interface{}) {
						if domKeyElement == "attributes" {
							doc.Find(domKey).Each(func(i int, s *goquery.Selection) {
								a.analyze_dom_attribute(technoName,domKeyElement2,domElement2,s)
							})
						} else {
							a.analyze_dom_exist(technoName,domKeyElement2,domKey)
						}
					}
				}
			}
		}
	} else {
		for _, domArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
			doc.Find(domArray.(string)).Each(func(i int, s *goquery.Selection) {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			})
		}
	}			
}
func  (a *Analyze) analyze_dom_exist(technoName string,domKeyElement2 string,domKey string ){
	var res interface{}
	chromedp.Evaluate("(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()", &res).Do(a.Ctx)
	//fmt.Println(res, "(()=>{a=false;document.querySelectorAll('"+domKey+"').forEach(element=>{if(element."+domKeyElement2+"!=undefined){a=true}});return a})()")
	if res == true {
		technoTemp := a.NewTechno(technoName)												
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}


func  (a *Analyze) analyze_dom_attribute(technoName string,domKeyElement2 string,domElement2 interface{},s *goquery.Selection){
	dommAttr, _ := s.Attr(domKeyElement2)
	if dommAttr != "" {
		if domKeyElement2 != "" {
			regex := strings.Split(domElement2.(string), "\\;")
			re, ok := compileCI(regex[0])
			if ok && re.MatchString(dommAttr) {
				technoTemp := a.NewTechno(technoName)
				regexGroup := re.FindAllStringSubmatch(dommAttr, -1)
				technoTemp.Version = versionFromMarker(regex, regexGroup)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		} else {
			technoTemp := a.NewTechno(technoName)
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		}
	}
}


func  (a *Analyze) analyze_dom_valued(technoName string,domElement interface{}){
	if domElement == "" {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	} else {
		regex := strings.Split(domElement.(string), "\\;")
		re, ok := compileCI(regex[0])
		if ok && re.MatchString(a.Body) {
			//fmt.Println(technoName)
			technoTemp := a.NewTechno(technoName)
			regexGroup := re.FindAllStringSubmatch(a.Body, -1)
			technoTemp.Version = versionFromMarker(regex, regexGroup)
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
		}
	}
}
