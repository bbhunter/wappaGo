package analyze

import (
	"fmt"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze)analyze_html_main(technoName string,key string){
	if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
		a.analyze_html(technoName, a.ResultGlobal[technoName].(map[string]interface{})[key])
	} else {
		for _, htmlRegex := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
			a.analyze_html(technoName,htmlRegex)
		}
	}
}

func (a *Analyze) analyze_html(technoName string,regexStr interface{}) {
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	re, ok := compileCI(regex[0])
	if ok && re.MatchString(a.Body) {
		technoTemp := a.NewTechno(technoName)
		regexGroup := re.FindAllStringSubmatch(a.Body, -1)
		technoTemp.Version = versionFromMarker(regex, regexGroup)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}