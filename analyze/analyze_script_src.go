package analyze

import (
	"fmt"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)

func (a *Analyze)analyze_scriptSrc_main(technoName string,key string){
	for _, scriptCrc := range a.SrcList {
		if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
			a.analyze_scriptSrc(technoName,a.ResultGlobal[technoName].(map[string]interface{})[key].(string),scriptCrc)
		} else {
			for _, scriptSrcArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
				finalRegex := strings.ReplaceAll(scriptSrcArray.(string), "/", "\\/")		
				a.analyze_scriptSrc(technoName,finalRegex,scriptCrc)
			}
		}
	}
}

func  (a *Analyze) analyze_scriptSrc(technoName string,regexStr string,scriptCrc string){
	regex := strings.Split(fmt.Sprintf("%v", regexStr), "\\;")
	re, ok := compileCI(regex[0])
	if ok && re.MatchString(scriptCrc) {
		technoTemp := a.NewTechno(technoName)
		regexGroup := re.FindAllStringSubmatch(scriptCrc, -1)
		technoTemp.Version = versionFromMarker(regex, regexGroup)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}