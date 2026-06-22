package analyze

import (
	"fmt"
	"strings"
	"github.com/EasyRecon/wappaGo/technologies"
)


func (a *Analyze)analyze_headers_main(technoName string,key string){
	for header, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		for headerName, _ := range a.Resp.Headers {
			if strings.ToLower(header) == strings.ToLower(headerName) {
				//headerValue := a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[header]
				if a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName] != "" {
					regex := strings.Split(fmt.Sprintf("%v", a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[headerName]), "\\;")
					re, ok := compileCI(regex[0])
					if ok && re.MatchString(a.Resp.Headers[headerName][0]) {
						technoTemp := a.NewTechno(technoName)
						regexGroup := re.FindAllStringSubmatch(a.Resp.Headers[headerName][0], -1)
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
	}
}
