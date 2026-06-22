package analyze

import(
	"fmt"
	"github.com/EasyRecon/wappaGo/technologies"
)


func (a *Analyze)analyze_xhr_main(technoName string,key string){
	for _,url:=range a.XHRUrl {
		if fmt.Sprintf("%T", a.ResultGlobal[technoName].(map[string]interface{})[key]) == "string" {
			re, ok := compileCI(a.ResultGlobal[technoName].(map[string]interface{})[key].(string))
			if ok && re.MatchString(url) {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		} else {
			for _, XHRArray := range a.ResultGlobal[technoName].(map[string]interface{})[key].([]interface{}) {
				re, ok := compileCI(XHRArray.(string))
				if ok && re.MatchString(url) {
					technoTemp := a.NewTechno(technoName)
					a.Technos = append(a.Technos, technoTemp)
					a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
				}
			}
		}
	}
}