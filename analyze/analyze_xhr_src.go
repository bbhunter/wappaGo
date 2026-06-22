package analyze

import(
	"fmt"
	"github.com/EasyRecon/wappaGo/technologies"
)


// AddXHRUrl records an XHR response URL. It is invoked from the chromedp
// ListenTarget callback, which runs on a separate goroutine concurrently with
// Run(), so writes to XHRUrl must be serialised.
func (a *Analyze) AddXHRUrl(u string) {
	a.xhrMu.Lock()
	a.XHRUrl = append(a.XHRUrl, u)
	a.xhrMu.Unlock()
}

func (a *Analyze)analyze_xhr_main(technoName string,key string){
	a.xhrMu.Lock()
	urls := make([]string, len(a.XHRUrl))
	copy(urls, a.XHRUrl)
	a.xhrMu.Unlock()
	for _,url:=range urls {
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