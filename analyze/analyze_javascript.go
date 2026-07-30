package analyze

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/chromedp/chromedp"
)

func (a *Analyze) analyze_js_main(technoName string, key string) {
	if a.Ctx == nil {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	jsSpecs, ok := entry[key].(map[string]interface{})
	if !ok {
		return
	}
	for js, spec := range jsSpecs {
		if spec != "" { // the property must exist AND match a regex
			a.analyze_js_valued(fmt.Sprintf("%v", spec), js, technoName)
		} else { // the property only has to exist
			a.analyze_js_exist(js, technoName)
		}
	}
}

func (a *Analyze) analyze_js_valued(regexStr string, js string, technoName string) {
	regex := strings.Split(regexStr, "\\;")
	var res interface{}

	if regex[0] == "" {
		chromedp.Evaluate("(()=>{return (typeof "+js+" !== 'undefined' ? true : false)})()", &res).Do(a.Ctx)
	} else {
		// Read the requested capture group inside the page.
		//
		// The old expression was `<js>.match(/<re>/gm)[0]`, wrong three ways:
		// the `g` flag makes String.match return whole matches with no capture
		// groups, so `\;version:\1` could never work and the reported "version"
		// was the entire match ("Meteor.release=1.2" instead of "1.2");
		// indexing [0] throws when match returns null, and that error was
		// discarded; and an unescaped "/" in the pattern closed the regex
		// literal early, producing a SyntaxError for 31 live patterns. Building
		// the RegExp from a properly quoted string literal avoids all three.
		group := versionGroupIndex(regex)
		expr := "(()=>{try{var m=String(" + js + ").match(new RegExp(" + jsStringLiteral(regex[0]) + ",'m'));" +
			"if(!m)return null;var g=m[" + strconv.Itoa(group) + "];return g!==undefined?g:m[0]}catch(e){return null}})()"
		chromedp.Evaluate(expr, &res).Do(a.Ctx)
	}

	if res == nil || res == false {
		return
	}

	technoTemp := a.NewTechno(technoName)
	for _, marker := range regex[1:] {
		switch {
		case strings.HasPrefix(marker, "confidence:"):
			technoTemp.Confidence = strings.TrimPrefix(marker, "confidence:")
		case strings.HasPrefix(marker, "version:"):
			// res already is the capture group the marker asked for.
			if s, ok := res.(string); ok {
				technoTemp.Version = s
			} else if res != true {
				technoTemp.Version = fmt.Sprintf("%v", res)
			}
		}
	}
	a.Technos = append(a.Technos, technoTemp)
	a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
}

// versionGroupIndex returns the capture-group number a "\;version:\N" marker
// refers to, defaulting to 0 (the whole match).
func versionGroupIndex(regex []string) int {
	for _, marker := range regex[1:] {
		if !strings.HasPrefix(marker, "version:") {
			continue
		}
		spec := strings.TrimPrefix(marker, "version:")
		i := strings.Index(spec, "\\")
		if i < 0 {
			continue
		}
		digits := spec[i+1:]
		end := 0
		for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
			end++
		}
		if n, err := strconv.Atoi(digits[:end]); err == nil {
			return n
		}
	}
	return 0
}

// jsStringLiteral renders s as a JavaScript string literal so a pattern
// containing quotes, backslashes or newlines cannot break out of the expression
// it is embedded in.
func jsStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case ' ':
			b.WriteString(` `)
		case ' ':
			b.WriteString(` `)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (a *Analyze) analyze_js_exist(js string, technoName string) {
	var res interface{}
	chromedp.Evaluate("(()=>{ return (typeof "+js+" !== 'undefined' ? true : false)})()", &res).Do(a.Ctx)
	if res == true {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}
