package analyze

import (
	"fmt"
	"net/http"
	"strings"

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

// SetFinalHeaders records the response headers of the main document Chrome
// landed on, after any redirect. It is called from the same CDP listener
// goroutine as AddXHRUrl, so it shares the mutex.
//
// Only the first document response is kept: later ones are sub-frames.
func (a *Analyze) SetFinalHeaders(url string, headers map[string]interface{}) {
	if len(headers) == 0 {
		return
	}
	a.xhrMu.Lock()
	defer a.xhrMu.Unlock()
	if a.finalHeaders != nil {
		return
	}
	a.finalHeaders = make(map[string][]string, len(headers))
	for k, v := range headers {
		// CDP delivers header names as the server sent them; canonicalise so
		// the matcher and Go's own probe agree on spelling. Repeated headers
		// arrive as one newline-joined string, so split them back apart —
		// otherwise a "Via: 1.1 google\n1.1 varnish" pair is one opaque value.
		values := strings.Split(fmt.Sprintf("%v", v), "\n")
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		a.finalHeaders[http.CanonicalHeaderKey(k)] = values
	}
	a.finalURL = url
}

// headers returns the headers detection should run against: the union of what
// the raw probe saw and what Chrome saw on the final page, with Chrome winning
// on any header present in both.
//
// Neither source alone is sufficient. The probe stops at the 30x by default, so
// on a redirecting host its headers describe the redirector — that is why a
// http->https host reported no Server and no X-Powered-By. But Chrome consumes
// some headers before CDP reports them (Alt-Svc, which is the only signal for
// HTTP/3), so preferring Chrome outright loses those instead. Merging keeps both.
func (a *Analyze) headers() map[string][]string {
	a.xhrMu.Lock()
	final := a.finalHeaders
	a.xhrMu.Unlock()
	if len(final) == 0 {
		return a.Resp.Headers
	}
	merged := make(map[string][]string, len(final)+len(a.Resp.Headers))
	for k, v := range a.Resp.Headers {
		merged[http.CanonicalHeaderKey(k)] = v
	}
	for k, v := range final {
		merged[k] = v // already canonicalised by SetFinalHeaders
	}
	return merged
}

func (a *Analyze) analyze_xhr_main(technoName string, key string) {
	a.xhrMu.Lock()
	urls := make([]string, len(a.XHRUrl))
	copy(urls, a.XHRUrl)
	a.xhrMu.Unlock()
	if len(urls) == 0 {
		return
	}
	entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok {
		return
	}
	// Derive each pattern once instead of re-compiling it per observed URL.
	for _, pattern := range namesOfValue(entry[key]) {
		regex := strings.Split(pattern, "\\;")
		re, ok := compileCI(regex[0])
		if !ok {
			continue
		}
		for _, url := range urls {
			if !re.MatchString(url) {
				continue
			}
			technoTemp := a.NewTechno(technoName)
			technoTemp.Version = versionFromMarker(regex, re.FindAllStringSubmatch(url, -1))
			a.Technos = append(a.Technos, technoTemp)
			a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			break
		}
	}
}
