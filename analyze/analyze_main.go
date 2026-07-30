package analyze

import (
	"context"
	"github.com/EasyRecon/wappaGo/lib"
	structure "github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	cdp "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/projectdiscovery/retryabledns"
	"strings"
	"sync"
)

type Analyze struct {
	ResultGlobal map[string]interface{}
	Resp         structure.Response
	SrcList      []string
	Ctx          context.Context
	Hote         structure.Host
	CookiesList  []*network.Cookie
	Node         *cdp.Node
	Body         string
	Doc          *goquery.Document
	textCache    string // rendered document text, computed on first "text" match
	Technos      []structure.Technologie
	// Url is the URL that was scanned. The "url" matchers need it; they used to
	// fall back to Hote.Location, which is only ever set on a redirect.
	Url        string
	DnsData    *retryabledns.DNSData
	CertVhost  []string
	CertIssuer string
	XHRUrl     []string
	// finalHeaders / finalURL are the main document's response as Chrome saw
	// it, after redirects. Written from the CDP listener goroutine, so they are
	// guarded by xhrMu like XHRUrl.
	finalHeaders map[string][]string
	finalURL     string
	xhrMu        sync.Mutex
}

func (a *Analyze) Run() []structure.Technologie {
	// Reuse the document already parsed by the caller (launchChrome) when
	// available; only parse here as a fallback (e.g. unit tests).
	if a.Doc == nil {
		// Store it back, not just locally: the text() matcher and any later
		// caller need the same document.
		a.Doc, _ = goquery.NewDocumentFromReader(strings.NewReader(a.Body))
	}
	doc := a.Doc

	for technoName := range a.ResultGlobal {
		// The database is third-party JSON fetched at startup. A technology
		// whose value is not an object used to panic right here, taking down the
		// whole target (and, before the per-target recover(), the process).
		entry, ok := a.ResultGlobal[technoName].(map[string]interface{})
		if !ok {
			continue
		}
		for key := range entry {
			if lib.Contains(structure.InterrestingKey, key) {
				if key == "js" {
					a.analyze_js_main(technoName, key)
				}
				if key == "headers" {
					a.analyze_headers_main(technoName, key)
				}
				if key == "dom" {
					a.analyze_dom_main(technoName, key, doc)
				}
				if key == "cookies" && len(a.CookiesList) > 0 {
					a.analyze_cookies_main(technoName, key)
				}
				if key == "scriptSrc" {
					a.analyze_scriptSrc_main(technoName, key)
				}
				if key == "url" {
					a.analyze_url_main(technoName, key)
				}
				if key == "html" || key == "text" {
					a.analyze_html_main(technoName, key)
				}
				if key == "meta" {
					a.analyze_meta_main(technoName, key, doc)
				}
				if key == "dns" {
					a.analyze_dns_main(technoName, key)
				}
				if key == "certIssuer" {
					a.analyze_cert_main(technoName, key)
				}
				if key == "xhr" {
					a.analyze_xhr_main(technoName, key)
				}

			}
		}
	}
	return a.Technos
}

func (a *Analyze) NewTechno(name string) structure.Technologie {
	return technologies.New(name, a.ResultGlobal)
}
