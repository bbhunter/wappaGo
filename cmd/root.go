package cmd

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/EasyRecon/wappaGo/analyze"
	"github.com/EasyRecon/wappaGo/report"
	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/technologies"
	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/goccy/go-json"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/remeh/sizedwaitgroup"
)

type Cmd struct {
	ChromeCtx    context.Context
	Dialer       *fastdialer.Dialer
	ResultGlobal map[string]interface{}
	Cdn          *cdncheck.Client
	Options      structure.Options
	// portOpenByIP caches the open ports found for an IP so hosts sharing an
	// address are scanned once. It replaces a []PortOpenByIp that was linearly
	// scanned while holding portMu — quadratic, and fully serialised across
	// every worker (4 s of lock time at 50k hosts).
	portOpenByIP map[string][]string
	portMu       sync.RWMutex // guards portOpenByIP
	HttpClient   *http.Client
	ResultArray  []structure.Data
	reportMu     sync.Mutex // guards ResultArray (report mode)
	throttle     *hostThrottle
	Input        []string
	// identity is the browser identity presented to every scanned host, read
	// from the real Chrome build in Start before any worker starts.
	identity identity
	// dns answers the record queries the dns fingerprint family needs. Built
	// once in Start and read-only afterwards.
	dns *dnsResolver
	// sigCtx is cancelled on SIGINT/SIGTERM. It gates the host loop and the
	// port scanner so Ctrl+C actually stops the scan; previously it only
	// parented the Chrome allocator, so the first Ctrl+C killed the browser and
	// left the run grinding through the remaining input emitting empty results.
	sigCtx context.Context
}

// interrupted reports whether a shutdown signal has been received.
func (c *Cmd) interrupted() bool {
	return c.sigCtx != nil && c.sigCtx.Err() != nil
}

func (c *Cmd) Start(results chan structure.Data) {
	// Repair anything unset or nonsensical before a single pointer is
	// dereferenced. Both entry points go through here, so neither the CLI nor
	// the library can reach the scan with a nil field or an unbounded
	// worker count.
	c.Options.ApplyDefaults()
	c.portOpenByIP = make(map[string][]string)

	dialer, err := c.InitDialer()
	if err != nil {
		// Without a dialer every probe would nil-deref inside an http.Transport
		// goroutine, where no recover() can reach it.
		fmt.Fprintf(os.Stderr, "could not create the resolver cache: %v\n", err)
		close(results)
		return
	}
	c.Dialer = dialer
	defer c.Dialer.Close()

	// Resolved explicitly rather than scavenged from the dialer's cache: newer
	// fastdialer only retains address records, so the dns fingerprints had gone
	// silent. A failure here is not fatal — the dns family is one signal source
	// among a dozen — but it is worth reporting.
	dnsResolver, dnsErr := newDNSResolver(c.resolvers())
	if dnsErr != nil {
		fmt.Fprintf(os.Stderr, "could not create the DNS resolver, dns fingerprints disabled: %v\n", dnsErr)
	}
	c.dns = dnsResolver

	// Build the HTTP client once, up front: it is read-only for the rest of
	// the run and shared across all target goroutines. Previously it was
	// rebuilt per target on the shared c.HttpClient field (a data race), and
	// the process-global http.DefaultTransport was mutated per request.
	c.HttpClient = c.buildHTTPClient()

	// Per-host request pacing to stay under rate-based WAF rules (no-op unless
	// -rps or -jitter is set).
	c.throttle = newHostThrottle(*c.Options.Rps, *c.Options.Jitter)

	// The User-Agent is left to Chrome at launch: overriding it here with a
	// hardcoded version contradicted the Sec-CH-UA headers Chrome derives from
	// its own build (measured: UA said Chrome/131 while Sec-CH-UA said 150).
	// resolveIdentity below reads the real build and installs a consistent
	// identity per target instead.
	optionsChromeCtx := chromeAllocatorOptions(c.Options, "")

	// Tie the browser lifetime to SIGINT/SIGTERM: the first Ctrl+C cancels this
	// context, which tears Chrome down and lets the deferred cleanup (browser
	// processes, dialer, temp fingerprint dir) run instead of leaving orphans.
	// Watch for the signal on an explicit channel rather than via
	// signal.NotifyContext: that helper's stop function cancels the context
	// itself, so a normal end-of-scan teardown was indistinguishable from a real
	// Ctrl+C and printed the interrupt notice on every single run.
	sigCtx, cancelScan := context.WithCancel(context.Background())
	defer cancelScan()
	c.sigCtx = sigCtx

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	scanDone := make(chan struct{})
	defer close(scanDone)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "\ninterrupted: finishing in-flight hosts, press Ctrl+C again to abort")
			cancelScan()
			// Restore the default handler so a second Ctrl+C kills the process.
			// Previously the first signal disarmed it for the rest of the run,
			// leaving no way to abort at all.
			signal.Stop(sigCh)
		case <-scanDone:
		}
	}()

	//ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false), chromedp.Flag("disable-gpu", true))...)
	ctxAlloc, cancel1 := chromedp.NewExecAllocator(sigCtx, optionsChromeCtx...)
	defer cancel1()

	ctxAlloc1, cancel := chromedp.NewContext(ctxAlloc)
	c.ChromeCtx = ctxAlloc1
	defer cancel()

	// Read the real browser build once, up front, and present that same
	// identity everywhere: the Chrome targets (User-Agent + Client Hints) and
	// the raw HTTP probe's headers. c.identity is written here, before any
	// worker exists, and only read afterwards.
	if err := chromedp.Run(c.ChromeCtx); err != nil {
		// Startup failure (including a cancel during launch) is reported and the
		// results channel is closed so the consumer drains and exits cleanly,
		// rather than panicking and skipping cleanup.
		fmt.Fprintf(os.Stderr, "could not start Chrome: %v\n", err)
		close(results)
		return
	}

	if id, err := resolveIdentity(c.ChromeCtx); err != nil {
		fmt.Fprintf(os.Stderr, "could not read the browser build, using the fallback identity: %v\n", err)
		c.identity = id
	} else {
		c.identity = id
	}
	// An explicit -user-agent still wins, but the Client Hints metadata keeps
	// following the real build, so the two cannot contradict each other on the
	// version the way a hardcoded UA did.
	if c.Options.UserAgent != nil && *c.Options.UserAgent != "" {
		c.identity.UserAgent = *c.Options.UserAgent
	}

	c.Cdn = cdncheck.New()
	var url string
	var ip string
	swg := sizedwaitgroup.New(*c.Options.Threads)
	url = ""
	ip = ""
	prog := newProgress(len(c.Input), *c.Options.NoProgress)
	for _, line := range c.Input {
		if c.interrupted() {
			fmt.Fprintf(os.Stderr, "aborted: %d/%d hosts not scanned\n", len(c.Input)-int(prog.processed()), len(c.Input))
			break
		}
		ip = ""
		if *c.Options.AmassInput {
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				fmt.Fprintf(os.Stderr, "skip amass line: %v\n", err)
				prog.inc()
				continue
			}
			name, ok := result["name"].(string)
			if !ok {
				fmt.Fprintf(os.Stderr, "skip amass line: missing name\n")
				prog.inc()
				continue
			}
			url = name
			// Address is best-effort: a missing/odd shape leaves ip empty
			// (the host is still scanned by name) instead of panicking.
			if addrs, ok := result["addresses"].([]interface{}); ok && len(addrs) > 0 {
				if addr0, ok := addrs[0].(map[string]interface{}); ok {
					if ipStr, ok := addr0["ip"].(string); ok {
						ip = ipStr
					}
				}
			}
		} else {
			url = line
		}
		swg.Add()
		go func(url string, ip string) {
			defer swg.Done()
			defer prog.inc()
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "recovered while scanning %s: %v\n", url, r)
				}
			}()
			c.startPortScan(url, ip, results)
		}(url, ip)
	}
	swg.Wait()
	prog.finish()
	// Render the HTML report exactly once, from the complete result set, after
	// all targets finish. Previously launchChrome regenerated the whole file
	// after every host (O(n^2) rewrites with concurrent writers).
	if *c.Options.Report {
		report.Report_main(c.ResultArray, *c.Options.Screenshot)
	}
	close(results)
}

func (c *Cmd) startPortScan(url string, ip string, results chan structure.Data) {
	portList := strings.Split(*c.Options.Ports, ",")
	swg1 := sizedwaitgroup.New(50)
	swg := sizedwaitgroup.New(*c.Options.ChromeThreads)
	var CdnName string
	portTemp := portList

	if !*c.Options.AmassInput {
		c.throttle.wait(url)
		// This request exists only to populate the dialer history so
		// GetDialedIP works. Its body was never read nor closed, which parked a
		// connection plus its reader/writer goroutines until the 10 s client
		// timeout reaped them — one leaked socket per host.
		if warm, err := c.HttpClient.Get("http://" + url); err == nil {
			io.Copy(io.Discard, io.LimitReader(warm.Body, 4096))
			warm.Body.Close()
		}
		ip = c.Dialer.GetDialedIP(url)
	}
	isCDN, cdnName, _, err := c.Cdn.Check(net.ParseIP(ip))
	//fmt.Println(isCDN, ip)
	if err != nil {
		// A CDN lookup failure for a single IP must not abort the whole
		// scan; treat the host as non-CDN and carry on.
		isCDN = false
	}
	//fmt.Println(isCDN)
	if isCDN {
		portTemp = []string{"80", "443"}
		CdnName = cdnName
	}
	var portOpen []string
	// An empty IP means the address was never resolved; every such host would
	// otherwise share one bogus cache entry and inherit another host's ports.
	cached, hit := []string(nil), false
	if ip != "" {
		c.portMu.RLock()
		cached, hit = c.portOpenByIP[ip]
		c.portMu.RUnlock()
	}
	if hit {
		portOpen = cached
	} else {
		// Each scanner goroutine reports its open port on a buffered channel
		// instead of appending to a shared slice (which raced). The buffer is
		// sized to the port count so a send never blocks.
		portChan := make(chan string, len(portTemp))
		for _, portEnum := range portTemp {
			swg1.Add()
			go func(portEnum string, url string) {
				defer swg1.Done()
				if c.scanPort("tcp", url, portEnum, *c.Options.Porttimeout) {
					portChan <- portEnum
				}
			}(portEnum, url)
		}
		swg1.Wait()
		close(portChan)
		for p := range portChan {
			portOpen = append(portOpen, p)
		}
		if ip != "" {
			c.portMu.Lock()
			c.portOpenByIP[ip] = portOpen
			c.portMu.Unlock()
		}
	}
	url = strings.TrimSpace(url)
	for _, port := range portOpen {
		swg.Add()
		go func(port string, url string, portOpen []string, CdnName string, c *Cmd) {
			defer swg.Done()
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "recovered while probing %s:%s: %v\n", url, port, r)
				}
			}()
			data := structure.Data{}
			data.Infos.CDN = CdnName
			data.Infos.Data = url
			data.Infos.Ports = portOpen
			data.Infos.IP = ip
			c.getWrapper(url, port, data, results)
		}(port, url, portOpen, CdnName, c)
	}
	swg.Wait()
}

func (c *Cmd) getWrapper(urlData string, port string, data structure.Data, results chan structure.Data) {
	errorContinue := true
	//u, err := url.Parse(urlData)
	var urlDataPort string
	var resp *structure.Response
	if port != "80" && port != "443" {
		urlDataPort = urlData + ":" + port
	} else {
		urlDataPort = urlData
	}
	client := c.HttpClient

	var TempResp structure.Response
	//resp, errSSL = client.Get("https://" + urlDataPort)
	var errSSL error
	if port != "80" {
		c.throttle.wait(urlData)
		request, _ := http.NewRequest("GET", "https://"+urlDataPort, nil)
		setBrowserHeaders(request, c.userAgent())
		resp, errSSL = Do(request, client)
	}
	if errSSL != nil || port == "80" {
		if port == "443" {
			errorContinue = false
		} else {
			c.throttle.wait(urlData)
			request, _ := http.NewRequest("GET", "http://"+urlDataPort, nil)
			setBrowserHeaders(request, c.userAgent())
			resp, errPlain := Do(request, client)
			if errPlain != nil || resp == nil {

				errorContinue = false
			} else {
				data, TempResp, _ = c.DefineBasicMetric(data, resp)
				if data.Infos.Scheme == "" {
					data.Infos.Scheme = "http"
				}
				urlData = "http://" + urlDataPort
				data.Url = urlData
			}
		}
	} else {
		data, TempResp, _ = c.DefineBasicMetric(data, resp)
		if data.Infos.Scheme == "" {
			data.Infos.Scheme = "https"
		}
		urlData = "https://" + urlDataPort
		data.Url = urlData
	}
	if errorContinue {
		c.launchChrome(TempResp, data, urlData, port, results)
	}
}

func (c *Cmd) launchChrome(TempResp structure.Response, data structure.Data, urlData string, port string, results chan structure.Data) {
	var err error
	if data.Infos.Location != "" {
		urlData = resolveLocation(urlData, data.Infos.Location)
	}
	dnsData := c.dns.resolve(data.Infos.Data)
	if dnsData != nil {
		data.Infos.Cname = dnsData.CNAME
	}
	analyseStruct := analyze.Analyze{}
	ctxAlloc1, cancelTimeout := context.WithTimeout(c.ChromeCtx, 60*time.Second)
	defer cancelTimeout()
	cloneCTX, cancel := chromedp.NewContext(ctxAlloc1)
	chromedp.ListenTarget(cloneCTX, func(ev interface{}) {
		if _, ok := ev.(*network.EventResponseReceived); ok {
			//data, _ := network.GetResponseBody(ev.(*network.EventResponseReceived).RequestID).Do(cloneCTX)

			//log.Println(string(data))
			ev := ev.(*network.EventResponseReceived)
			switch ev.Type {
			case "XHR":
				analyseStruct.AddXHRUrl(ev.Response.URL)
			case "Document":
				// Headers of the page Chrome actually landed on. The raw probe
				// stops at the 30x by default, so its headers describe the
				// redirect, not the page that gets analysed — which is why a
				// host redirecting http->https reported none of its header-based
				// technologies (no Server, no X-Powered-By) even though the DOM
				// ones came through.
				analyseStruct.SetFinalHeaders(ev.Response.URL, ev.Response.Headers)
			}
		}
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			// Dismiss the dialog and say nothing else. This handler used to
			// json.Marshal the shared result struct — racing the goroutine
			// writing it — and print it to stdout, injecting a duplicate,
			// half-filled record into the JSON stream.
			go func() {
				if err := chromedp.Run(cloneCTX, page.HandleJavaScriptDialog(true)); err != nil {
					fmt.Fprintf(os.Stderr, "dismiss dialog on %s: %v\n", urlData, err)
				}
			}()
		}
	})
	defer cancel()
	// run task list
	//var res []string
	var buf []byte

	c.throttle.wait(data.Infos.Data)
	err = chromedp.Run(cloneCTX,
		// Install the User-Agent and its matching Client Hints before the first
		// navigation, so the very first request carries a consistent identity.
		applyIdentity(c.identity),
		chromedp.Navigate(urlData),
		chromedp.Title(&data.Infos.Title),
		// The screenshot is optional and must never be able to cost a detection.
		// It used to sit here unconditionally, so on a page where
		// Page.captureScreenshot failed (-32000) the action chain aborted and the
		// host was reported with zero technologies — and it ran even without
		// -screenshot, paying for a full PNG encode per page just to discard it.
		captureScreenshot(*c.Options.Screenshot != "", &buf),
		chromedp.ActionFunc(func(ctx context.Context) error {

			cookiesList, _ := network.GetCookies().Do(ctx)
			if strings.HasPrefix(urlData, "https://") {
				sslcert, _ := network.GetCertificate(urlData).Do(ctx)
				if len(sslcert) > 0 {
					sDec, _ := base64.StdEncoding.DecodeString(sslcert[0])
					cert, _ := x509.ParseCertificate(sDec)
					analyseStruct.CertVhost = cert.DNSNames
					analyseStruct.CertIssuer = cert.Issuer.CommonName
				}
			}
			node, err_node := dom.GetDocument().Do(ctx)
			if err_node != nil {
				return err_node
			}
			body, err := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			if err == nil {
				reader := strings.NewReader(body)
				doc, errDoc := goquery.NewDocumentFromReader(reader)

				if errDoc != nil {
					// Malformed DOM: skip analysis for this target rather
					// than killing the whole process.
					return errDoc
				}
				analyseStruct.Doc = doc
				var srcList []string
				doc.Find("script").Each(func(i int, s *goquery.Selection) {
					srcLink, exist := s.Attr("src")

					if exist {

						//fmt.Println(srcList, srcLink)
						srcList = append(srcList, srcLink)
					}
				})
				analyseStruct.SrcList = srcList
				analyseStruct.Body = body
			}

			analyseStruct.ResultGlobal = c.ResultGlobal
			analyseStruct.Resp = TempResp
			// The URL family matches against the page that was scanned, not
			// against the Location header.
			analyseStruct.Url = urlData

			analyseStruct.Ctx = ctx
			analyseStruct.Hote = data.Infos
			analyseStruct.CookiesList = cookiesList
			analyseStruct.Node = node

			analyseStruct.Technos = []structure.Technologie{}
			analyseStruct.DnsData = dnsData
			data.Infos.Technologies = analyseStruct.Run()
			data.Infos.CertVhost = analyseStruct.CertVhost
			return nil
		}),
	)

	// chromedp.Run's error used to be assigned and never read, so a failed
	// navigation looked exactly like a page that rendered cleanly and happened
	// to run no technologies. Record it and say so on stderr.
	if err != nil {
		data.Infos.Error = err.Error()
		fmt.Fprintf(os.Stderr, "render %s: %v\n", urlData, err)
	}

	data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
	// Drop technologies whose "requires" precondition isn't met by the rest of
	// the detected set (e.g. a plugin without the platform it needs), then drop
	// any that a detected technology declares it cannot coexist with.
	data.Infos.Technologies = technologies.FilterRequired(data.Infos.Technologies, c.ResultGlobal)
	data.Infos.Technologies = technologies.FilterExcluded(data.Infos.Technologies, c.ResultGlobal)
	if *c.Options.Screenshot != "" && len(buf) > 0 {
		// Name the screenshot by the SHA-1 of its URL. The previous scheme
		// stripped ':' '/' '.' from the URL, which collapsed distinct URLs to
		// the same filename and silently overwrote screenshots.
		imgTitle := fmt.Sprintf("%x", sha1.Sum([]byte(urlData)))
		file, err := os.OpenFile(
			*c.Options.Screenshot+"/"+imgTitle+".png",
			os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
			0666,
		)
		if err == nil {
			file.Write(buf)
			file.Close()
			data.Infos.Screenshot = imgTitle + ".png"
		}
	}
	// The HTML report is an additional sink, not a replacement for the JSON
	// stream. -report used to take the else branch away entirely, so
	// `wappaGo -report > out.json` wrote an empty file and the run looked like
	// it had detected nothing.
	if *c.Options.Report {
		c.reportMu.Lock()
		c.ResultArray = append(c.ResultArray, data)
		c.reportMu.Unlock()
	}
	results <- data
}

// resolveLocation resolves a redirect target against the URL that was actually
// probed.
//
// A Location header is allowed to be relative (RFC 7231 §7.1.2) and very often
// is — "https://stackoverflow.com" answers "302 Location: /questions". Feeding
// that raw value to chromedp.Navigate fails, which aborted the whole action
// chain, so Title, the screenshot and every technology matcher were skipped and
// the host was emitted with an empty title and zero technologies.
//
// Anything that does not resolve to http(s) is refused and the probed URL is
// kept: a scanned host must not be able to steer the operator's browser to
// file:// or javascript:.
func resolveLocation(probed string, location string) string {
	base, err := URL.Parse(probed)
	if err != nil {
		return probed
	}
	ref, err := URL.Parse(strings.TrimSpace(location))
	if err != nil {
		return probed
	}
	target := base.ResolveReference(ref)
	if target.Scheme != "http" && target.Scheme != "https" {
		return probed
	}
	return target.String()
}

func (c *Cmd) scanPort(protocol, hostname string, port string, portTimeout int) bool {
	address := hostname + ":" + port
	conn, err := net.DialTimeout(protocol, address, time.Duration(portTimeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// userAgent returns the User-Agent presented to scanned hosts. Once Start has
// read the real browser build this is that build's UA; before then (or if the
// browser could not be queried) it is the explicit -user-agent, then the
// built-in fallback.
func (c *Cmd) userAgent() string {
	if c.identity.UserAgent != "" {
		return c.identity.UserAgent
	}
	if c.Options.UserAgent != nil && *c.Options.UserAgent != "" {
		return *c.Options.UserAgent
	}
	return structure.DefaultUserAgent
}

// setBrowserHeaders makes the raw HTTP probe look like the same Chrome that
// drives the rendering pass, so a WAF sees one consistent browser instead of
// the default "Go-http-client/1.1". Accept-Encoding is left unset on purpose so
// Go keeps decompressing gzip transparently.
func setBrowserHeaders(req *http.Request, ua string) {
	h := req.Header
	h.Set("User-Agent", ua)
	// Byte-for-byte what Chrome 1xx sends on a document navigation. The probe
	// used to omit the signed-exchange entry and to hardcode a language Chrome
	// itself did not use, so the two clients disagreed on every host.
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	h.Set("Accept-Language", acceptLanguageHeader)
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-User", "?1")
	if v := chromeMajor(ua); v != "" {
		h.Set("Sec-Ch-Ua", `"Google Chrome";v="`+v+`", "Chromium";v="`+v+`", "Not_A Brand";v="24"`)
		h.Set("Sec-Ch-Ua-Mobile", "?0")
		h.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	}
}

// chromeMajor extracts the Chrome major version from a UA string ("" if none).
func chromeMajor(ua string) string {
	i := strings.Index(ua, "Chrome/")
	if i < 0 {
		return ""
	}
	rest := ua[i+len("Chrome/"):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	return rest[:j]
}

// maxProbeBody caps how much of a probed body is read. Only the metrics below
// use it — technology detection runs on the DOM Chrome renders, not on this.
const maxProbeBody = 4096

// Do http request
func Do(req *http.Request, client *http.Client) (*structure.Response, error) {
	var gzipRetry bool
	started := time.Now()
get_response:
	httpresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpresp.Body.Close()

	var resp structure.Response

	// Response.Duration was read into Host.Response_time but never assigned, so
	// every result reported response_time: 0 and the report's "time" row was
	// always blank.
	resp.Duration = time.Since(started)
	resp.Headers = httpresp.Header.Clone()

	// The previous implementation ran pdhttputil.DumpResponseHeadersAndRaw here,
	// whose DumpResponse(resp, true) reads the ENTIRE body into memory and then
	// copies it again — before the deliberate 4096-byte cap below ever applied.
	// The size was dictated purely by the scanned host, so a large or
	// heavily-compressed response could exhaust the scanner's memory. Its only
	// outputs were Response.Raw and Response.RawHeaders, which nothing read.

	var respbody []byte
	// websockets don't have a readable body
	if httpresp.StatusCode != http.StatusSwitchingProtocols {
		respbody, err = io.ReadAll(io.LimitReader(httpresp.Body, maxProbeBody))
		if err != nil {
			// Some servers advertise gzip but send an uncompressed body; the
			// stdlib then wires up a gzip reader that fails on the first read.
			// Retry once asking for identity.
			if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
				gzipRetry = true
				req.Header.Set("Accept-Encoding", "identity")
				httpresp.Body.Close()
				goto get_response
			}
			return nil, err
		}
	}

	resp.StatusCode = httpresp.StatusCode

	// Prefer the advertised length; fall back to what was actually read. The
	// fallback is capped by maxProbeBody, so it under-reports on a large body
	// that omits Content-Length.
	if contentLength, ok := resp.Headers["Content-Length"]; ok {
		if n, convErr := strconv.Atoi(strings.Join(contentLength, "")); convErr == nil && n >= 0 {
			resp.ContentLength = n
		}
	}
	if resp.ContentLength <= 0 && len(respbody) > 0 {
		resp.ContentLength = utf8.RuneCountInString(string(respbody))
	}

	return &resp, nil
}

// defaultResolvers are used when -resolvers is not set.
const defaultResolvers = "8.8.8.8,1.1.1.1,64.6.64.6,74.82.42.42,1.0.0.1,8.8.4.4,64.6.65.6,77.88.8.8"

// resolvers returns the resolver list to use, honouring -resolvers.
//
// It does not write through the option pointer: in library mode that pointer may
// alias a caller's struct field.
func (c *Cmd) resolvers() []string {
	list := defaultResolvers
	if c.Options.Resolvers != nil && *c.Options.Resolvers != "" {
		list = *c.Options.Resolvers
	}
	return strings.Split(list, ",")
}

// InitDialer builds the resolving dialer. It used to swallow the error and hand
// back a nil *Dialer, which the caller then used as if it were valid.
func (c *Cmd) InitDialer() (*fastdialer.Dialer, error) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true
	fastdialerOpts.BaseResolvers = c.resolvers()

	return fastdialer.NewDialer(fastdialerOpts)
}

// buildHTTPClient constructs the single, shared HTTP client used for every
// probe. It is called once from Start(); the returned client (and its
// transport) is never mutated afterwards, so it is safe to share across all
// target/port goroutines.
func (c *Cmd) buildHTTPClient() *http.Client {
	// A proxy tunnels the origin handshake through CONNECT, so the ClientHello
	// is not ours to shape; that path keeps the standard transport. The
	// MaxVersion pin that used to be here as well has been dropped: capping the
	// tunnel at TLS 1.2 hid every TLS-1.3-only origin behind a probe failure.
	var proxyTransport *http.Transport
	if *c.Options.Proxy != "" {
		if proxyURL, parseErr := URL.Parse(*c.Options.Proxy); parseErr == nil {
			proxyTransport = &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
				DialContext:       c.Dialer.Dial,
				DisableKeepAlives: true,
				Proxy:             http.ProxyURL(proxyURL),
			}
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: newHTTPTransport(c.Dialer.Dial, proxyTransport),
	}
	if !*c.Options.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func (c *Cmd) DefineBasicMetric(data structure.Data, resp *structure.Response) (structure.Data, structure.Response, error) {

	if (resp.StatusCode == 301 || resp.StatusCode == 302) && len(resp.Headers["Location"]) > 0 {
		data.Infos.Location = resp.Headers["Location"][0]
	}
	if len(resp.Headers["Content-Type"]) > 0 {
		data.Infos.Content_type = strings.Split(resp.Headers["Content-Type"][0], ";")[0]
	}
	data.Infos.Response_time = resp.Duration
	data.Infos.Content_length = resp.ContentLength
	data.Infos.Status_code = resp.StatusCode
	return data, *resp, nil
}
