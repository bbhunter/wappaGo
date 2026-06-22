package cmd

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
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
	"github.com/EasyRecon/wappaGo/lib"
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
	pdhttputil "github.com/projectdiscovery/httputil"
	"github.com/remeh/sizedwaitgroup"
)

type Cmd struct {
	ChromeCtx    context.Context
	Dialer       *fastdialer.Dialer
	ResultGlobal map[string]interface{}
	Cdn          *cdncheck.Client
	Options      structure.Options
	PortOpenByIP []structure.PortOpenByIp
	portMu       sync.Mutex // guards PortOpenByIP
	HttpClient   *http.Client
	ResultArray  []structure.Data
	reportMu     sync.Mutex // guards ResultArray (report mode)
	Input        []string
}

func (c *Cmd) Start(results chan structure.Data) {
	c.Dialer = c.InitDialer()
	defer c.Dialer.Close()

	// Build the HTTP client once, up front: it is read-only for the rest of
	// the run and shared across all target goroutines. Previously it was
	// rebuilt per target on the shared c.HttpClient field (a data race), and
	// the process-global http.DefaultTransport was mutated per request.
	c.HttpClient = c.buildHTTPClient()

	optionsChromeCtx := []chromedp.ExecAllocatorOption{}
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DefaultExecAllocatorOptions[:]...)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("headless", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-popup-blocking", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.DisableGPU)
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("disable-webgl", true))
	optionsChromeCtx = append(optionsChromeCtx, chromedp.Flag("ignore-certificate-errors", true)) // RIP shittyproxy.go
	optionsChromeCtx = append(optionsChromeCtx, chromedp.WindowSize(1400, 900))
	if *c.Options.Proxy != "" {
		optionsChromeCtx = append(optionsChromeCtx, chromedp.ProxyServer(*c.Options.Proxy))
	}

	// Tie the browser lifetime to SIGINT/SIGTERM: the first Ctrl+C cancels this
	// context, which tears Chrome down and lets the deferred cleanup (browser
	// processes, dialer, temp fingerprint dir) run instead of leaving orphans.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	//ctxAlloc, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false), chromedp.Flag("disable-gpu", true))...)
	ctxAlloc, cancel1 := chromedp.NewExecAllocator(sigCtx, optionsChromeCtx...)
	defer cancel1()

	ctxAlloc1, cancel := chromedp.NewContext(ctxAlloc)
	c.ChromeCtx = ctxAlloc1
	defer cancel()

	if err := chromedp.Run(c.ChromeCtx); err != nil {
		// Startup failure (including a cancel during launch) is reported and the
		// results channel is closed so the consumer drains and exits cleanly,
		// rather than panicking and skipping cleanup.
		fmt.Fprintf(os.Stderr, "could not start Chrome: %v\n", err)
		close(results)
		return
	}

	c.Cdn = cdncheck.New()
	var url string
	var ip string
	swg := sizedwaitgroup.New(*c.Options.Threads)
	url = ""
	ip = ""
	for _, line := range c.Input {
		ip = ""
		if *c.Options.AmassInput {
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				fmt.Fprintf(os.Stderr, "skip amass line: %v\n", err)
				continue
			}
			name, ok := result["name"].(string)
			if !ok {
				fmt.Fprintf(os.Stderr, "skip amass line: missing name\n")
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
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "recovered while scanning %s: %v\n", url, r)
				}
			}()
			c.startPortScan(url, ip, results)
		}(url, ip)
	}
	swg.Wait()
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
		c.HttpClient.Get("http://" + url)
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
	c.portMu.Lock()
	alreadyScanned := lib.CheckIpAlreadyScan(ip, c.PortOpenByIP)
	c.portMu.Unlock()
	if alreadyScanned.IP != "" {
		portOpen = alreadyScanned.Open_port
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
		c.portMu.Lock()
		c.PortOpenByIP = append(c.PortOpenByIP, structure.PortOpenByIp{IP: ip, Open_port: portOpen})
		c.portMu.Unlock()
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
		request, _ := http.NewRequest("GET", "https://"+urlDataPort, nil)
		resp, errSSL = Do(request, client)
	}
	if errSSL != nil || port == "80" {
		if port == "443" {
			errorContinue = false
		} else {
			request, _ := http.NewRequest("GET", "http://"+urlDataPort, nil)
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
		urlData = data.Infos.Location
	}
	dnsData, err := c.Dialer.GetDNSData(data.Infos.Data)
	if dnsData != nil && err == nil {
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
			switch typeDoc := ev.(*network.EventResponseReceived).Type; typeDoc {
			case "XHR":
				analyseStruct.AddXHRUrl(ev.(*network.EventResponseReceived).Response.URL)
			case "Stylesheet":
				//analyseStruct.CSSContent = append(analyseStruct.CSSContent,ev.(*network.EventResponseReceived).Response.URL)

			case "Script":
				//analyseStruct.CSSContent = append(analyseStruct.CSSContent,ev.(*network.EventResponseReceived).Response.URL)
			}
		}
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			//fmt.Println("closing alert:", ev.Message)
			go func() {
				if err := chromedp.Run(cloneCTX,
					page.HandleJavaScriptDialog(true),
				); err != nil {
					b, err := json.Marshal(data)
					if err != nil {
						fmt.Println("Error:", err)
					}
					fmt.Println(string(b))
					return
				}
			}()
		}
	})
	defer cancel()
	// run task list
	//var res []string
	var buf []byte

	err = chromedp.Run(cloneCTX,
		chromedp.Navigate(urlData),
		chromedp.Title(&data.Infos.Title),
		//chromedp.FullScreenshot(&buf, 100),
		chromedp.CaptureScreenshot(&buf),
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

	data.Infos.Technologies = technologies.DedupTechno(data.Infos.Technologies)
	// Drop technologies whose "requires" precondition isn't met by the rest of
	// the detected set (e.g. a plugin without the platform it needs).
	data.Infos.Technologies = technologies.FilterRequired(data.Infos.Technologies, c.ResultGlobal)
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
	if *c.Options.Report {
		c.reportMu.Lock()
		c.ResultArray = append(c.ResultArray, data)
		c.reportMu.Unlock()
	} else {
		results <- data
	}
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

// Do http request
func Do(req *http.Request, client *http.Client) (*structure.Response, error) {
	var gzipRetry bool
get_response:
	httpresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var resp structure.Response

	resp.Headers = httpresp.Header.Clone()

	// httputil.DumpResponse does not handle websockets
	headers, rawResp, err := pdhttputil.DumpResponseHeadersAndRaw(httpresp)
	if err != nil {
		// Edge case - some servers respond with gzip encoding header but uncompressed body, in this case the standard library configures the reader as gzip, triggering an error when read.
		// The bytes slice is not accessible because of abstraction, therefore we need to perform the request again tampering the Accept-Encoding header
		if !gzipRetry && strings.Contains(err.Error(), "gzip: invalid header") {
			gzipRetry = true
			req.Header.Set("Accept-Encoding", "identity")
			goto get_response
		}

		return nil, err

	}
	resp.Raw = string(rawResp)
	resp.RawHeaders = string(headers)

	var respbody []byte
	// websockets don't have a readable body
	if httpresp.StatusCode != http.StatusSwitchingProtocols {
		var err error
		respbody, err = ioutil.ReadAll(io.LimitReader(httpresp.Body, 4096))
		if err != nil {

			return nil, err
		}
	}

	closeErr := httpresp.Body.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	respbodystr := string(respbody)

	// if content length is not defined
	if resp.ContentLength <= 0 {
		// check if it's in the header and convert to int
		if contentLength, ok := resp.Headers["Content-Length"]; ok {
			contentLengthInt, _ := strconv.Atoi(strings.Join(contentLength, ""))
			resp.ContentLength = contentLengthInt
		}

		// if we have a body, then use the number of bytes in the body if the length is still zero
		if resp.ContentLength <= 0 && len(respbodystr) > 0 {
			resp.ContentLength = utf8.RuneCountInString(respbodystr)
		}
	}

	resp.Data = respbody

	// fill metrics
	resp.StatusCode = httpresp.StatusCode
	// number of words
	resp.Words = len(strings.Split(respbodystr, " "))
	// number of lines
	resp.Lines = len(strings.Split(respbodystr, "\n"))

	return &resp, nil
}

func (c *Cmd) InitDialer() *fastdialer.Dialer {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = true

	if len(*c.Options.Resolvers) == 0 {
		*c.Options.Resolvers = "8.8.8.8,1.1.1.1,64.6.64.6,74.82.42.42,1.0.0.1,8.8.4.4,64.6.65.6,77.88.8.8"
	}
	fastdialerOpts.BaseResolvers = strings.Split(*c.Options.Resolvers, ",")

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create resolver cache: %s\n", err)
	}
	return dialer
}

// buildHTTPClient constructs the single, shared HTTP client used for every
// probe. It is called once from Start(); the returned client (and its
// transport) is never mutated afterwards, so it is safe to share across all
// target/port goroutines.
func (c *Cmd) buildHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext:       c.Dialer.Dial,
		DisableKeepAlives: true,
	}
	if *c.Options.Proxy != "" {
		proxyURL, parseErr := URL.Parse(*c.Options.Proxy)
		if parseErr == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
			transport.TLSClientConfig.MaxVersion = tls.VersionTLS12
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
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
