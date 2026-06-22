package structure

import (
	"time"

	"github.com/projectdiscovery/cryptoutil"
)

type Technologie struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Cpe        string `json:"cpe,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

const WappazlyerRoot = "https://raw.githubusercontent.com/dochne/wappalyzer/master/src"
const LetterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// DefaultUserAgent is presented by both the raw HTTP probe and Chrome so a WAF
// sees one consistent, browser-like client instead of "Go-http-client" then
// "HeadlessChrome".
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

var InterrestingKey = []string{"dns", "js", "meta", "text", "dom", "script", "html", "scriptSrc", "headers", "cookies", "url", "certIssuer", "xhr"}

type Host struct {
	Status_code    int           `json:"status_code"`
	Ports          []string      `json:"ports"`
	Path           string        `json:"path"`
	Location       string        `json:"location,omitempty"`
	Title          string        `json:"title"`
	Scheme         string        `json:"scheme"`
	Data           string        `json:"data"`
	Response_time  time.Duration `json:"response_time"`
	Screenshot     string        `json:"screenshot_name,omitempty"`
	Technologies   []Technologie `json:"technologies"`
	Content_length int           `json:"content_length"`
	Content_type   string        `json:"content_type"`
	IP             string        `json:"ip"`
	Cname          []string      `json:"cname,omitempty"`
	CDN            string        `json:"cdn,omitempty"`
	CertVhost      []string      `json:"certvhost,omitempty"`
}
type Data struct {
	Url   string `json:"url"`
	Infos Host   `json:"infos"`
}
type Options struct {
	Screenshot     *string
	Ports          *string
	Threads        *int
	Porttimeout    *int
	Resolvers      *string
	AmassInput     *bool
	FollowRedirect *bool
	ChromeTimeout  *int
	ChromeThreads  *int
	Report         *bool
	Proxy          *string
	UserAgent      *string
	Rps            *float64
	Jitter         *int
}
type WrapperOptions struct {
	Screenshot     string
	Ports          string
	Threads        int
	Porttimeout    int
	Resolvers      string
	FollowRedirect bool
	ChromeTimeout  int
	ChromeThreads  int
	Proxy          string
	UserAgent      string
	Rps            float64
	Jitter         int
}
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *cryptoutil.TLSData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
}

type PortOpenByIp struct {
	IP        string
	Open_port []string
}
