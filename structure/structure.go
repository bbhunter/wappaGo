package structure

import "time"

type Technologie struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Cpe     string `json:"cpe,omitempty"`
	// Icon is the fingerprint's icon filename (e.g. "Nginx.svg"), copied
	// straight from the database. Omitted for technologies that declare none.
	Icon       string `json:"icon,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// TechnologiesRoot is the base URL of the fingerprint database. The 27 shards
// (_.json, a.json … z.json) live directly at this root.
const TechnologiesRoot = "https://raw.githubusercontent.com/Serizao/tech/main"

// WappazlyerRoot is the previous upstream, kept as a deprecated alias so
// library users pinning it still compile.
//
// Deprecated: use TechnologiesRoot.
const WappazlyerRoot = TechnologiesRoot

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
	// Error carries a failed render. Without it a host whose page never loaded
	// is indistinguishable from one that loaded and genuinely runs nothing.
	Error string `json:"error,omitempty"`
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
	NoProgress     *bool
	// Headless runs Chrome without a display. It defaults to false: headless
	// reports an 800x600 screen whatever the window size and writes
	// "HeadlessChrome" into its own User-Agent, both of which have to be papered
	// over. Running with a real display (Xvfb on a server) avoids that entirely.
	// Requires a display to be available — see the note in cmd.Start.
	Headless *bool
}

// Default values for Options. They are the single source of truth: main.go
// passes them to the flag package, and ApplyDefaults repairs anything that
// reaches cmd.Start unset or nonsensical.
const (
	DefaultPorts         = "80,443"
	DefaultThreads       = 5
	DefaultChromeThreads = 5
	DefaultPortTimeout   = 2000
)

// ApplyDefaults fills in every unset or invalid field.
//
// Options is a struct of fourteen pointers that cmd dereferences unguarded, so
// any nil is a crash. The library path built this struct by hand and forwarded
// a caller's zero-valued WrapperOptions verbatim, which meant the documented
// README example ran with Threads=0 and Porttimeout=0. A non-positive worker
// count is also actively dangerous: sizedwaitgroup treats limit<=0 as unbounded,
// so `-threads 0` removed the concurrency cap entirely.
func (o *Options) ApplyDefaults() {
	str := func(p **string, def string) {
		if *p == nil {
			v := def
			*p = &v
		} else if **p == "" {
			**p = def
		}
	}
	num := func(p **int, def int) {
		if *p == nil {
			v := def
			*p = &v
		} else if **p <= 0 {
			**p = def
		}
	}
	flag := func(p **bool) {
		if *p == nil {
			v := false
			*p = &v
		}
	}

	str(&o.Ports, DefaultPorts)
	num(&o.Threads, DefaultThreads)
	num(&o.ChromeThreads, DefaultChromeThreads)
	num(&o.Porttimeout, DefaultPortTimeout)

	// Empty is meaningful for these: no screenshots, system resolvers, no proxy,
	// built-in User-Agent.
	for _, p := range []**string{&o.Screenshot, &o.Resolvers, &o.Proxy, &o.UserAgent} {
		if *p == nil {
			v := ""
			*p = &v
		}
	}
	for _, p := range []**bool{&o.AmassInput, &o.FollowRedirect, &o.Report, &o.NoProgress, &o.Headless} {
		flag(p)
	}
	if o.ChromeTimeout == nil {
		v := 0
		o.ChromeTimeout = &v
	}
	// 0 means "unlimited" for both, so only a negative value is repaired.
	if o.Rps == nil || *o.Rps < 0 {
		v := 0.0
		if o.Rps != nil {
			*o.Rps = v
		} else {
			o.Rps = &v
		}
	}
	if o.Jitter == nil || *o.Jitter < 0 {
		v := 0
		if o.Jitter != nil {
			*o.Jitter = v
		} else {
			o.Jitter = &v
		}
	}
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
	// Headless runs Chrome without a display. Default false; requires a display
	// (Xvfb on a server) when left off.
	Headless bool
}

// Response is the raw HTTP probe result. It only carries what is actually
// consumed: Headers feed the header matcher, the rest feed Host's metrics.
// Raw, RawHeaders, Data, Words, Lines, TLSData, HTTP2 and Pipeline were removed
// because nothing ever read them — and populating Raw meant buffering every
// probed body whole, twice.
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	ContentLength int
	Duration      time.Duration
}
