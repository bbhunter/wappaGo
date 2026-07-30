# WappaGo

<p align="center">  
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>  
    <a href="https://github.com/EasyRecon/Hunt3r"><img src="https://img.shields.io/badge/release-v0.0.8-informational"></a>
    <a href="https://github.com/easyrecon/wappago/issues" target="_blank"><img src="https://img.shields.io/github/issues/easyrecon/wappago?color=blue" /></a>
</p>

<p align="center">  
    <a href="https://codeclimate.com/github/EasyRecon/wappaGo"><img src="https://codeclimate.com/github/EasyRecon/wappaGo.png"></a>
</p>

<p align="center">
  <a href="#about">About WappaGo</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a>
</p>

# About
WappaGo has been developed to assemble different features from tools like [HTTPX](https://github.com/projectdiscovery/httpx), [Naabu](https://github.com/projectdiscovery/naabu), [GoWitness](https://github.com/sensepost/gowitness) and [Wappalyzer](https://github.com/wappalyzer/wappalyzer).
To allow an efficient detection of technologies, it is necessary to open a browser and in order to avoid opening a browser for each target, WappaGo opens only one browser and uses the system of pages which allows to consume less resources and to carry out an analysis much more quickly.

# Installation

Download the latest [release](https://github.com/EasyRecon/wappaGo/releases)  or compile by yourself :

```bash
git clone https://github.com/EasyRecon/wappaGo
cd wappaGo && go build 
```
or
```
go install github.com/EasyRecon/wappaGo@latest
```

**Note :** _wappaGo requires Chrome to be present on the system_

# Usage



```
Usage of wappaGo:
  -amass-input
        Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo
  -chrome-threads int
        Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5) (default 5)
  -follow-redirect
        Follow redirect to detect technologie
  -headless
        Run Chrome without a display. Off by default: headless fakes an 800x600
        screen and brands its own User-Agent. Use xvfb-run on a server instead
  -jitter int
        Max random delay in ms added before each request (0 = none)
  -no-progress
        Disable the stderr progress bar
  -port-timeout int
        Timeout during port scanning in ms (default 2000)
  -ports string
        port want to scan separated by coma (default "80,443")
  -proxy string
        Use http proxy
  -report
        Generate HTML report (in addition to the JSON on stdout)
  -resolvers string
        Use specifique resolver separated by comma
  -rps float
        Max HTTP requests per second per host to stay under rate-based WAF rules (0 = unlimited)
  -screenshot string
        path to screenshot if empty no screenshot
  -threads int
        Number of threads to start recon in same time (default 5)
  -user-agent string
        User-Agent sent by both the HTTP probe and Chrome (blank keeps the built-in browser UA)

```

Results are written to stdout as one JSON object per line, so `-report` can be
combined with a redirect:

```bash
cat domain.txt | ./wappaGo -report > results.json   # JSON on stdout + wappaGo_report.html
```

The technology fingerprints are downloaded at startup from
[Serizao/tech](https://github.com/Serizao/tech), parsed into memory, and the
on-disk copy is deleted before the scan begins.

## Blending in

wappaGo presents one consistent browser identity to every host it scans. The
User-Agent is read from the installed Chrome at startup (with the
`HeadlessChrome` token rewritten) and installed together with its matching
Client Hints metadata, so `navigator.userAgent`, `navigator.userAgentData` and
the `Sec-CH-UA-*` headers all report the same build. The raw HTTP probe derives
its `User-Agent`, `Sec-CH-UA-*`, `Accept` and `Accept-Language` from that same
identity. `--enable-automation` is not passed, and WebGL is left enabled.

**Chrome runs with a display by default.** Headless is available behind
`-headless`, but it costs two things that then have to be papered over: it reports
an 800x600 screen whatever the window size, so a 1400x900 viewport claims to sit
on a smaller display, and it brands its own User-Agent. With a real display both
are simply correct — measured `screen=1920x1200` and a clean UA — and no screen
override is issued at all. On a server, run it under a virtual display:

```bash
xvfb-run -a --server-args="-screen 0 1920x1080x24" ./wappaGo < domain.txt
```

Without a display and without `-headless`, Chrome will not start; wappaGo says so
and points at both options rather than failing with a bare error.

`RTCPeerConnection` leaks the host's real public address when `-proxy` is in use:
WebRTC negotiates over UDP and does not traverse an HTTP proxy, so a scanned page
can reach a public STUN server and read straight past the proxy. That is
deanonymisation rather than fingerprinting, so `-proxy` also enables
`--webrtc-ip-handling-policy=disable_non_proxied_udp`, which drops both the
server-reflexive and host candidates while leaving `RTCPeerConnection` defined —
closing the leak without substituting a "browser with no WebRTC" tell. Chrome
already hides the LAN address behind an mDNS name by default. The
`--force-webrtc-ip-handling-policy` spelling was measured to have no effect at all
on Chrome 150; only the older flag name works.

That identity is capped to the Chrome version the TLS handshake below can
actually imitate. uTLS ships no profile for the newest Chrome releases, and
claiming a browser newer than the handshake produces is a contradiction
bot-protection vendors correlate: against a DataDome-protected origin, a Chrome
133 handshake paired with a User-Agent claiming Chrome 150 was refused 4/4 with
`403` and a captcha page, while the same handshake with a matching User-Agent
passed 2/2. The cost is that the browser reports an older version than its own
engine, which a site could catch by comparing the User-Agent against JS features
only present in the real build — a rarer and more expensive check than the
TLS/User-Agent correlation, and claiming *older* is the safe direction.

A measurement harness records what the browser actually gives away:

```bash
WAPPAGO_STEALTH_CHECK=1 go test ./cmd/ -run Stealth -v
```

It serves its own page locally, so the verdicts are reproducible, and it also
drives the hosted detector at `bot-detector.rebrowser.net`:

```bash
WAPPAGO_STEALTH_REMOTE=1 go test ./cmd/ -run RemoteDetector -v
```

Two known limits it reports rather than hides:

- **`window.outerWidth` / `outerHeight` are 0.** This comes from the tab chromedp
  attaches to through `Target.createTarget`, which has no window of its own —
  not from headless, and not from the metrics override. Measured: every
  combination of headless/display, override/no override and
  `Browser.setWindowBounds` reports 0, while raw Chrome opening a URL itself
  reports the window size. Nothing reachable over CDP changes it, and the usual
  workaround redefines the accessor from an injected script, which leaves a getter
  that no longer reports `[native code]` — a broader tell than the one it fixes.
- **WebGL quality depends on the host.** With a GPU, Chrome reports the real
  adapter, the most plausible fingerprint available. On a GPU-less server it falls
  back to software rendering and says so (`SwiftShader`, `llvmpipe`,
  `Microsoft Basic Render Driver`), and the canvas hash shifts with it — a stable
  value that is a *known* value is still identifying. There is no CDP override for
  WebGL, so masking it would mean patching JS. Measured against the hosted
  detector, forcing SwiftShader changed no verdict at all: the same greens as a
  real GPU. That is a negative result from one detector rather than proof of
  safety — CreepJS and commercial vendors do fingerprint WebGL — so nothing is
  patched for now and the harness logs a `NOTE:` when software rendering is in use.

Canvas, WebGL and audio fingerprints are deliberately **not** randomised. The
goal is to look ordinary, not unique: a fingerprint that changes between two
reads is itself a signature of an anti-fingerprinting tool. The harness asserts
those surfaces are present and stable instead.

The raw HTTP probe also handshakes like a browser. It runs before Chrome on every
target, so its TLS ClientHello is the first thing a host sees, and Go's
`crypto/tls` hello does not resemble one: different cipher list and ordering, and
no ALPN at all — which is what JA3/JA4 hashes key on. The probe now dials https
through [uTLS](https://github.com/refraction-networking/utls) with a Chrome
ClientHello, and carries the request over HTTP/2 when ALPN settles on it, so the
HTTP/2 `SETTINGS`/`WINDOW_UPDATE` fingerprint is a real h2 client's rather than a
downgrade to HTTP/1.1. Measured against a local server:

| | cipher suites | first suite | ALPN offered |
|---|---|---|---|
| `crypto/tls` | 13 | `0xc02b` | *(none)* |
| uTLS Chrome | 16 | `0x5a5a` (GREASE) | `h2`, `http/1.1` |

Two cases keep the standard transport on purpose: plain `http`, which has no
handshake to disguise, and `-proxy`, where the origin handshake happens inside a
`CONNECT` tunnel wappaGo does not drive.

Still outstanding: `chromedp` issues `Runtime.enable` on every target, which is
a reliable CDP detection signal. The usual fix routes evaluation through an
isolated world, but wappaGo's `js` fingerprints read page globals
(`jQuery.fn.jquery`, `Stimulus.Application`) and so require the main world.

You can either use wappaGo from a file containing a list of domains
```bash
cat domain.txt | ./wappaGo
```

or from an Amass output  (preferred)

```bash
amass enum -d example.com -ipv4 -json out.json
cat out.json | ./wappaGo -amass-input
```

# Library

You can use wappaGo as a library in your own project.

## Options
      
```go
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
	Headless       bool
}
```

Any field left at its zero value falls back to the same default as the
corresponding CLI flag (`Ports: "80,443"`, `Threads: 5`, `ChromeThreads: 5`,
`Porttimeout: 2000`), so you only have to set what you want to change.

## Example

Both entry points return an `error`, which is non-nil when the setup itself
failed — most often because the technology fingerprints could not be downloaded.
Ignoring it means scanning every host with an empty database and reporting zero
technologies everywhere.

```go
package main

import (
	"fmt"
	"log"

	"github.com/EasyRecon/wappaGo/structure"
	"github.com/EasyRecon/wappaGo/wrapper"
)

func main() {
	input := []string{"google.com", "twitter.com"}

	options := structure.WrapperOptions{
		Ports:      "80,443",
		Screenshot: "screenshots",
	}

	// Sync mode: blocks, then returns everything.
	results, err := wrapper.StartReconSync(input, options)
	if err != nil {
		log.Fatal(err)
	}
	for _, result := range results {
		fmt.Println(result)
	}
}
```

```go
	// Async mode: results are streamed on the channel, which wrapper closes
	// when the scan is done. StartReconAsync blocks until then, so run the
	// consumer in its own goroutine and wait for it to drain.
	results := make(chan structure.Data)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for result := range results {
			fmt.Println(result)
		}
	}()

	if err := wrapper.StartReconAsync(input, options, results); err != nil {
		log.Fatal(err)
	}
	<-done
```

For each url, you will receive a structure.Data which contains all the information about the target.

## Todo



  - Add robot technologie dectection
  - Add xhr technologie dectection


## Thank's

This tool uses several [ProjectDiscovery](https://github.com/projectdiscovery) libraries
