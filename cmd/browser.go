package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/EasyRecon/wappaGo/structure"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// chromeAllocatorOptions builds the command line the browser is launched with.
//
// It deliberately does NOT start from chromedp.DefaultExecAllocatorOptions.
// That list ends with Flag("enable-automation", true) — the single most widely
// checked automation marker — so importing it wholesale undid part of the point
// of launching a browser at all. The flags below are the useful subset, copied
// explicitly so every one of them is a decision rather than an inheritance.
//
// Kept separate from Start so the exact production configuration can be
// launched by the stealth harness in browser_stealth_test.go.
func chromeAllocatorOptions(options structure.Options, userAgent string) []chromedp.ExecAllocatorOption {
	opts := []chromedp.ExecAllocatorOption{
		// Housekeeping: a scanner must never wait on first-run UI, a default
		// browser prompt, a crash reporter or an update check.
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),

		// Keep background pages and timers running: throttling a backgrounded
		// renderer is exactly what stops lazily-loaded scripts from appearing,
		// which is what the js/scriptSrc fingerprints look for.
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-hang-monitor", true),

		// Containers give /dev/shm 64 MB, which crashes renderers.
		chromedp.Flag("disable-dev-shm-usage", true),

		// A scanner must not stop on a prompt.
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),

		// Throughput, not stealth. Dropping these was measured to cost 47
		// detections over the 20-target reference set and to time out two hosts
		// entirely: with site isolation on, every third-party iframe on an
		// ad-heavy page gets its own process, multiplied by the concurrent tab
		// count. None of them is a known bot signal, so they stay.
		chromedp.Flag("disable-features", "site-per-process,Translate,BlinkGenPropertyTrees"),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),

		// We are deliberately visiting hosts with broken TLS.
		chromedp.Flag("ignore-certificate-errors", true),

		// Hides navigator.webdriver.
		chromedp.Flag("disable-blink-features", "AutomationControlled"),

		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.WindowSize(viewportWidth, viewportHeight),
		chromedp.Headless,
	}

	// Notable omissions, each one a measured decision:
	//
	//   --enable-automation      the marker itself, and the only flag from
	//                            chromedp's defaults that is actually dropped
	//   --disable-webgl          an absent WebGL context is a strong bot signal;
	//                            Camoufox spoofs WebGL rather than removing it
	//   --disable-gpu            would take the real WebGL adapter down with it
	//
	// Nothing is added for graphics on purpose. Measured on this machine with
	// the stealth harness:
	//
	//   no flags                 NVIDIA T1200 Laptop GPU / Direct3D11   <- kept
	//   --use-angle=swiftshader  SwiftShader (software)
	//   --disable-gpu            Microsoft Basic Render Driver
	//   --disable-webgl          no WebGL context at all                <- was here
	//
	// Letting Chrome choose gives the real adapter, which is the most plausible
	// WebGL fingerprint available, and costs nothing. Forcing SwiftShader made
	// rendering so much slower that 7 of 20 targets hit the 60 s budget and came
	// back with zero technologies. On a GPU-less host Chrome falls back to
	// software rendering by itself, so this stays correct on a server too.

	if userAgent != "" {
		opts = append(opts, chromedp.UserAgent(userAgent))
	}
	if options.Proxy != nil && *options.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(*options.Proxy))
	}
	return opts
}

// On the Runtime.enable CDP leak, deliberately not addressed:
//
// chromedp issues runtime.Enable() on every target (chromedp@v0.8.5:368), and
// that command is the basis of the most widely cited CDP detection technique.
// The usual mitigation — evaluating everything in an isolated world — is not
// available to wappaGo: the js fingerprint family reads page globals
// (jQuery.fn.jquery, Stimulus.Application, ~3155 patterns), so the main world is
// required. The remaining option was to patch chromedp behind a replace
// directive.
//
// Measured before committing to that: run against rebrowser's hosted detector
// with this exact configuration and Chrome 150, runtimeEnableLeak reports "No
// leak detected", as do navigatorWebdriver, viewport, pwInitScripts, bypassCsp
// and useragent. Forking a dependency for no measurable gain is not worth the
// maintenance, so it is left alone. TestStealthRemoteDetector re-checks this, so
// a future Chrome or chromedp that does leak will show up rather than pass
// unnoticed.
//
// One honest caveat: that detector's mainWorldExecution test only fires when the
// page is asked for a specific selector, which the harness does not do. In
// production the js matchers do touch the main world on every page, so that
// particular vector is untested rather than cleared.

// identity is the single browser identity presented to every scanned host: one
// User-Agent, and the Client Hints metadata derived from the same values.
//
// Splitting those two apart is what the previous approach got wrong. Chrome
// computes Sec-CH-UA from its own build and ignores the --user-agent flag, so
// hardcoding "Chrome/131" while running Chrome 150 made every request advertise
// two different versions — measured on Chrome 150 against a local echo server.
// A real browser derives both from one internal state, so we do too.
type identity struct {
	UserAgent string
	Major     string
	Full      string
	Platform  string
}

// resolveIdentity asks the running browser what it actually is, and turns that
// into an identity that does not admit to being headless.
//
// New headless still writes "HeadlessChrome" into the User-Agent, so the token
// has to be rewritten; everything else is left exactly as Chrome reported it.
func resolveIdentity(ctx context.Context) (identity, error) {
	var product, ua string
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var e error
		_, product, _, ua, _, e = browser.GetVersion().Do(ctx)
		return e
	}))
	if err != nil {
		return fallbackIdentity(), err
	}
	return identityFromUserAgent(ua, product), nil
}

// identityFromUserAgent derives the presented identity from Chrome's own
// User-Agent and product strings ("HeadlessChrome/150.0.7871.188").
func identityFromUserAgent(ua, product string) identity {
	id := fallbackIdentity()
	if ua == "" {
		return id
	}
	// "HeadlessChrome/150.0..." -> "Chrome/150.0..."; a site must not be told
	// the browser is headless.
	ua = strings.ReplaceAll(ua, "HeadlessChrome/", "Chrome/")
	id.UserAgent = ua

	if full := versionAfter(product, "Chrome/"); full != "" {
		id.Full = full
	} else if full := versionAfter(ua, "Chrome/"); full != "" {
		id.Full = full
	}
	if major := chromeMajor(ua); major != "" {
		id.Major = major
	}
	id.capToHello()
	if strings.Contains(ua, "Windows") {
		id.Platform = "Windows"
	} else if strings.Contains(ua, "Mac OS X") {
		id.Platform = "macOS"
	} else if strings.Contains(ua, "Linux") || strings.Contains(ua, "X11") {
		id.Platform = "Linux"
	}
	return id
}

// capToHello lowers the presented version to the one the TLS handshake imitates.
//
// The probe's ClientHello comes from a uTLS profile, and uTLS has no profile for
// the newest Chrome releases. Presenting the installed browser's version while
// handshaking as an older one is a contradiction we introduce ourselves, and it
// is the kind bot-protection vendors correlate: against a DataDome origin the
// mismatched pair was refused 4/4 while the matched pair passed 2/2.
//
// The trade-off, stated plainly: the browser then claims to be older than its own
// engine, so a site comparing the User-Agent against JS features only present in
// the real build could notice. That check is far rarer and more expensive than the
// TLS/User-Agent correlation, and claiming an older version is the safe direction
// — claiming a version newer than the latest stable release is what detectors
// actually flag. Capping only the probe was the alternative, and it was rejected
// because it puts the probe and the browser back in disagreement, which is the
// defect this whole line of work started from.
func (id *identity) capToHello() {
	if id.Major == "" || helloChromeMajor == "" {
		return
	}
	have, err1 := strconv.Atoi(id.Major)
	cap, err2 := strconv.Atoi(helloChromeMajor)
	if err1 != nil || err2 != nil || have <= cap {
		return
	}
	id.Major = helloChromeMajor
	id.Full = helloChromeMajor + ".0.0.0"
	// Rewrite the version inside the UA string so every surface agrees.
	if i := strings.Index(id.UserAgent, "Chrome/"); i >= 0 {
		rest := id.UserAgent[i+len("Chrome/"):]
		end := 0
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		id.UserAgent = id.UserAgent[:i] + "Chrome/" + id.Full + rest[end:]
	}
}

// fallbackIdentity is used only when the browser cannot be queried. It is a
// last resort, not a default: a hardcoded version is precisely the thing that
// contradicted the Client Hints.
func fallbackIdentity() identity {
	ua := structure.DefaultUserAgent
	major := chromeMajor(ua)
	full := versionAfter(ua, "Chrome/")
	if full == "" {
		full = major
	}
	return identity{UserAgent: ua, Major: major, Full: full, Platform: "Windows"}
}

// Viewport and the screen it is meant to sit on. Headless Chrome reports an
// 800x600 screen regardless of the window size, so a 1400x900 window appeared
// to be larger than the display containing it — impossible on real hardware, and
// the sort of internal inconsistency detectors look for. The screen is declared
// as a common desktop resolution that comfortably contains the viewport.
const (
	viewportWidth  = 1400
	viewportHeight = 900
	screenWidth    = 1920
	screenHeight   = 1080
)

// The language both clients advertise. Chrome would otherwise use the host's
// locale (measured: fr-FR on this machine) while the raw probe hardcoded en-US,
// so the two contradicted each other on every host. Pinning it makes them agree
// and makes scans reproducible.
//
// Two spellings are needed: Chrome appends the quality values itself, so handing
// it the full header produced "en-US,en;q=0.9;q=0.9".
const (
	acceptLanguageChrome = "en-US,en"       // Emulation.setUserAgentOverride
	acceptLanguageHeader = "en-US,en;q=0.9" // the raw probe's own header
)

// captureScreenshot grabs the viewport into buf when screenshots are enabled.
//
// It is deliberately non-fatal: technology detection is the product, a PNG is
// not, so a renderer that cannot produce one must not abort the action chain
// that carries every matcher. When screenshots are disabled it does nothing at
// all rather than encoding an image that is immediately discarded.
func captureScreenshot(enabled bool, buf *[]byte) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if !enabled {
			return nil
		}
		if err := chromedp.CaptureScreenshot(buf).Do(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "screenshot: %v\n", err)
		}
		return nil
	})
}

// applyIdentity installs the identity on a target: the User-Agent together with
// the Client Hints metadata, so navigator.userAgent, navigator.userAgentData and
// the Sec-CH-UA-* headers all agree; a viewport that fits inside a plausible
// screen; and a locale matching the Accept-Language the probe sends.
func applyIdentity(id identity) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if id.UserAgent != "" {
			if err := emulation.SetUserAgentOverride(id.UserAgent).
				WithUserAgentMetadata(id.metadata()).
				WithAcceptLanguage(acceptLanguageChrome).
				Do(ctx); err != nil {
				return err
			}
		}
		// Declare the screen the viewport lives on, so screen.width/height stop
		// reporting the headless 800x600 default.
		if err := emulation.SetDeviceMetricsOverride(viewportWidth, viewportHeight, 1, false).
			WithScreenWidth(screenWidth).
			WithScreenHeight(screenHeight).
			WithPositionX(0).
			WithPositionY(0).
			Do(ctx); err != nil {
			return err
		}
		// Browser.setWindowBounds was tried here to give
		// window.outerWidth/outerHeight a non-zero value. The harness measured no
		// effect — headless has no real window — and it made
		// Page.captureScreenshot fail with -32000 on heavy pages, which took the
		// whole detection pass down with it. Removed: it cost detections and
		// bought nothing. The zero outer dimensions are a documented residual.
		return nil
	})
}

// secChUa renders the identity as a Sec-CH-UA header value, in the same brand
// order and with the same bogus entry the browser itself sends.
//
// The raw probe used to hardcode `"Google Chrome";v="N", "Chromium";v="N",
// "Not_A Brand";v="24"` — the Chrome-110-era spelling, with the brands in the
// opposite order to what Chrome now emits. So after commit "one coherent browser
// identity" the User-Agent finally agreed between the probe and the browser while
// the Client Hints still contradicted each other. Both now come from here.
func (id identity) secChUa() string {
	parts := make([]string, 0, len(id.metadata().Brands))
	for _, b := range id.metadata().Brands {
		parts = append(parts, `"`+b.Brand+`";v="`+b.Version+`"`)
	}
	return strings.Join(parts, ", ")
}

// metadata mirrors what a real Chrome of this version reports, including the
// deliberately-bogus "Not)A;Brand" entry Chrome uses to keep parsers honest.
func (id identity) metadata() *emulation.UserAgentMetadata {
	brands := []*emulation.UserAgentBrandVersion{
		{Brand: "Not)A;Brand", Version: "99"},
		{Brand: "Chromium", Version: id.Major},
		{Brand: "Google Chrome", Version: id.Major},
	}
	full := []*emulation.UserAgentBrandVersion{
		{Brand: "Not)A;Brand", Version: "99.0.0.0"},
		{Brand: "Chromium", Version: id.Full},
		{Brand: "Google Chrome", Version: id.Full},
	}
	return &emulation.UserAgentMetadata{
		Brands:          brands,
		FullVersionList: full,
		Platform:        id.Platform,
		PlatformVersion: platformVersion(id.Platform),
		Architecture:    "x86",
		Bitness:         "64",
		Model:           "",
		Mobile:          false,
	}
}

// platformVersion is the Sec-CH-UA-Platform-Version value. Chrome reports the
// OS version here; "15.0.0" is what Chrome on Windows 10/11 sends.
func platformVersion(platform string) string {
	switch platform {
	case "Windows":
		return "15.0.0"
	case "macOS":
		return "14.0.0"
	default:
		return ""
	}
}

// versionAfter returns the dotted version that follows prefix in s.
func versionAfter(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	rest := s[i+len(prefix):]
	end := 0
	for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	out := strings.TrimSuffix(rest[:end], ".")
	if out == "" {
		return ""
	}
	// Reject something that is not a version at all.
	if _, err := strconv.Atoi(strings.SplitN(out, ".", 2)[0]); err != nil {
		return ""
	}
	return out
}
