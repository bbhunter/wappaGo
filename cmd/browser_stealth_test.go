package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EasyRecon/wappaGo/structure"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// This harness measures what the browser we actually launch gives away. It is
// opt-in because it starts a real Chrome:
//
//	WAPPAGO_STEALTH_CHECK=1 go test ./cmd/ -run Stealth -v
//
// The probe page is served locally, so the verdicts are deterministic and do
// not depend on a third-party detector staying up or unchanged. Cross-check
// against https://bot-detector.rebrowser.net/ by hand when touching the
// Runtime.enable path, which a local page cannot observe.

func requireStealthCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("WAPPAGO_STEALTH_CHECK") == "" {
		t.Skip("set WAPPAGO_STEALTH_CHECK=1 to run the stealth harness (launches Chrome)")
	}
}

// stealthProbe is the page the browser is pointed at. Everything it reports is
// read from the page's own main world, i.e. exactly what a detection script
// running on a scanned site would see.
const stealthProbe = `<!doctype html>
<html><head><title>probe</title></head><body>
<script>
// Cheap stable digest. Only used to compare two readings of the same surface
// against each other, never sent anywhere, so a cryptographic hash would be
// pointless weight.
function digest(s) {
  var h1 = 0x811c9dc5, h2 = 0x01000193;
  for (var i = 0; i < s.length; i++) {
    h1 = (h1 ^ s.charCodeAt(i)) >>> 0;
    h1 = (h1 * 0x01000193) >>> 0;
    h2 = (h2 + s.charCodeAt(i) * (i + 1)) >>> 0;
  }
  return ('00000000' + h1.toString(16)).slice(-8) + ('00000000' + h2.toString(16)).slice(-8);
}

function webglInfo() {
  try {
    var c = document.createElement('canvas');
    c.width = 256; c.height = 128;
    var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return { available: false };
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    var exts = gl.getSupportedExtensions() || [];
    function prec(shader, p) {
      var f = gl.getShaderPrecisionFormat(shader, p);
      return f ? f.rangeMin + ':' + f.rangeMax + ':' + f.precision : 'null';
    }
    // Draw something and read it back: this is the actual WebGL image
    // fingerprint detectors compute, not just the parameter strings.
    var vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vs, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}');
    gl.compileShader(vs);
    var fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fs, 'precision mediump float;void main(){gl_FragColor=vec4(gl_FragCoord.x/256.0,gl_FragCoord.y/128.0,0.5,1.0);}');
    gl.compileShader(fs);
    var pr = gl.createProgram();
    gl.attachShader(pr, vs); gl.attachShader(pr, fs); gl.linkProgram(pr); gl.useProgram(pr);
    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(pr, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    var px = new Uint8Array(256 * 128 * 4);
    gl.readPixels(0, 0, 256, 128, gl.RGBA, gl.UNSIGNED_BYTE, px);
    var s = '';
    for (var i = 0; i < px.length; i += 997) s += px[i] + ',';

    return {
      available: true,
      vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
      renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
      glVersion: gl.getParameter(gl.VERSION),
      shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      extensionCount: exts.length,
      hasDebugRendererInfo: !!dbg,
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxViewportDims: (gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []).join('x'),
      maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      precision: prec(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT) + '|' + prec(gl.VERTEX_SHADER, gl.HIGH_FLOAT),
      imageHash: digest(s)
    };
  } catch (e) { return { available: false, error: String(e) }; }
}

// canvasHash renders text and gradients through the 2D context — the classic
// canvas fingerprint. It is read twice so the caller can tell a genuine, stable
// fingerprint from a randomised one: noise injection is itself a marker of an
// anti-fingerprinting tool, which is the opposite of blending in.
function canvasHash() {
  try {
    var c = document.createElement('canvas');
    c.width = 240; c.height = 60;
    var ctx = c.getContext('2d');
    var g = ctx.createLinearGradient(0, 0, 240, 60);
    g.addColorStop(0, '#f60'); g.addColorStop(1, '#06f');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 240, 60);
    ctx.fillStyle = 'rgba(255,255,255,0.7)';
    ctx.font = '18px "Arial"';
    ctx.fillText('wappaGo ☁ 🔒 0123', 4, 40);
    ctx.strokeStyle = 'rgba(0,0,0,0.5)';
    ctx.arc(60, 30, 20, 0, Math.PI * 2);
    ctx.stroke();
    return digest(c.toDataURL());
  } catch (e) { return 'error:' + String(e); }
}

// audioInfo reads the AudioContext parameters and renders a short offline
// buffer. Same reasoning as canvas: what matters is that it exists and is
// stable, not that it is unique.
function audioInfo() {
  var out = { sampleRate: null, maxChannelCount: null, hash: '', error: '' };
  try {
    var AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC) { out.error = 'no OfflineAudioContext'; return Promise.resolve(out); }
    var ctx = new AC(1, 44100, 44100);
    out.sampleRate = ctx.sampleRate;
    out.maxChannelCount = ctx.destination.maxChannelCount;
    var osc = ctx.createOscillator();
    osc.type = 'triangle';
    osc.frequency.value = 10000;
    var comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    return ctx.startRendering().then(function (buf) {
      var d = buf.getChannelData(0), s = '';
      for (var i = 4500; i < 5000; i++) s += d[i].toFixed(6) + ',';
      out.hash = digest(s);
      return out;
    }).catch(function (e) { out.error = String(e); return out; });
  } catch (e) { out.error = String(e); return Promise.resolve(out); }
}
function uaData() {
  var d = navigator.userAgentData;
  if (!d) return null;
  var brands = (d.brands || []).map(function (b) { return b.brand + '/' + b.version; });
  return { brands: brands, mobile: d.mobile, platform: d.platform };
}
window.__probe = {
  webdriver: navigator.webdriver,
  hasWindowChrome: typeof window.chrome !== 'undefined',
  hasChromeRuntime: !!(window.chrome && window.chrome.runtime),
  userAgent: navigator.userAgent,
  uaData: uaData(),
  languages: (navigator.languages || []).join(','),
  language: navigator.language,
  pluginCount: navigator.plugins ? navigator.plugins.length : -1,
  mimeTypeCount: navigator.mimeTypes ? navigator.mimeTypes.length : -1,
  hardwareConcurrency: navigator.hardwareConcurrency,
  deviceMemory: navigator.deviceMemory === undefined ? null : navigator.deviceMemory,
  outerWidth: window.outerWidth,
  outerHeight: window.outerHeight,
  innerWidth: window.innerWidth,
  innerHeight: window.innerHeight,
  screenWidth: screen.width,
  screenHeight: screen.height,
  webgl: webglInfo(),
  // Each surface twice, so the caller can prove stability rather than assume it.
  webglImageHash2: webglInfo().imageHash || '',
  canvasHash: canvasHash(),
  canvasHash2: canvasHash(),
  // A patched-JS check of the kind Camoufox's docs call out: a spoofed accessor
  // stops reporting [native code].
  webdriverIsNative: (function () {
    try {
      var d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      return !d || !d.get ? null : d.get.toString().indexOf('[native code]') !== -1;
    } catch (e) { return null; }
  })()
};

// Audio is asynchronous; the Go side awaits this promise and merges the result.
window.__probeAudio = Promise.all([audioInfo(), audioInfo()]).then(function (r) {
  return { first: r[0], second: r[1] };
});
</script>
</body></html>`

// probeResult mirrors window.__probe.
type probeResult struct {
	Webdriver           interface{} `json:"webdriver"`
	HasWindowChrome     bool        `json:"hasWindowChrome"`
	HasChromeRuntime    bool        `json:"hasChromeRuntime"`
	UserAgent           string      `json:"userAgent"`
	UAData              *uaDataInfo `json:"uaData"`
	Language            string      `json:"language"`
	PluginCount         int         `json:"pluginCount"`
	MimeTypeCount       int         `json:"mimeTypeCount"`
	HardwareConcurrency int         `json:"hardwareConcurrency"`
	OuterWidth          int         `json:"outerWidth"`
	OuterHeight         int         `json:"outerHeight"`
	InnerWidth          int         `json:"innerWidth"`
	InnerHeight         int         `json:"innerHeight"`
	ScreenWidth         int         `json:"screenWidth"`
	ScreenHeight        int         `json:"screenHeight"`
	WebGL               webglResult `json:"webgl"`
	WebGLImageHash2     string      `json:"webglImageHash2"`
	CanvasHash          string      `json:"canvasHash"`
	CanvasHash2         string      `json:"canvasHash2"`
	WebdriverIsNative   *bool       `json:"webdriverIsNative"`

	// Filled from window.__probeAudio, which resolves separately.
	Audio audioPair `json:"-"`
}

type audioPair struct {
	First  audioResult `json:"first"`
	Second audioResult `json:"second"`
}

type audioResult struct {
	SampleRate      float64 `json:"sampleRate"`
	MaxChannelCount int     `json:"maxChannelCount"`
	Hash            string  `json:"hash"`
	Error           string  `json:"error"`
}

type uaDataInfo struct {
	Brands   []string `json:"brands"`
	Mobile   bool     `json:"mobile"`
	Platform string   `json:"platform"`
}

type webglResult struct {
	Available            bool   `json:"available"`
	Vendor               string `json:"vendor"`
	Renderer             string `json:"renderer"`
	GLVersion            string `json:"glVersion"`
	ShadingLanguage      string `json:"shadingLanguage"`
	ExtensionCount       int    `json:"extensionCount"`
	HasDebugRendererInfo bool   `json:"hasDebugRendererInfo"`
	MaxTextureSize       int    `json:"maxTextureSize"`
	MaxViewportDims      string `json:"maxViewportDims"`
	MaxRenderbufferSize  int    `json:"maxRenderbufferSize"`
	Precision            string `json:"precision"`
	ImageHash            string `json:"imageHash"`
	Error                string `json:"error"`
}

// runProbe serves the probe page, drives the production browser configuration
// at it, and returns both the in-page findings and the headers the browser
// actually put on the wire.
func runProbe(t *testing.T) (probeResult, http.Header) {
	t.Helper()

	var mu sync.Mutex
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if got == nil {
			got = r.Header.Clone()
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(stealthProbe))
	}))
	defer srv.Close()

	empty := ""
	opts := structure.Options{Proxy: &empty}
	allocOpts := chromeAllocatorOptions(opts, "")

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	ctx, cancel := context.WithTimeout(browserCtx, 90*time.Second)
	defer cancel()

	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("could not start Chrome: %v", err)
	}

	ident, err := resolveIdentity(ctx)
	if err != nil {
		t.Logf("resolveIdentity: %v", err)
	}

	var raw []byte
	err = chromedp.Run(ctx,
		applyIdentity(ident, false),
		chromedp.Navigate(srv.URL),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Evaluate(`JSON.stringify(window.__probe)`, &raw).Do(ctx)
		}),
	)
	if err != nil {
		t.Fatalf("probe run: %v", err)
	}

	var unquoted string
	if err := json.Unmarshal(raw, &unquoted); err != nil {
		t.Fatalf("probe payload was not a JSON string: %v (%s)", err, raw)
	}
	var res probeResult
	if err := json.Unmarshal([]byte(unquoted), &res); err != nil {
		t.Fatalf("decode probe: %v (%s)", err, unquoted)
	}

	// The audio surface is rendered asynchronously, so it is awaited separately.
	// chromedp.Evaluate cannot await a promise, but runtime.Evaluate can.
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		out, exc, err := runtime.Evaluate(`window.__probeAudio.then(function(r){return JSON.stringify(r)})`).
			WithAwaitPromise(true).
			WithReturnByValue(true).
			Do(ctx)
		if err != nil {
			return err
		}
		if exc != nil {
			return fmt.Errorf("%s", exc.Text)
		}
		var s string
		if err := json.Unmarshal(out.Value, &s); err != nil {
			return err
		}
		return json.Unmarshal([]byte(s), &res.Audio)
	})); err != nil {
		t.Logf("audio probe: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	return res, got
}

// TestStealthReport prints the verdict table. It is the measurement baseline:
// run it before and after any change to chromeAllocatorOptions.
func TestStealthReport(t *testing.T) {
	requireStealthCheck(t)
	res, hdr := runProbe(t)

	t.Log("=== in-page ===")
	t.Logf("  navigator.webdriver     %v", res.Webdriver)
	t.Logf("  webdriver getter native %v", boolPtr(res.WebdriverIsNative))
	t.Logf("  window.chrome           %v (runtime: %v)", res.HasWindowChrome, res.HasChromeRuntime)
	t.Logf("  navigator.userAgent     %s", res.UserAgent)
	if res.UAData != nil {
		t.Logf("  userAgentData.brands    %s", strings.Join(res.UAData.Brands, ", "))
		t.Logf("  userAgentData.platform  %q mobile=%v", res.UAData.Platform, res.UAData.Mobile)
	} else {
		t.Log("  userAgentData           <absent>")
	}
	t.Logf("  plugins/mimeTypes       %d / %d", res.PluginCount, res.MimeTypeCount)
	t.Logf("  hardwareConcurrency     %d", res.HardwareConcurrency)
	t.Logf("  window outer/inner      %dx%d / %dx%d", res.OuterWidth, res.OuterHeight, res.InnerWidth, res.InnerHeight)
	t.Logf("  screen                  %dx%d", res.ScreenWidth, res.ScreenHeight)
	t.Log("=== fingerprint surfaces ===")
	t.Logf("  canvas 2D hash          %s (2nd read: %s)", res.CanvasHash, res.CanvasHash2)
	t.Logf("  webgl image hash        %s (2nd read: %s)", res.WebGL.ImageHash, res.WebGLImageHash2)
	t.Logf("  audio sampleRate        %.0f, maxChannelCount %d", res.Audio.First.SampleRate, res.Audio.First.MaxChannelCount)
	t.Logf("  audio hash              %s (2nd read: %s) %s", res.Audio.First.Hash, res.Audio.Second.Hash, res.Audio.First.Error)
	if res.WebGL.Available {
		t.Logf("  webgl version           %s / %s", res.WebGL.GLVersion, res.WebGL.ShadingLanguage)
		t.Logf("  webgl extensions        %d (debug_renderer_info: %v)", res.WebGL.ExtensionCount, res.WebGL.HasDebugRendererInfo)
		t.Logf("  webgl limits            maxTexture=%d maxViewport=%s maxRenderbuffer=%d",
			res.WebGL.MaxTextureSize, res.WebGL.MaxViewportDims, res.WebGL.MaxRenderbufferSize)
		t.Logf("  webgl precision         %s", res.WebGL.Precision)
	}

	if res.WebGL.Available {
		t.Logf("  webgl                   %s / %s", res.WebGL.Vendor, res.WebGL.Renderer)
	} else {
		t.Logf("  webgl                   UNAVAILABLE %s", res.WebGL.Error)
	}

	// Known residual, reported rather than hidden. It comes from the tab chromedp
	// attaches to via Target.createTarget, which has no window of its own — not
	// from headless, and not from the metrics override, both of which were blamed
	// here before and measured innocent:
	//
	//   headless, no override      outer=0x0     display, no override      outer=0x0
	//   headless, override         outer=0x0     display, override         outer=0x0
	//   headless + windowBounds    outer=0x0     display + windowBounds    outer=0x0
	//
	// Raw Chrome opening a URL itself does report the window size, so nothing
	// reachable over CDP fixes this. The usual workaround redefines the accessor
	// from an injected script, which leaves a getter that no longer reports
	// [native code] — a broader tell than the one it fixes.
	if res.OuterWidth == 0 || res.OuterHeight == 0 {
		t.Logf("  RESIDUAL: window.outerWidth/outerHeight are 0 (chromedp target has no window; not patched on purpose)")
	}

	t.Log("=== on the wire ===")
	var keys []string
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), "sec-") || strings.EqualFold(k, "user-agent") ||
			strings.EqualFold(k, "accept-language") || strings.EqualFold(k, "accept") {
			t.Logf("  %-24s %s", k, hdr.Get(k))
		}
	}
}

// TestStealthNoHeadlessToken pins that the identity presented to a site never
// admits to being headless. New headless still writes "HeadlessChrome" into the
// UA, so this only passes because resolveIdentity rewrites it.
func TestStealthNoHeadlessToken(t *testing.T) {
	requireStealthCheck(t)
	res, hdr := runProbe(t)

	for label, value := range map[string]string{
		"navigator.userAgent":    res.UserAgent,
		"User-Agent on the wire": hdr.Get("User-Agent"),
	} {
		if strings.Contains(value, "Headless") {
			t.Errorf("%s admits to being headless: %s", label, value)
		}
	}
}

// TestStealthUserAgentMatchesClientHints is the regression guard for the leak
// this work started from: the UA claimed Chrome/131 while Sec-CH-UA, which
// Chrome derives from its own build, said 150. A real browser reports one
// version from a single internal state.
func TestStealthUserAgentMatchesClientHints(t *testing.T) {
	requireStealthCheck(t)
	res, hdr := runProbe(t)

	uaMajor := chromeMajor(hdr.Get("User-Agent"))
	if uaMajor == "" {
		t.Fatalf("no Chrome version in the User-Agent header: %q", hdr.Get("User-Agent"))
	}

	chMajor := majorFromSecChUa(hdr.Get("Sec-Ch-Ua"))
	if chMajor == "" {
		// A real Chrome always sends Sec-CH-UA over http on localhost too;
		// missing headers are themselves a signal.
		t.Fatalf("Sec-CH-UA absent (%q) — a real Chrome always sends it", hdr.Get("Sec-Ch-Ua"))
	}
	if uaMajor != chMajor {
		t.Errorf("version mismatch: User-Agent says %s, Sec-CH-UA says %s (headers: UA=%q CH=%q)",
			uaMajor, chMajor, hdr.Get("User-Agent"), hdr.Get("Sec-Ch-Ua"))
	}

	if navMajor := chromeMajor(res.UserAgent); navMajor != uaMajor {
		t.Errorf("navigator.userAgent says %s but the header says %s", navMajor, uaMajor)
	}
	if res.UAData != nil {
		found := false
		for _, b := range res.UAData.Brands {
			if strings.HasSuffix(b, "/"+uaMajor) {
				found = true
			}
		}
		if !found {
			t.Errorf("navigator.userAgentData.brands %v carries no %s entry", res.UAData.Brands, uaMajor)
		}
	}
}

// TestStealthWebGLAvailable pins the removal of --disable-webgl: a missing WebGL
// context is a strong bot signal, so software rendering must still provide one.
func TestStealthWebGLAvailable(t *testing.T) {
	requireStealthCheck(t)
	res, _ := runProbe(t)

	if !res.WebGL.Available {
		t.Fatalf("no WebGL context: %s", res.WebGL.Error)
	}
	if res.WebGL.Vendor == "" || res.WebGL.Renderer == "" {
		t.Errorf("empty WebGL vendor/renderer: %q / %q", res.WebGL.Vendor, res.WebGL.Renderer)
	}
}

// webrtcProbe reports its ICE candidates back to the test server rather than
// leaving them in the DOM.
//
// ICE gathering is asynchronous and chromedp.Evaluate returns immediately, so
// reading window state would only ever catch "pending" — the page has to push the
// result once gathering completes.
const webrtcProbe = `<!doctype html><html><body><script>
var lines = [], sent = false;
function send(tag) {
  if (sent) return;
  sent = true;
  fetch('/report', {method: 'POST', body: JSON.stringify({tag: tag, candidates: lines})});
}
if (typeof RTCPeerConnection === 'undefined') { send('NO_API'); }
else {
  var pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
  pc.onicecandidate = function (e) {
    if (e.candidate) { lines.push(e.candidate.candidate); } else { send('COMPLETE'); }
  };
  pc.createDataChannel('probe');
  pc.createOffer().then(function (o) { return pc.setLocalDescription(o); })
    .catch(function () { send('OFFER_ERROR'); });
  setTimeout(function () { send('TIMEOUT'); }, 8000);
}
</script></body></html>`

type webrtcResult struct {
	Tag        string   `json:"tag"`
	Candidates []string `json:"candidates"`
}

// runWebrtcProbe drives the production configuration at the WebRTC page and
// returns what the page managed to gather. proxy mirrors -proxy, which is what
// gates the mitigation.
func runWebrtcProbe(t *testing.T, proxy string) webrtcResult {
	t.Helper()

	var mu sync.Mutex
	var got *webrtcResult
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var res webrtcResult
			if err := json.NewDecoder(r.Body).Decode(&res); err == nil {
				mu.Lock()
				if got == nil {
					got = &res
				}
				mu.Unlock()
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(webrtcProbe))
	}))
	defer srv.Close()

	opts := structure.Options{Proxy: &proxy}
	opts.ApplyDefaults()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		chromeAllocatorOptions(opts, "")...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 90*time.Second)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL), chromedp.Sleep(10*time.Second)); err != nil {
		t.Fatalf("webrtc probe run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("the page never reported its ICE candidates")
	}
	return *got
}

// TestStealthWebRTCDoesNotLeakTheHostAddress is the regression guard for a leak
// that is not fingerprinting but deanonymisation: WebRTC negotiates over UDP and
// does not traverse an HTTP proxy, so a scanned page could open an
// RTCPeerConnection to a public STUN server and read the scanner's real public
// address straight past -proxy.
//
// The mitigation is gated on -proxy, so that is what this asserts. Note the flag
// name is the older --webrtc-ip-handling-policy; the --force- spelling was
// measured to have no effect at all on Chrome 150.
func TestStealthWebRTCDoesNotLeakTheHostAddress(t *testing.T) {
	requireStealthCheck(t)

	res := runWebrtcProbe(t, "http://127.0.0.1:1")
	t.Logf("with -proxy: tag=%s, %d candidate(s)", res.Tag, len(res.Candidates))
	for _, c := range res.Candidates {
		t.Logf("    %s", c)
	}
	if res.Tag == "NO_API" {
		t.Error("RTCPeerConnection is gone entirely: the leak is closed, but a browser " +
			"without WebRTC is itself unusual — the flag should keep the API present")
	}
	for _, c := range res.Candidates {
		if strings.Contains(c, "typ srflx") {
			t.Errorf("server-reflexive candidate leaked the host's public address past the proxy: %s", c)
		}
		if strings.Contains(c, "typ host") {
			t.Errorf("host candidate leaked past the proxy: %s", c)
		}
	}

	// Without -proxy the mitigation is deliberately not applied, on the grounds
	// that the scanned host sees the real address anyway. Recording it here keeps
	// that decision visible and, just as importantly, proves the probe above is
	// capable of observing a leak — a test that can only ever pass is worthless.
	bare := runWebrtcProbe(t, "")
	leaked := 0
	for _, c := range bare.Candidates {
		if strings.Contains(c, "typ srflx") {
			leaked++
		}
	}
	t.Logf("without -proxy (mitigation deliberately off): tag=%s, %d candidate(s), %d server-reflexive",
		bare.Tag, len(bare.Candidates), leaked)
	if leaked == 0 {
		t.Log("NOTE: no leak observed without -proxy either. Either the network blocks STUN or Chrome " +
			"changed its default — if the latter, the proxy gating is no longer load-bearing and this " +
			"test has stopped proving anything.")
	}
}

// TestStealthRemoteDetector runs the shipping configuration against
// rebrowser's hosted detector, which checks things a local page cannot observe —
// above all the Runtime.enable CDP leak.
//
// Separate opt-in from the rest of the harness because it needs the network and
// depends on a third party staying up:
//
//	WAPPAGO_STEALTH_REMOTE=1 go test ./cmd/ -run RemoteDetector -v
//
// Measured 2026-07-30 against Chrome 150: every test green, runtimeEnableLeak
// included. That is why chromedp is not patched — see the note below.
func TestStealthRemoteDetector(t *testing.T) {
	if os.Getenv("WAPPAGO_STEALTH_REMOTE") == "" {
		t.Skip("set WAPPAGO_STEALTH_REMOTE=1 to run the hosted detector (needs network)")
	}

	empty := ""
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		chromeAllocatorOptions(structure.Options{Proxy: &empty}, "")...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browserCtx, 120*time.Second)
	defer cancel()

	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("could not start Chrome: %v", err)
	}
	ident, err := resolveIdentity(ctx)
	if err != nil {
		t.Logf("resolveIdentity: %v", err)
	}

	var raw []byte
	if err := chromedp.Run(ctx,
		applyIdentity(ident, false),
		chromedp.Navigate("https://bot-detector.rebrowser.net/"),
		// The page runs its checks on load; the last one is a network call.
		chromedp.Sleep(8*time.Second),
		chromedp.Evaluate(`document.body.innerText`, &raw),
	); err != nil {
		t.Fatalf("detector run: %v", err)
	}

	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		t.Fatalf("decode page text: %v", err)
	}

	// The page marks each verdict with an emoji: green passed, red failed, white
	// means the test was not triggered (which is not a failure).
	var failed []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "🔴"), strings.HasPrefix(line, "❌"):
			failed = append(failed, line)
			t.Logf("FAIL %s", line)
		case strings.HasPrefix(line, "🟢"), strings.HasPrefix(line, "⚪️"):
			t.Logf("     %s", line)
		}
	}
	if len(failed) > 0 {
		t.Errorf("%d detector test(s) flagged the browser:\n%s", len(failed), strings.Join(failed, "\n"))
	}
}

// TestStealthFingerprintsAreStable is the counter-intuitive one, and the reason
// wappaGo does not copy Camoufox here.
//
// Camoufox randomises canvas, audio and WebGL because it wants a *different*
// identity per session, to defeat tracking. wappaGo's goal is the opposite: not
// to look unique, but to look ordinary. A fingerprint that changes between two
// reads in the same page is itself a well-known marker of an anti-fingerprinting
// tool — CreepJS reports canvas noise explicitly. A real Chrome returns the same
// bytes every time, so these surfaces must be present and stable, and are
// deliberately left unspoofed.
func TestStealthFingerprintsAreStable(t *testing.T) {
	requireStealthCheck(t)
	res, _ := runProbe(t)

	if res.CanvasHash == "" || strings.HasPrefix(res.CanvasHash, "error:") {
		t.Fatalf("no canvas 2D fingerprint: %q", res.CanvasHash)
	}
	if res.CanvasHash != res.CanvasHash2 {
		t.Errorf("canvas fingerprint changed between two reads (%s vs %s): looks like noise injection",
			res.CanvasHash, res.CanvasHash2)
	}

	if res.WebGL.Available {
		if res.WebGL.ImageHash == "" {
			t.Error("WebGL context exists but rendered no readable image")
		}
		if res.WebGL.ImageHash != res.WebGLImageHash2 {
			t.Errorf("WebGL image fingerprint changed between two reads (%s vs %s)",
				res.WebGL.ImageHash, res.WebGLImageHash2)
		}
	}

	if res.Audio.First.Error != "" {
		t.Fatalf("no audio fingerprint: %s", res.Audio.First.Error)
	}
	if res.Audio.First.SampleRate != 44100 {
		t.Errorf("OfflineAudioContext sampleRate = %.0f, want the requested 44100", res.Audio.First.SampleRate)
	}
	if res.Audio.First.MaxChannelCount == 0 {
		t.Error("destination.maxChannelCount is 0: no audio output device is being reported")
	}
	if res.Audio.First.Hash == "" {
		t.Error("audio rendered no samples")
	}
	if res.Audio.First.Hash != res.Audio.Second.Hash {
		t.Errorf("audio fingerprint changed between two reads (%s vs %s): looks like noise injection",
			res.Audio.First.Hash, res.Audio.Second.Hash)
	}
}

// TestStealthWebGLSurfaceIsCoherent checks the rest of the WebGL surface, which
// detectors cross-reference against the renderer string. A real adapter reports
// plausible limits and a full extension list; a stub or a blocked context does
// not.
func TestStealthWebGLSurfaceIsCoherent(t *testing.T) {
	requireStealthCheck(t)
	res, _ := runProbe(t)

	if !res.WebGL.Available {
		t.Fatalf("no WebGL context: %s", res.WebGL.Error)
	}
	if !res.WebGL.HasDebugRendererInfo {
		t.Error("WEBGL_debug_renderer_info is missing: a real Chrome exposes it, and its absence is itself unusual")
	}
	// Every desktop GL implementation Chrome ships with clears these easily; the
	// point is to catch a stubbed or software-blocked context, not to pin exact
	// hardware values.
	if res.WebGL.MaxTextureSize < 4096 {
		t.Errorf("MAX_TEXTURE_SIZE = %d, implausibly low for a desktop adapter", res.WebGL.MaxTextureSize)
	}
	if res.WebGL.MaxRenderbufferSize < 4096 {
		t.Errorf("MAX_RENDERBUFFER_SIZE = %d, implausibly low", res.WebGL.MaxRenderbufferSize)
	}
	if res.WebGL.ExtensionCount < 20 {
		t.Errorf("only %d WebGL extensions: a real desktop adapter exposes far more", res.WebGL.ExtensionCount)
	}
	if res.WebGL.MaxViewportDims == "" || res.WebGL.MaxViewportDims == "0x0" {
		t.Errorf("MAX_VIEWPORT_DIMS = %q", res.WebGL.MaxViewportDims)
	}
	if res.WebGL.GLVersion == "" || res.WebGL.ShadingLanguage == "" {
		t.Errorf("empty GL version strings: %q / %q", res.WebGL.GLVersion, res.WebGL.ShadingLanguage)
	}

	// Software rendering is a legitimate fallback on a GPU-less host, but it is
	// visible in the renderer string, so surface it rather than let it pass
	// silently as if the fingerprint were as good as a real adapter's.
	lower := strings.ToLower(res.WebGL.Renderer)
	for _, marker := range []string{"swiftshader", "basic render driver", "llvmpipe"} {
		if strings.Contains(lower, marker) {
			t.Logf("NOTE: software renderer in use (%q). Plausible on a GPU-less host, but weaker than a real adapter.", res.WebGL.Renderer)
		}
	}
}

// TestStealthNavigatorWebdriver pins that navigator.webdriver stays hidden and,
// just as importantly, that hiding it did not leave a non-native accessor
// behind — the exact tell Camoufox's documentation calls out.
func TestStealthNavigatorWebdriver(t *testing.T) {
	requireStealthCheck(t)
	res, _ := runProbe(t)

	if res.Webdriver == true {
		t.Error("navigator.webdriver is true")
	}
	if res.WebdriverIsNative != nil && !*res.WebdriverIsNative {
		t.Error("the navigator.webdriver accessor no longer reports [native code]")
	}
}

// majorFromSecChUa pulls the Google Chrome / Chromium major version out of a
// Sec-CH-UA header value, ignoring the deliberately-bogus "Not;A=Brand" entry.
func majorFromSecChUa(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		brand, version, ok := strings.Cut(part, ";v=")
		if !ok {
			continue
		}
		brand = strings.Trim(brand, `"`)
		if strings.Contains(strings.ToLower(brand), "not") {
			continue
		}
		return strings.Trim(version, `"`)
	}
	return ""
}

func boolPtr(b *bool) string {
	if b == nil {
		return "n/a"
	}
	return fmt.Sprint(*b)
}
