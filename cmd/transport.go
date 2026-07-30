package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// The raw HTTP probe is the first thing a scanned host sees — it runs before
// Chrome on every target — and Go's crypto/tls ClientHello does not resemble a
// browser's at all. Cipher order, extension order, supported groups and
// signature algorithms all differ, which is what JA3/JA4 hashes capture. Sending
// a perfect Chrome User-Agent over a Go TLS handshake advertises the tool on the
// very first packet, before a single header is read.
//
// stealthTransport dials with a Chrome ClientHello via uTLS and then speaks
// whichever protocol ALPN settled on, so the HTTP/2 SETTINGS/WINDOW_UPDATE
// fingerprint comes from x/net/http2 rather than from a downgrade to HTTP/1.1.
//
// chromeHello is pinned rather than set to HelloChrome_Auto.
//
// Auto is an alias for whatever the uTLS build considers newest (133 in v1.8.2),
// so a dependency bump silently changes the handshake this tool presents. That
// matters because the handshake and the claimed User-Agent are correlated by
// bot-protection vendors: measured against a DataDome-protected origin, the
// 133 hello paired with a User-Agent claiming Chrome 150 was refused 4/4 with
// HTTP 403 and a captcha page, while the same hello paired with a matching
// Chrome 133 User-Agent passed 2/2. Which profile ships is therefore a decision
// to make deliberately and to keep in step with helloChromeMajor below.
var chromeHello = utls.HelloChrome_133

// helloChromeMajor is the Chrome major version chromeHello imitates.
//
// The identity presented to a host is capped to this, because claiming a browser
// newer than the handshake we can actually produce is an inconsistency we create
// ourselves. uTLS has no profile for Chrome 150, so a scanner running on a newer
// Chrome presents this version instead of its own.
const helloChromeMajor = "133"

// stealthTransport is a RoundTripper that gives every request a browser-shaped
// TLS handshake.
//
// It dispatches per connection rather than per host because ALPN is only known
// once the handshake completes: probing a host first to learn its protocol would
// double the handshake count, which works against the pacing wappaGo already
// does to stay under rate limits. DisableKeepAlives is on for the probe anyway,
// so a connection serves exactly one request and the one-shot transports below
// cost an allocation, not a round trip.
type stealthTransport struct {
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	skipVerify bool
}

func (t *stealthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("stealthTransport handles https only, got %q", req.URL.Scheme)
	}

	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(req.URL.Hostname(), "443")
	}

	raw, err := t.dial(req.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	conn := utls.UClient(raw, &utls.Config{
		ServerName:         req.URL.Hostname(),
		InsecureSkipVerify: t.skipVerify,
	}, chromeHello)
	if err := conn.HandshakeContext(req.Context()); err != nil {
		raw.Close()
		return nil, err
	}

	if conn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		cc, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return cc.RoundTrip(req)
	}

	// HTTP/1.1 over the connection just established. Going through
	// http.Transport rather than writing the request by hand keeps the
	// behaviour the probe relies on — notably Go's transparent gzip, which
	// Do() depends on and which the response-reading path in root.go handles
	// the failure mode of.
	h1 := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
	}
	resp, err := h1.RoundTrip(req)
	if err != nil {
		conn.Close()
	}
	return resp, err
}

// newHTTPTransport returns the transport the probe should use.
//
// Plain HTTP has no handshake to disguise, and a proxy means the origin
// handshake happens inside a CONNECT tunnel we do not drive, so both fall back
// to the standard transport. Only direct https gets the browser ClientHello.
func newHTTPTransport(dial func(ctx context.Context, network, addr string) (net.Conn, error), proxy *http.Transport) http.RoundTripper {
	if proxy != nil {
		return proxy
	}
	plain := &http.Transport{
		DialContext:       dial,
		DisableKeepAlives: true,
	}
	return &schemeRouter{
		http:  plain,
		https: &stealthTransport{dial: dial, skipVerify: true},
	}
}

// schemeRouter sends https through the uTLS path and everything else through the
// standard transport.
type schemeRouter struct {
	http  http.RoundTripper
	https http.RoundTripper
}

func (r *schemeRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.EqualFold(req.URL.Scheme, "https") {
		return r.https.RoundTrip(req)
	}
	return r.http.RoundTrip(req)
}
