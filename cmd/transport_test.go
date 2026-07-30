package cmd

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// dialer used by the tests: a plain TCP dial, standing in for fastdialer.
func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// TestStealthTransportSendsChromeClientHello is the point of the whole file: the
// probe's TLS handshake must look like a browser's, not like Go's.
//
// It captures the ClientHello server-side and compares the cipher suite list
// against what crypto/tls sends. The two differ in count and in leading cipher,
// which is exactly what a JA3/JA4 hash keys on.
func TestStealthTransportSendsChromeClientHello(t *testing.T) {
	var got *tls.ClientHelloInfo
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			got = chi
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &stealthTransport{dial: plainDial, skipVerify: true}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request through the stealth transport failed: %v", err)
	}
	resp.Body.Close()

	if got == nil {
		t.Fatal("the server never saw a ClientHello")
	}
	chrome := got

	// Now the same request through crypto/tls, for comparison.
	got = nil
	std := &http.Client{Transport: &http.Transport{
		DialContext:       plainDial,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
	resp2, err := std.Get(srv.URL)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	resp2.Body.Close()
	if got == nil {
		t.Fatal("the server never saw the baseline ClientHello")
	}
	goHello := got

	t.Logf("uTLS      : %d cipher suites, first 0x%04x, ALPN %v",
		len(chrome.CipherSuites), chrome.CipherSuites[0], chrome.SupportedProtos)
	t.Logf("crypto/tls: %d cipher suites, first 0x%04x, ALPN %v",
		len(goHello.CipherSuites), goHello.CipherSuites[0], goHello.SupportedProtos)

	if len(chrome.CipherSuites) == len(goHello.CipherSuites) &&
		chrome.CipherSuites[0] == goHello.CipherSuites[0] {
		t.Error("the ClientHello is indistinguishable from Go's: uTLS is not being applied")
	}

	// A Chrome hello always offers h2 before http/1.1; a JA4 hash includes ALPN,
	// so a handshake that only offers http/1.1 would contradict the Chrome
	// User-Agent the probe sends.
	if len(chrome.SupportedProtos) == 0 || chrome.SupportedProtos[0] != "h2" {
		t.Errorf("ALPN = %v, want h2 first as Chrome sends", chrome.SupportedProtos)
	}
}

// TestStealthTransportSpeaksHTTP2 pins the second half of the fix: once ALPN has
// settled on h2 the request must actually be carried over HTTP/2, so the
// SETTINGS/WINDOW_UPDATE fingerprint is a real h2 client's. Falling back to
// HTTP/1.1 here would move the inconsistency rather than remove it.
func TestStealthTransportSpeaksHTTP2(t *testing.T) {
	var proto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &stealthTransport{dial: plainDial, skipVerify: true}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if proto != "HTTP/2.0" {
		t.Errorf("server saw %s, want HTTP/2.0", proto)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("client reports HTTP/%d.%d, want 2.x", resp.ProtoMajor, resp.ProtoMinor)
	}
}

// TestStealthTransportFallsBackToHTTP11 covers the other ALPN outcome: a server
// that does not offer h2 must still be scanned.
func TestStealthTransportFallsBackToHTTP11(t *testing.T) {
	var proto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		w.Write([]byte("ok"))
	}))
	srv.StartTLS() // no EnableHTTP2
	defer srv.Close()

	client := &http.Client{Transport: &stealthTransport{dial: plainDial, skipVerify: true}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if proto != "HTTP/1.1" {
		t.Errorf("server saw %s, want HTTP/1.1", proto)
	}
}

// TestSchemeRouterKeepsPlainHTTPOnTheStandardTransport: plain http has no
// handshake to disguise, and routing it through the TLS path would break it.
func TestSchemeRouterKeepsPlainHTTPOnTheStandardTransport(t *testing.T) {
	var proto string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := &http.Client{Transport: newHTTPTransport(plainDial, nil)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("plain http through the router failed: %v", err)
	}
	resp.Body.Close()
	if proto != "HTTP/1.1" {
		t.Errorf("server saw %s", proto)
	}
}

// TestNewHTTPTransportHonoursProxy: with a proxy the origin handshake happens
// inside a CONNECT tunnel we do not drive, so the standard transport is used and
// uTLS is deliberately out of the picture.
func TestNewHTTPTransportHonoursProxy(t *testing.T) {
	proxy := &http.Transport{DisableKeepAlives: true}
	if got := newHTTPTransport(plainDial, proxy); got != http.RoundTripper(proxy) {
		t.Errorf("proxy transport was not used: got %T", got)
	}
	if _, ok := newHTTPTransport(plainDial, nil).(*schemeRouter); !ok {
		t.Error("without a proxy the scheme router should be used")
	}
}
