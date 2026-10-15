package server

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ-TLS-001: the optional native TLS listener. Every certificate here is
// made in memory for the test (crypto/ecdsa P-256, or RSA-2048 where an
// RSA-key-exchange suite must be possible at all); nothing is committed.

// newTestCert returns a self-signed server certificate for 127.0.0.1 and
// localhost. rsaKey selects RSA-2048 instead of ECDSA P-256.
func newTestCert(t *testing.T, cn string, rsaKey bool) tls.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	var pub, priv any
	if rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv = &k.PublicKey, k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv = &k.PublicKey, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}

// startTLSServer serves h over TLS with the production config built from
// cert, on the production http.Server, and returns its address.
func startTLSServer(t *testing.T, h http.Handler, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(ln.Addr().String(), h, TLSConfig(cert))
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeTLS: %v", err)
		}
	})
	return ln.Addr().String()
}

// tlsClient trusts cert and speaks exactly TLS version v.
func tlsClient(cert tls.Certificate, v uint16) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: v, MaxVersion: v},
	}}
}

func send(t *testing.T, c *http.Client, method, url, body string, auth bool) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		req.SetBasicAuth("u", "p")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

// proves: REQ-TLS-001-AC1 — TLS 1.2 and 1.3 complete an authenticated PUT/GET round trip; plain HTTP gets Go's 400 and stores nothing
func TestTLSRoundTripAndPlainHTTPRefused(t *testing.T) {
	cert := newTestCert(t, "fscache-test", false)
	addr := startTLSServer(t, newTestHandler(t, Credentials{Username: "u", Password: "p"}), cert)

	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		c := tlsClient(cert, v)
		key := "https://" + addr + "/key-" + strconv.FormatUint(uint64(v), 16)
		if resp, _ := send(t, c, http.MethodPut, key, "payload", false); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: PUT without credentials = %d, want 401", tls.VersionName(v), resp.StatusCode)
		}
		resp, _ := send(t, c, http.MethodPut, key, "payload", true)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: PUT = %d, want 201", tls.VersionName(v), resp.StatusCode)
		}
		if resp.TLS == nil || resp.TLS.Version != v {
			t.Fatalf("%s: the response did not come over the requested TLS version (%v)", tls.VersionName(v), resp.TLS)
		}
		resp, body := send(t, c, http.MethodGet, key, "", true)
		if resp.StatusCode != http.StatusOK || body != "payload" {
			t.Fatalf("%s: GET = %d %q, want 200 payload", tls.VersionName(v), resp.StatusCode, body)
		}
	}

	// Plain HTTP to the TLS port: Go's server recognises an HTTP request in
	// place of a TLS record and answers 400 itself; the handler never runs.
	plain := &http.Client{Timeout: 10 * time.Second}
	resp, body := send(t, plain, http.MethodPut, "http://"+addr+"/plain-key", "payload", true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain HTTP PUT = %d %q, want 400", resp.StatusCode, body)
	}
	if !strings.Contains(body, "HTTPS server") {
		t.Errorf("plain HTTP body %q is not Go's 400 for an HTTP request to an HTTPS server", body)
	}
	if resp, _ := send(t, tlsClient(cert, tls.VersionTLS13), http.MethodGet, "https://"+addr+"/plain-key", "", true); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("after the plain-HTTP PUT, GET over TLS = %d, want 404 (nothing stored)", resp.StatusCode)
	}
}

// helloResult is what a server answered to one hand-built ClientHello.
type helloResult string

const (
	serverHello helloResult = "server hello"
	alert       helloResult = "alert"
	closed      helloResult = "closed"
)

// rawHello sends one hand-built ClientHello offering exactly version and
// suites, and reports the server's first answer. It is built by hand, not
// with crypto/tls, because a Go client filters what it offers (in FIPS mode
// it would never send a non-approved version or suite), and the point here
// is what the SERVER refuses.
func rawHello(t *testing.T, addr string, version uint16, suites ...uint16) helloResult {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	ext := func(b []byte, typ int, data []byte) []byte { return append(u16(u16(b, typ), len(data)), data...) }

	body := u16(nil, int(version))
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	body = append(body, 0) // no session id
	body = u16(body, 2*len(suites))
	for _, s := range suites {
		body = u16(body, int(s))
	}
	body = append(body, 1, 0) // compression: null only
	var exts []byte
	exts = ext(exts, 0x000a, []byte{0, 4, 0x00, 0x17, 0x00, 0x18})                                      // supported_groups: P-256, P-384
	exts = ext(exts, 0x000b, []byte{1, 0})                                                              // ec_point_formats: uncompressed
	exts = ext(exts, 0x000d, []byte{0, 10, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01}) // signature_algorithms
	exts = ext(exts, 0x0017, nil)                                                                       // extended_master_secret
	exts = ext(exts, 0xff01, []byte{0})                                                                 // renegotiation_info
	body = append(u16(body, len(exts)), exts...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append(u16([]byte{0x16, 0x03, 0x01}, len(hs)), hs...)
	if _, err := conn.Write(rec); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return closed
	}
	switch {
	case hdr[0] == 0x16 && hdr[5] == 0x02:
		return serverHello
	case hdr[0] == 0x15:
		return alert
	}
	t.Fatalf("unexpected first record % x", hdr)
	return ""
}

const (
	suiteECDHEECDSAAES128GCM = 0xc02b
	suiteECDHEECDSAAES128CBC = 0xc009
	suiteECDHEECDSACHACHA    = 0xcca9
	suiteECDHERSAAES128GCM   = 0xc02f
	suiteECDHERSAAES128CBC   = 0xc013
	suiteRSAAES128GCM        = 0x009c // RSA key exchange
	suiteRSAAES128CBC        = 0x002f // RSA key exchange
	suiteRSA3DES             = 0x000a
	suiteECDHERSA3DES        = 0xc012
)

// proves: REQ-TLS-001-AC2 — TLS 1.0, TLS 1.1, RSA key exchange and 3DES are refused; MinVersion is TLS 1.2, set explicitly, with Go's default suites
func TestTLSRefusesOldVersionsAndWeakSuites(t *testing.T) {
	cfg := TLSConfig(newTestCert(t, "cfg", false))
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2 set explicitly", cfg.MinVersion)
	}
	if cfg.CipherSuites != nil {
		t.Fatalf("CipherSuites = %v, want nil (Go's defaults)", cfg.CipherSuites)
	}
	if srv := NewHTTPServer(":0", http.NewServeMux(), cfg); srv.TLSConfig != cfg {
		t.Fatal("NewHTTPServer did not install the TLS config")
	}
	if srv := NewHTTPServer(":0", http.NewServeMux(), nil); srv.TLSConfig != nil {
		t.Fatal("NewHTTPServer with no TLS config must leave plain HTTP")
	}

	ecAddr := startTLSServer(t, http.NewServeMux(), newTestCert(t, "ec", false))
	rsaAddr := startTLSServer(t, http.NewServeMux(), newTestCert(t, "rsa", true))

	// Controls: the hand-built hello is a valid one, so a refusal below is the server's choice.
	if got := rawHello(t, ecAddr, tls.VersionTLS12, suiteECDHEECDSAAES128GCM); got != serverHello {
		t.Fatalf("control: TLS 1.2 ECDHE-ECDSA-AES128-GCM got %s, want %s", got, serverHello)
	}
	if got := rawHello(t, rsaAddr, tls.VersionTLS12, suiteECDHERSAAES128GCM); got != serverHello {
		t.Fatalf("control: TLS 1.2 ECDHE-RSA-AES128-GCM got %s, want %s", got, serverHello)
	}

	cases := []struct {
		name    string
		addr    string
		version uint16
		suites  []uint16
	}{
		{"TLS 1.0 only (ECDSA certificate)", ecAddr, tls.VersionTLS10, []uint16{suiteECDHEECDSAAES128CBC, suiteECDHEECDSAAES128GCM}},
		{"TLS 1.1 only (ECDSA certificate)", ecAddr, tls.VersionTLS11, []uint16{suiteECDHEECDSAAES128CBC, suiteECDHEECDSAAES128GCM}},
		{"TLS 1.0 only (RSA certificate)", rsaAddr, tls.VersionTLS10, []uint16{suiteECDHERSAAES128CBC, suiteRSAAES128CBC}},
		{"TLS 1.1 only (RSA certificate)", rsaAddr, tls.VersionTLS11, []uint16{suiteECDHERSAAES128CBC, suiteRSAAES128CBC}},
		{"TLS 1.2, RSA key exchange only", rsaAddr, tls.VersionTLS12, []uint16{suiteRSAAES128GCM, suiteRSAAES128CBC}},
		{"TLS 1.2, 3DES only", rsaAddr, tls.VersionTLS12, []uint16{suiteRSA3DES, suiteECDHERSA3DES}},
	}
	for _, c := range cases {
		if got := rawHello(t, c.addr, c.version, c.suites...); got != alert {
			t.Errorf("%s: server answered %s, want an alert", c.name, got)
		}
	}
}

// proves: REQ-TLS-001-AC2 — with GODEBUG=tls10server=1 set, a TLS 1.0 or 1.1 hello is still refused
//
// Go 1.27 removed the tls10server setting (internal/godebugs: Removed: 27),
// so today it changes nothing whether or not MinVersion is set; the case
// is kept so a toolchain that honoured it again would still be held at
// TLS 1.2 by the explicit MinVersion.
func TestTLSFloorHoldsUnderTLS10ServerGODEBUG(t *testing.T) {
	godebug := "tls10server=1"
	if cur := os.Getenv("GODEBUG"); cur != "" {
		godebug = cur + "," + godebug // keep fips140=only in the fips140-only job
	}
	t.Setenv("GODEBUG", godebug)
	addr := startTLSServer(t, http.NewServeMux(), newTestCert(t, "ec", false))
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if got := rawHello(t, addr, v, suiteECDHEECDSAAES128CBC, suiteECDHEECDSAAES128GCM); got != alert {
			t.Errorf("GODEBUG=%s: %s hello got %s, want an alert", godebug, tls.VersionName(v), got)
		}
	}
	if got := rawHello(t, addr, tls.VersionTLS12, suiteECDHEECDSAAES128GCM); got != serverHello {
		t.Errorf("control under GODEBUG=%s: TLS 1.2 got %s, want %s", godebug, got, serverHello)
	}
}

// proves: REQ-TLS-001-AC5 — in FIPS mode a TLS 1.2 ChaCha20-Poly1305 hello is refused and TLS 1.3 negotiates AES-GCM with a P-256 certificate
//
// The narrowing is Go's FIPS mode, not our config: outside FIPS mode the
// same ChaCha20 hello is accepted, which the test asserts so it is never
// vacuous in the ordinary jobs. It runs in FIPS mode in ci.yml's
// fips140-only job (GOFIPS140=v1.0.0 GODEBUG=fips140=only), and locally
// with GOFIPS140=v1.0.0 alone (the -fips build's default runtime mode).
func TestTLSFIPSModeNarrowsSuites(t *testing.T) {
	cert := newTestCert(t, "fips", false)
	addr := startTLSServer(t, newTestHandler(t, Credentials{}), cert)

	chacha := rawHello(t, addr, tls.VersionTLS12, suiteECDHEECDSACHACHA)
	if fips140.Enabled() {
		if chacha != alert {
			t.Errorf("FIPS mode: TLS 1.2 ChaCha20-Poly1305 hello got %s, want an alert", chacha)
		}
	} else if chacha != serverHello {
		t.Errorf("outside FIPS mode the ChaCha20-Poly1305 hello got %s, want %s (the narrowing must come from FIPS mode)", chacha, serverHello)
	}

	resp, _ := send(t, tlsClient(cert, tls.VersionTLS13), http.MethodGet, "https://"+addr+"/healthz", "", false)
	if resp.StatusCode != http.StatusOK || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS 1.3 /healthz = %d (%v), want 200 over TLS 1.3", resp.StatusCode, resp.TLS)
	}
	if fips140.Enabled() {
		if s := resp.TLS.CipherSuite; s != tls.TLS_AES_128_GCM_SHA256 && s != tls.TLS_AES_256_GCM_SHA384 {
			t.Errorf("FIPS mode: TLS 1.3 negotiated %s, want an AES-GCM suite", tls.CipherSuiteName(s))
		}
	}
}

// proves: REQ-TLS-001-AC9 — with TLS on only HTTP/1.1 is negotiated: an h2-only ALPN offer fails, an h2 + http/1.1 offer gets http/1.1
func TestTLSOffersOnlyHTTP11(t *testing.T) {
	cert := newTestCert(t, "alpn", false)
	cfg := TLSConfig(cert)
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos = %v, want [http/1.1]", cfg.NextProtos)
	}
	for _, c := range []*tls.Config{cfg, nil} {
		srv := NewHTTPServer(":0", http.NewServeMux(), c)
		if srv.Protocols == nil || !srv.Protocols.HTTP1() || srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2() {
			t.Fatalf("Protocols = %v, want HTTP/1 only", srv.Protocols)
		}
	}

	addr := startTLSServer(t, newTestHandler(t, Credentials{}), cert)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	dial := func(protos ...string) (tls.ConnectionState, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
			&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: protos})
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState(), nil
	}
	if st, err := dial("h2"); err == nil {
		t.Errorf("an h2-only ALPN offer completed a handshake (negotiated %q), want a failed ALPN negotiation", st.NegotiatedProtocol)
	}
	st, err := dial("h2", "http/1.1")
	if err != nil {
		t.Fatalf("h2 + http/1.1 offer: %v", err)
	}
	if st.NegotiatedProtocol != "http/1.1" {
		t.Errorf("h2 + http/1.1 offer negotiated %q, want http/1.1", st.NegotiatedProtocol)
	}

	// A Go client that tries HTTP/2 first still talks HTTP/1.1.
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	resp, _ := send(t, c, http.MethodGet, "https://"+addr+"/healthz", "", false)
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 || resp.ProtoMinor != 1 {
		t.Errorf("/healthz = %d over %s, want 200 over HTTP/1.1", resp.StatusCode, resp.Proto)
	}
}

// listener is one way of serving: plain HTTP or TLS, through the
// production http.Server.
type listener struct {
	name   string
	tls    bool
	cert   tls.Certificate
	client *http.Client
}

func (l listener) start(t *testing.T, h http.Handler) string {
	t.Helper()
	if l.tls {
		return "https://" + startTLSServer(t, h, l.cert)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(ln.Addr().String(), h, nil)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return "http://" + ln.Addr().String()
}

// rawStatus writes raw request bytes on a fresh connection (TLS when
// base is https) while reading the response, and returns its status code.
// Writing and reading run side by side because the server answers an
// oversized header before it has read all of it.
func (l listener) rawStatus(t *testing.T, base string, req []byte) int {
	t.Helper()
	addr := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	var conn net.Conn
	var err error
	if l.tls {
		pool := x509.NewCertPool()
		pool.AddCert(l.cert.Leaf)
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
			&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = conn.Write(req) }()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s: reading the response: %v", l.name, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// proves: REQ-TLS-001-AC9 — the TLS listener has the plain listener's request bounds: header size, body limit, upload concurrency, timeouts
func TestTLSListenerHasPlainListenerBounds(t *testing.T) {
	cert := newTestCert(t, "bounds", false)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	tlsClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	listeners := []listener{
		{name: "plain", client: &http.Client{Timeout: 10 * time.Second}},
		{name: "tls", tls: true, cert: cert, client: tlsClient},
	}

	plainSrv, tlsSrv := NewHTTPServer(":0", http.NewServeMux(), nil), NewHTTPServer(":0", http.NewServeMux(), TLSConfig(cert))
	if plainSrv.ReadHeaderTimeout != tlsSrv.ReadHeaderTimeout || plainSrv.ReadTimeout != tlsSrv.ReadTimeout ||
		plainSrv.WriteTimeout != tlsSrv.WriteTimeout || plainSrv.IdleTimeout != tlsSrv.IdleTimeout ||
		plainSrv.MaxHeaderBytes != tlsSrv.MaxHeaderBytes {
		t.Errorf("timeouts or header bound differ between the plain and the TLS server")
	}

	for _, l := range listeners {
		t.Run(l.name, func(t *testing.T) {
			// Header size: a header block past Go's 1 MiB default gets 431.
			base := l.start(t, newTestHandlerWithUploadLimit(t, 1))
			big := "PUT /hdr-key HTTP/1.1\r\nHost: x\r\nX-Big: " + strings.Repeat("a", http.DefaultMaxHeaderBytes+8192) + "\r\nContent-Length: 1\r\n\r\nx"
			if got := l.rawStatus(t, base, []byte(big)); got != http.StatusRequestHeaderFieldsTooLarge {
				t.Errorf("oversized header: %d, want 431", got)
			}
			if resp, _ := send(t, l.client, http.MethodGet, base+"/hdr-key", "", false); resp.StatusCode != http.StatusNotFound {
				t.Errorf("the refused PUT stored something: GET = %d", resp.StatusCode)
			}

			// Body limit: past MaxBodyBytes is 413 and stores nothing.
			bodyBase := l.start(t, newTestHandlerWithMaxBody(t, Credentials{}, 16))
			if resp, _ := send(t, l.client, http.MethodPut, bodyBase+"/body-key", strings.Repeat("b", 17), false); resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("oversized body: %d, want 413", resp.StatusCode)
			}
			if resp, _ := send(t, l.client, http.MethodGet, bodyBase+"/body-key", "", false); resp.StatusCode != http.StatusNotFound {
				t.Errorf("the refused body was stored: GET = %d", resp.StatusCode)
			}

			// Upload concurrency: with a bound of 1 and one slow upload in
			// flight, the next PUT gets 429 with Retry-After.
			slow := &slowBody{release: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(slow.release) }) }
			t.Cleanup(release)
			first := make(chan int, 1)
			go func() {
				req, _ := http.NewRequest(http.MethodPut, base+"/slow-key", slow)
				resp, err := l.client.Do(req)
				if err != nil {
					first <- 0
					return
				}
				_ = resp.Body.Close()
				first <- resp.StatusCode
			}()
			time.Sleep(300 * time.Millisecond)
			resp, _ := send(t, l.client, http.MethodPut, base+"/refused-key", "body", false)
			if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
				t.Errorf("second PUT while the slot is busy: %d (Retry-After %q), want 429 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
			}
			release()
			if got := <-first; got != http.StatusCreated {
				t.Errorf("the slow upload ended with %d, want 201", got)
			}
		})
	}
}
