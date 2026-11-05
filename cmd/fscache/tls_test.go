package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// REQ-TLS-001: FSCACHE_TLS_CERT / FSCACHE_TLS_KEY. Certificates and keys
// are made in memory for each test (ECDSA P-256) and written to
// t.TempDir(); no key or certificate file is committed.

// testPair is one generated certificate and key, written to disk.
type testPair struct {
	certPath, keyPath string
	leaf              *x509.Certificate
	keyFile           []byte // the key file exactly as written
	keyBody           string // the key's base64 body, newlines removed
	marker            string
}

// writePair generates a P-256 certificate and key and writes them as PEM.
// The key file carries marker in a PEM header and in a preamble line, so a
// leak of any part of the file is detectable, not only of the body.
func writePair(t *testing.T, dir, name, marker string) testPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"X-Test-Marker": marker}, Bytes: pkcs8})
	keyFile := append([]byte("fscache-test-preamble "+marker+"\n"), keyBlock...)
	p := testPair{
		certPath: filepath.Join(dir, name+".crt"),
		keyPath:  filepath.Join(dir, name+".key"),
		leaf:     leaf,
		keyFile:  keyFile,
		marker:   marker,
	}
	for _, line := range strings.Split(string(keyBlock), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") && !strings.Contains(line, ":") {
			p.keyBody += line
		}
	}
	if err := os.WriteFile(p.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyPath, keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// leaks returns a description of the first piece of the key found in s:
// the marker, or any 16-byte window of the key's base64 body (checked
// as-is and with JSON-escaped newlines removed).
func (p testPair) leaks(s string) string {
	flat := strings.NewReplacer(`\n`, "", "\n", "").Replace(s)
	for _, hay := range []string{s, flat} {
		if strings.Contains(hay, p.marker) {
			return "the marker " + p.marker
		}
		for i := 0; i+16 <= len(p.keyBody); i++ {
			if w := p.keyBody[i : i+16]; strings.Contains(hay, w) {
				return "the key-body window " + w
			}
		}
	}
	return ""
}

func tlsTestClient(leaf *x509.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true, // every request is a new connection and a new handshake
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

// getTLS fetches url and returns the status, the body and the certificate
// the server presented.
func getTLS(t *testing.T, c *http.Client, url string) (int, string, *x509.Certificate) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Errorf("GET %s: %v", url, err)
		return 0, "", nil
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read %s: %v", url, err)
	}
	return resp.StatusCode, string(b), resp.TLS.PeerCertificates[0]
}

// runMainCaptured runs runMain with os.Stdout sent to a file and returns
// the exit code and everything the process logged.
func runMainCaptured(t *testing.T) (int, string) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = f
	code := runMain()
	os.Stdout = orig
	_ = f.Close()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(b)
}

// badPairCase is one refused TLS configuration and what its error names.
type badPairCase struct {
	name  string
	env   map[string]string
	names []string // variables and paths the error must name
	files []string // files whose contents must not appear in the error
}

func badPairCases(t *testing.T) []badPairCase {
	t.Helper()
	dir := t.TempDir()
	a := writePair(t, dir, "a", "MARKER-A-7f3c19")
	b := writePair(t, dir, "b", "MARKER-B-2d84e6")
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notPEM := write("not-pem.txt", "this is not PEM at all CONTENT-MARKER-91ab\n")
	badCert := write("bad-cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("CONTENT-MARKER-cert-not-der")})))
	badKey := write("bad-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("CONTENT-MARKER-key-not-der")})))
	missing := filepath.Join(dir, "does-not-exist.pem")
	const C, K = "FSCACHE_TLS_CERT", "FSCACHE_TLS_KEY"
	return []badPairCase{
		{"only the certificate set", map[string]string{C: a.certPath}, []string{C, K, a.certPath}, nil},
		{"only the key set", map[string]string{K: a.keyPath}, []string{C, K, a.keyPath}, nil},
		{"certificate path does not exist", map[string]string{C: missing, K: a.keyPath}, []string{C, missing}, []string{a.keyPath}},
		{"key path does not exist", map[string]string{C: a.certPath, K: missing}, []string{K, missing}, []string{a.certPath}},
		{"key path is a directory", map[string]string{C: a.certPath, K: dir}, []string{K, dir}, []string{a.certPath}},
		{"certificate file is not PEM", map[string]string{C: notPEM, K: a.keyPath}, []string{C, notPEM}, []string{notPEM, a.keyPath}},
		{"key file is not PEM", map[string]string{C: a.certPath, K: notPEM}, []string{K, notPEM}, []string{notPEM, a.certPath}},
		{"certificate file holds a key, not a certificate", map[string]string{C: a.keyPath, K: a.keyPath}, []string{C, a.keyPath}, []string{a.keyPath}},
		{"key file holds a certificate, not a key", map[string]string{C: a.certPath, K: a.certPath}, []string{K, a.certPath}, []string{a.certPath}},
		{"certificate block does not parse", map[string]string{C: badCert, K: a.keyPath}, []string{C, badCert}, []string{badCert, a.keyPath}},
		{"key block does not parse", map[string]string{C: a.certPath, K: badKey}, []string{K, badKey}, []string{badKey, a.certPath}},
		{"certificate and key from different pairs", map[string]string{C: a.certPath, K: b.keyPath}, []string{C, K, a.certPath, b.keyPath}, []string{a.certPath, b.keyPath}},
	}
}

// unreadableCase is the "key file the process cannot read" case. A process
// running as root reads a mode-0000 file anyway, so there it is skipped
// (the directory case above still covers an unreadable key path).
func unreadableCase(t *testing.T) (badPairCase, bool) {
	t.Helper()
	dir := t.TempDir()
	a := writePair(t, dir, "u", "MARKER-U-55c0aa")
	if err := os.Chmod(a.keyPath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(a.keyPath, 0o600) })
	if _, err := os.ReadFile(a.keyPath); err == nil {
		return badPairCase{}, false
	}
	return badPairCase{"key file the process cannot read",
		map[string]string{"FSCACHE_TLS_CERT": a.certPath, "FSCACHE_TLS_KEY": a.keyPath},
		[]string{"FSCACHE_TLS_KEY", a.keyPath}, []string{a.certPath}}, true
}

// checkRefusal asserts the error names what it must and quotes no file.
func checkRefusal(t *testing.T, c badPairCase, msg string) {
	t.Helper()
	for _, n := range c.names {
		if !strings.Contains(msg, n) {
			t.Errorf("error %q does not name %q", msg, n)
		}
	}
	for _, f := range c.files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := string(content)
		for _, line := range strings.Split(s, "\n") {
			if len(line) >= 16 && !strings.HasPrefix(line, "-----") {
				for i := 0; i+16 <= len(line); i++ {
					if strings.Contains(msg, line[i:i+16]) {
						t.Errorf("error %q quotes the contents of %s (%q)", msg, f, line[i:i+16])
						return
					}
				}
			}
		}
	}
	if strings.Contains(msg, "MARKER") {
		t.Errorf("error %q quotes a file's marker", msg)
	}
}

func allBadPairCases(t *testing.T) []badPairCase {
	cases := badPairCases(t)
	if c, ok := unreadableCase(t); ok {
		cases = append(cases, c)
	} else {
		t.Log("running as a user that reads mode-0000 files: the unreadable-file case is covered by the directory case only")
	}
	return cases
}

// proves: REQ-TLS-001-AC3 — a one-sided, missing, unreadable, non-PEM, unparseable or mismatched pair exits non-zero naming the variable(s) and path, and an absent data directory stays absent
func TestTLSBadPairRefusedAndDataDirNotCreated(t *testing.T) {
	for _, c := range allBadPairCases(t) {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dir := filepath.Join(t.TempDir(), "never-created")
			t.Setenv("FSCACHE_DATA_DIR", dir)
			t.Setenv("FSCACHE_ADDR", freePort(t))
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			code, out := runMainCaptured(t)
			if code == 0 {
				t.Fatal("the server started")
			}
			var rec struct {
				Msg   string `json:"msg"`
				Error string `json:"error"`
			}
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "fscache: fatal" {
					break
				}
			}
			if rec.Msg != "fscache: fatal" {
				t.Fatalf("no fatal line in %q", out)
			}
			checkRefusal(t, c, rec.Error)
			checkRefusal(t, badPairCase{files: c.files}, out)
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Errorf("the data directory was created (stat err = %v)", err)
			}
		})
	}
}

// proves: REQ-TLS-001-AC3 — the same refusals leave an existing data directory byte-identical, with no unclean-shutdown marker
func TestTLSBadPairLeavesExistingDataDirIdentical(t *testing.T) {
	for _, c := range allBadPairCases(t) {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dir := seedExistingDataDir(t)
			before := snapshotTree(t, dir)
			t.Setenv("FSCACHE_DATA_DIR", dir)
			t.Setenv("FSCACHE_ADDR", freePort(t))
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			err := serve(context.Background(), quietLogger(), nil)
			if err == nil {
				t.Fatal("serve accepted the configuration")
			}
			checkRefusal(t, c, err.Error())
			after := snapshotTree(t, dir)
			if !reflect.DeepEqual(before, after) {
				t.Errorf("data dir changed:\nbefore %v\nafter  %v", before, after)
			}
			if _, ok := after[".unclean-shutdown"]; ok {
				t.Error("an unclean-shutdown marker was written")
			}
		})
	}
}

// captureStderr sends everything written to os.Stderr, and the standard
// logger (where an http.Server with no ErrorLog writes its TLS handshake
// errors), to a file for the rest of the test, and returns a reader of
// what was captured so far.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	origStderr, origLog := os.Stderr, log.Writer()
	os.Stderr = f
	log.SetOutput(f)
	t.Cleanup(func() {
		os.Stderr = origStderr
		log.SetOutput(origLog)
		_ = f.Close()
	})
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// clientHello is a hand-built TLS ClientHello record offering exactly
// version and suites.
func clientHello(version uint16, suites ...uint16) []byte {
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	body := u16(nil, int(version))
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // no session id
	body = u16(body, 2*len(suites))
	for _, s := range suites {
		body = u16(body, int(s))
	}
	body = append(body, 1, 0) // null compression
	exts := []byte{0x00, 0x0a, 0, 4, 0, 2, 0x00, 0x17, 0x00, 0x0d, 0, 4, 0, 2, 0x04, 0x03}
	body = append(u16(body, len(exts)), exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(u16([]byte{0x16, 0x03, 0x01}, len(hs)), hs...)
}

// induceHandshakeErrors makes the TLS server at addr log four handshake
// errors: a hello offering nothing it accepts (3DES only), a plain-HTTP
// request, a truncated ClientHello, and a client that closes before
// sending anything.
func induceHandshakeErrors(t *testing.T, addr string) {
	t.Helper()
	exchange := func(payload []byte, read bool) {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if len(payload) > 0 {
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		if read {
			_, _ = io.ReadAll(conn)
		}
	}
	exchange(clientHello(tls.VersionTLS12, 0x000a), true) // TLS_RSA_WITH_3DES_EDE_CBC_SHA only
	exchange([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), true)
	exchange(clientHello(tls.VersionTLS12, 0xc02b)[:20], false)
	exchange(nil, false)
}

// proves: REQ-TLS-001-AC4 — neither the key's marker nor any 16-byte window of its body appears in the logs, stderr (Go's TLS handshake-error log included), the startup error, /metrics or /statusz, in a valid start or a refused one
func TestTLSKeyNeverAppearsInOutput(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "valid", "MARKER-KEY-c41d0e")

	t.Run("valid start", func(t *testing.T) {
		clearEnv(t)
		freshRegistry(t)
		t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
		t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
		t.Setenv("FSCACHE_TLS_CERT", p.certPath)
		t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
		stderr := captureStderr(t)
		var logs syncBuffer
		var surfaces []string
		ctx, cancel := context.WithCancel(context.Background())
		err := serve(ctx, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), func() {
			defer cancel()
			addr := boundAddr(t, &logs)
			c := tlsTestClient(p.leaf)
			for _, path := range []string{"/metrics", "/statusz", "/"} {
				code, body, _ := getTLS(t, c, "https://"+addr+path)
				if code != http.StatusOK {
					t.Errorf("%s = %d, want 200", path, code)
				}
				surfaces = append(surfaces, path+"\n"+body)
			}
			induceHandshakeErrors(t, addr)
			// The server logs handshake errors from its connection
			// goroutines; wait for all four before shutting it down.
			for deadline := time.Now().Add(5 * time.Second); strings.Count(logs.String(), "TLS handshake error") < 4 && time.Now().Before(deadline); {
				time.Sleep(20 * time.Millisecond)
			}
		})
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
		if len(surfaces) != 3 {
			t.Fatalf("captured %d surfaces, want 3", len(surfaces))
		}
		// Go's http.Server error log (TLS handshake errors) goes through the
		// process logger at DEBUG, never to bare stderr: four induced errors,
		// four DEBUG records, none on stderr. That makes the check below
		// cover the path those lines really take, and proves it non-empty.
		var handshake int
		for _, line := range strings.Split(logs.String(), "\n") {
			var rec struct{ Level, Msg string }
			if json.Unmarshal([]byte(line), &rec) == nil && strings.Contains(rec.Msg, "http: TLS handshake error") {
				handshake++
				if rec.Level != "DEBUG" {
					t.Errorf("a TLS handshake error was logged at %s, want DEBUG: %s", rec.Level, line)
				}
			}
		}
		if handshake < 4 {
			t.Fatalf("the log holds %d TLS handshake-error records, want at least 4 (one per induced error):\n%s", handshake, logs.String())
		}
		errLog := stderr()
		if strings.Contains(errLog, "TLS handshake error") {
			t.Errorf("TLS handshake errors reached bare stderr:\n%s", errLog)
		}
		for _, s := range append(surfaces, logs.String(), errLog) {
			if leak := p.leaks(s); leak != "" {
				t.Errorf("%s appears in:\n%s", leak, s)
			}
		}
	})

	t.Run("handshake errors stay out of an INFO-level log and stderr", func(t *testing.T) {
		clearEnv(t)
		freshRegistry(t)
		t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
		t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
		t.Setenv("FSCACHE_TLS_CERT", p.certPath)
		t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
		stderr := captureStderr(t)
		var logs syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		err := serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
			defer cancel()
			induceHandshakeErrors(t, boundAddr(t, &logs))
			time.Sleep(300 * time.Millisecond)
		})
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
		for _, s := range []string{logs.String(), stderr()} {
			if strings.Contains(s, "TLS handshake error") {
				t.Errorf("a handshake error was written at the default level:\n%s", s)
			}
		}
	})

	t.Run("start refused for a mismatch", func(t *testing.T) {
		other := writePair(t, dir, "other", "MARKER-OTHER-9e2b77")
		clearEnv(t)
		freshRegistry(t)
		t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
		t.Setenv("FSCACHE_ADDR", freePort(t))
		t.Setenv("FSCACHE_TLS_CERT", other.certPath)
		t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
		stderr := captureStderr(t)
		var logs bytes.Buffer
		err := serve(context.Background(), slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
		if err == nil {
			t.Fatal("serve accepted a mismatched pair")
		}
		code, out := runMainCaptured(t)
		if code == 0 {
			t.Fatal("runMain exited 0 for a mismatched pair")
		}
		for _, s := range []string{err.Error(), logs.String(), out, stderr()} {
			if leak := p.leaks(s); leak != "" {
				t.Errorf("%s appears in %q", leak, s)
			}
		}
	})
}

// proves: REQ-TLS-001-AC4 — a key parser that panics is contained: the start is refused with a plain error, and no stack trace or key bytes are printed
func TestTLSKeyParserPanicIsContained(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "contained", "MARKER-PANIC-3a6f50")
	orig := x509KeyPair
	x509KeyPair = func(certPEM, keyPEM []byte) (tls.Certificate, error) {
		panic("parser failure on input: " + string(keyPEM))
	}
	defer func() { x509KeyPair = orig }()

	clearEnv(t)
	freshRegistry(t)
	dataDir := filepath.Join(t.TempDir(), "never-created")
	t.Setenv("FSCACHE_DATA_DIR", dataDir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	t.Setenv("FSCACHE_TLS_CERT", p.certPath)
	t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
	code, out := runMainCaptured(t)
	if code == 0 {
		t.Fatal("the server started with a panicking key parser")
	}
	if !strings.Contains(out, "FSCACHE_TLS_KEY") || !strings.Contains(out, p.keyPath) {
		t.Errorf("the refusal does not name FSCACHE_TLS_KEY and the path: %q", out)
	}
	for _, s := range []string{"goroutine ", "panic", "parser failure"} {
		if strings.Contains(out, s) {
			t.Errorf("the output carries %q (a stack trace or the panic value): %q", s, out)
		}
	}
	if leak := p.leaks(out); leak != "" {
		t.Errorf("%s appears in %q", leak, out)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("the data directory was created (stat err = %v)", err)
	}
}

// proves: REQ-TLS-001-AC6 — the certificate is read once at startup: a file replaced on disk is presented only after a restart
func TestTLSCertificateReadOnceAtStartup(t *testing.T) {
	dir := t.TempDir()
	old := writePair(t, dir, "live", "MARKER-OLD-1b2c3d")
	replDir := t.TempDir()
	repl := writePair(t, replDir, "live", "MARKER-NEW-4e5f6a")
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	t.Setenv("FSCACHE_TLS_CERT", old.certPath)
	t.Setenv("FSCACHE_TLS_KEY", old.keyPath)

	both := x509.NewCertPool()
	both.AddCert(old.leaf)
	both.AddCert(repl.leaf)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: both, MinVersion: tls.VersionTLS12},
	}}

	var logs syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	err := serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
		defer cancel()
		addr := boundAddr(t, &logs)
		if _, _, got := getTLS(t, c, "https://"+addr+"/healthz"); got == nil || got.SerialNumber.Cmp(old.leaf.SerialNumber) != 0 {
			t.Fatalf("first connection: presented %v, want the original certificate", got)
		}
		for _, f := range [][2]string{{repl.certPath, old.certPath}, {repl.keyPath, old.keyPath}} {
			b, err := os.ReadFile(f[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f[1], b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, got := getTLS(t, c, "https://"+addr+"/healthz"); got == nil || got.SerialNumber.Cmp(old.leaf.SerialNumber) != 0 {
			t.Errorf("new connection after the files were replaced: presented %v, want the original certificate until a restart", got)
		}
	})
	if err != nil {
		t.Fatalf("first serve: %v", err)
	}

	freshRegistry(t)
	var logs2 syncBuffer
	ctx, cancel = context.WithCancel(context.Background())
	err = serve(ctx, slog.New(slog.NewJSONHandler(&logs2, nil)), func() {
		defer cancel()
		addr := boundAddr(t, &logs2)
		if _, _, got := getTLS(t, c, "https://"+addr+"/healthz"); got == nil || got.SerialNumber.Cmp(repl.leaf.SerialNumber) != 0 {
			t.Errorf("after the restart: presented %v, want the replacement certificate", got)
		}
	})
	if err != nil {
		t.Fatalf("second serve: %v", err)
	}
}

// proves: REQ-TLS-001-AC8 — the startup record ("fscache: starting") carries tls=enabled or tls=disabled beside auth and fips140
//
// The record is found by its message, not by position: an unknown-variable
// warning (set here on purpose) or a reconcile warning is logged before it.
func TestStartupLineCarriesTLSState(t *testing.T) {
	p := writePair(t, t.TempDir(), "startup", "MARKER-START-0d0e0f")
	for _, tc := range []struct {
		want string
		env  map[string]string
	}{
		{"disabled", nil},
		{"enabled", map[string]string{"FSCACHE_TLS_CERT": p.certPath, "FSCACHE_TLS_KEY": p.keyPath}},
	} {
		t.Run(tc.want, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
			t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			t.Setenv("FSCACHE_NOT_A_SETTING", "x") // a warning record precedes the startup record
			var buf bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			if err := serve(ctx, slog.New(slog.NewJSONHandler(&buf, nil)), func() { cancel() }); err != nil {
				t.Fatalf("serve: %v", err)
			}
			var found int
			for _, line := range strings.Split(buf.String(), "\n") {
				var rec map[string]any
				if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "fscache: starting" {
					continue
				}
				found++
				if rec["tls"] != tc.want {
					t.Errorf("tls = %v, want %q", rec["tls"], tc.want)
				}
				for _, k := range []string{"auth", "fips140"} {
					if _, ok := rec[k]; !ok {
						t.Errorf("the startup line lost %s: %v", k, rec)
					}
				}
			}
			if found != 1 {
				t.Fatalf("%d startup records in %q, want exactly one", found, buf.String())
			}
		})
	}
}

// proves: REQ-TLS-001-AC3 — a valid key is not refused as unparseable in any encoding the TLS stack reads (PKCS #1, SEC 1, PKCS #8)
func TestTLSKeyEncodingsAccepted(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		pub, key any
		block    *pem.Block
	}{
		{"PKCS1", &rsaKey.PublicKey, rsaKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}},
		{"SEC1", &ecKey.PublicKey, ecKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}},
		{"PKCS8", &ecKey.PublicKey, ecKey, &pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: tc.name},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, tc.pub, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, tc.name+".crt"), filepath.Join(dir, tc.name+".key")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(tc.block), 0o600); err != nil {
				t.Fatal(err)
			}
			cert, err := loadKeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("a valid %s key was refused: %v", tc.name, err)
			}
			if len(cert.Certificate) != 1 || !bytes.Equal(cert.Certificate[0], der) {
				t.Errorf("loaded a different certificate")
			}
		})
	}
}

// proves: REQ-TLS-001-AC9 — the server as started by serve negotiates only HTTP/1.1: an h2-only ALPN offer fails, h2 + http/1.1 gets http/1.1
func TestTLSServeOffersOnlyHTTP11(t *testing.T) {
	p := writePair(t, t.TempDir(), "alpn", "MARKER-ALPN-77aa01")
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	t.Setenv("FSCACHE_TLS_CERT", p.certPath)
	t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
	pool := x509.NewCertPool()
	pool.AddCert(p.leaf)
	var logs syncBuffer
	var addr string // set in the ready hook, before dial is used
	dial := func(protos ...string) (tls.ConnectionState, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
			&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: protos})
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState(), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
		defer cancel()
		addr = boundAddr(t, &logs)
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
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// proves: REQ-TLS-001-AC3 — a certificate or key file larger than 1 MiB is refused unread past the cap, naming the variable and path; files of exactly 1 MiB load
func TestTLSFileSizeCap(t *testing.T) {
	const limit = 1 << 20
	dir := t.TempDir()
	p := writePair(t, dir, "cap", "MARKER-CAP-5b5b5b")
	pad := func(src, dst string, size int) string {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > size {
			t.Fatalf("%s is already %d bytes", src, len(b))
		}
		b = append(b, bytes.Repeat([]byte("#"), size-len(b)-1)...)
		b = append(b, '\n')
		path := filepath.Join(dir, dst)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certAt, keyAt := pad(p.certPath, "cert-at.pem", limit), pad(p.keyPath, "key-at.pem", limit)
	certOver, keyOver := pad(p.certPath, "cert-over.pem", limit+1), pad(p.keyPath, "key-over.pem", limit+1)

	if _, err := loadKeyPair(certAt, keyAt); err != nil {
		t.Fatalf("files of exactly 1 MiB were refused: %v", err)
	}
	for _, c := range []badPairCase{
		{"certificate over the cap", map[string]string{"FSCACHE_TLS_CERT": certOver, "FSCACHE_TLS_KEY": p.keyPath}, []string{"FSCACHE_TLS_CERT", certOver, "1048576"}, []string{certOver, p.keyPath}},
		{"key over the cap", map[string]string{"FSCACHE_TLS_CERT": p.certPath, "FSCACHE_TLS_KEY": keyOver}, []string{"FSCACHE_TLS_KEY", keyOver, "1048576"}, []string{keyOver, p.certPath}},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dataDir := filepath.Join(t.TempDir(), "never-created")
			t.Setenv("FSCACHE_DATA_DIR", dataDir)
			t.Setenv("FSCACHE_ADDR", freePort(t))
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := serve(ctx, quietLogger(), cancel) // a start that wrongly succeeds shuts down at once
			if err == nil {
				t.Fatal("serve accepted an over-cap file")
			}
			checkRefusal(t, c, err.Error())
			if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
				t.Errorf("the data directory was created (stat err = %v)", statErr)
			}
		})
	}
}

// proves: REQ-TLS-001-AC3, REQ-TLS-001-AC4 — the refusal text is the fixed wording with only variable names and paths: no parser error text is appended
func TestTLSRefusalTextIsFixed(t *testing.T) {
	dir := t.TempDir()
	a := writePair(t, dir, "fixed-a", "MARKER-FIXA-6c6c6c")
	b := writePair(t, dir, "fixed-b", "MARKER-FIXB-7d7d7d")
	badKey := filepath.Join(dir, "malformed.key")
	if err := os.WriteFile(badKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, cert, key, want string
	}{
		{"mismatched pair", a.certPath, b.keyPath, fmt.Sprintf("FSCACHE_TLS_CERT=%q and FSCACHE_TLS_KEY=%q are not a usable pair: the private key does not match the certificate, or is of a type TLS cannot use", a.certPath, b.keyPath)},
		{"malformed key", a.certPath, badKey, fmt.Sprintf("FSCACHE_TLS_KEY=%q: the private key does not parse", badKey)},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
			t.Setenv("FSCACHE_ADDR", freePort(t))
			t.Setenv("FSCACHE_TLS_CERT", c.cert)
			t.Setenv("FSCACHE_TLS_KEY", c.key)
			err := serve(context.Background(), quietLogger(), nil)
			if err == nil || err.Error() != c.want {
				t.Fatalf("startup error = %v\nwant exactly  %s", err, c.want)
			}
		})
	}
}

// proves: REQ-TLS-001-AC3 — a path swapped for a non-regular file between the check and the open is refused on the opened handle
func TestTLSPathCheckedAgainOnTheOpenHandle(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "swap", "MARKER-SWAP-9f9f9f")
	orig := openTLSFile
	openTLSFile = func(string) (*os.File, error) { return os.Open(dir) } // the "file" became a directory after the stat
	defer func() { openTLSFile = orig }()
	_, err := loadKeyPair(p.certPath, p.keyPath)
	want := fmt.Sprintf("FSCACHE_TLS_CERT=%q is not a regular file", p.certPath)
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want exactly %q", err, want)
	}
}

// proves: REQ-TLS-001-AC3 — a regular file whose read fails is refused, naming the variable and the path
func TestTLSReadErrorRefused(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "readerr", "MARKER-READ-a0a0a0")
	orig := openTLSFile
	openTLSFile = func(path string) (*os.File, error) { return os.OpenFile(path, os.O_WRONLY, 0) } // a handle that cannot be read
	defer func() { openTLSFile = orig }()
	_, err := loadKeyPair(p.certPath, p.keyPath)
	if err == nil {
		t.Fatal("a file that cannot be read was accepted")
	}
	checkRefusal(t, badPairCase{names: []string{"FSCACHE_TLS_CERT", p.certPath, "cannot be read"}, files: []string{p.certPath, p.keyPath}}, err.Error())
}
