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
	"encoding/json"
	"encoding/pem"
	"io"
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

// proves: REQ-TLS-001-AC4 — neither the key's marker nor any 16-byte window of its body appears in the logs, the startup error, /metrics or /statusz, in a valid start or a refused one
func TestTLSKeyNeverAppearsInOutput(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "valid", "MARKER-KEY-c41d0e")

	t.Run("valid start", func(t *testing.T) {
		clearEnv(t)
		freshRegistry(t)
		addr := freePort(t)
		t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
		t.Setenv("FSCACHE_ADDR", addr)
		t.Setenv("FSCACHE_TLS_CERT", p.certPath)
		t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
		var logs bytes.Buffer
		var surfaces []string
		ctx, cancel := context.WithCancel(context.Background())
		err := serve(ctx, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), func() {
			defer cancel()
			c := tlsTestClient(p.leaf)
			for _, path := range []string{"/metrics", "/statusz", "/"} {
				code, body, _ := getTLS(t, c, "https://"+addr+path)
				if code != http.StatusOK {
					t.Errorf("%s = %d, want 200", path, code)
				}
				surfaces = append(surfaces, path+"\n"+body)
			}
		})
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
		if len(surfaces) != 3 {
			t.Fatalf("captured %d surfaces, want 3", len(surfaces))
		}
		for _, s := range append(surfaces, logs.String()) {
			if leak := p.leaks(s); leak != "" {
				t.Errorf("%s appears in:\n%s", leak, s)
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
		var logs bytes.Buffer
		err := serve(context.Background(), slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
		if err == nil {
			t.Fatal("serve accepted a mismatched pair")
		}
		code, out := runMainCaptured(t)
		if code == 0 {
			t.Fatal("runMain exited 0 for a mismatched pair")
		}
		for _, s := range []string{err.Error(), logs.String(), out} {
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
	addr := freePort(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", addr)
	t.Setenv("FSCACHE_TLS_CERT", old.certPath)
	t.Setenv("FSCACHE_TLS_KEY", old.keyPath)

	both := x509.NewCertPool()
	both.AddCert(old.leaf)
	both.AddCert(repl.leaf)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: both, MinVersion: tls.VersionTLS12},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	err := serve(ctx, quietLogger(), func() {
		defer cancel()
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
	ctx, cancel = context.WithCancel(context.Background())
	err = serve(ctx, quietLogger(), func() {
		defer cancel()
		if _, _, got := getTLS(t, c, "https://"+addr+"/healthz"); got == nil || got.SerialNumber.Cmp(repl.leaf.SerialNumber) != 0 {
			t.Errorf("after the restart: presented %v, want the replacement certificate", got)
		}
	})
	if err != nil {
		t.Fatalf("second serve: %v", err)
	}
}

// proves: REQ-TLS-001-AC8 — the startup line carries tls=enabled or tls=disabled beside auth and fips140
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
			t.Setenv("FSCACHE_ADDR", freePort(t))
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			var buf bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			if err := serve(ctx, slog.New(slog.NewJSONHandler(&buf, nil)), func() { cancel() }); err != nil {
				t.Fatalf("serve: %v", err)
			}
			var found bool
			for _, line := range strings.Split(buf.String(), "\n") {
				var rec map[string]any
				if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "fscache: starting" {
					continue
				}
				found = true
				if rec["tls"] != tc.want {
					t.Errorf("tls = %v, want %q", rec["tls"], tc.want)
				}
				for _, k := range []string{"auth", "fips140"} {
					if _, ok := rec[k]; !ok {
						t.Errorf("the startup line lost %s: %v", k, rec)
					}
				}
			}
			if !found {
				t.Fatalf("no startup line in %q", buf.String())
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
