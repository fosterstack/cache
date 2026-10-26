// Command fscache is the FosterStack Cache server: a self-hosted,
// drop-in remote build cache speaking Gradle's HttpBuildCache protocol and
// the Apache Maven Build Cache Extension's remote HTTP mode.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/buildinfo"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/fosterstack/cache/internal/server"
	"github.com/fosterstack/cache/internal/storesample"
	"github.com/prometheus/client_golang/prometheus"
)

type config struct {
	addr                 string
	dataDir              string
	maxBytes             int64
	username             string
	password             string
	roUsername           string
	roPassword           string
	maxBodyBytes         int64
	maxConcurrentUploads int64
	tlsCert              string
	tlsKey               string
}

func loadConfig() (config, error) {
	maxBytes, err := envSize("FSCACHE_MAX_BYTES", 0, "byte count")
	if err != nil {
		return config{}, err
	}
	maxBodyBytes, err := envSize("FSCACHE_MAX_BODY_BYTES", 1<<30, "byte count") // 1 GiB default cap per blob
	if err != nil {
		return config{}, err
	}
	maxUploads, err := envSize("FSCACHE_MAX_CONCURRENT_UPLOADS", 32, "upload count")
	if err != nil {
		return config{}, err
	}
	cfg := config{
		addr:                 envOr("FSCACHE_ADDR", ":8080"),
		dataDir:              envOr("FSCACHE_DATA_DIR", "./data"),
		maxBytes:             maxBytes,
		username:             os.Getenv("FSCACHE_USERNAME"),
		password:             os.Getenv("FSCACHE_PASSWORD"),
		roUsername:           os.Getenv("FSCACHE_RO_USERNAME"),
		roPassword:           os.Getenv("FSCACHE_RO_PASSWORD"),
		maxBodyBytes:         maxBodyBytes,
		maxConcurrentUploads: maxUploads,
		tlsCert:              os.Getenv("FSCACHE_TLS_CERT"),
		tlsKey:               os.Getenv("FSCACHE_TLS_KEY"),
	}
	if (cfg.username == "") != (cfg.password == "") {
		return cfg, errors.New("FSCACHE_USERNAME and FSCACHE_PASSWORD must both be set or both be empty")
	}
	if (cfg.roUsername == "") != (cfg.roPassword == "") {
		return cfg, errors.New("FSCACHE_RO_USERNAME and FSCACHE_RO_PASSWORD must both be set or both be empty")
	}
	if cfg.roUsername != "" {
		if cfg.username == "" {
			return cfg, errors.New("FSCACHE_RO_USERNAME and FSCACHE_RO_PASSWORD require " +
				"FSCACHE_USERNAME and FSCACHE_PASSWORD: " +
				"a read-only pair with no read-write pair would leave nothing able to write")
		}
		if cfg.roUsername == cfg.username {
			return cfg, errors.New("FSCACHE_RO_USERNAME must differ from FSCACHE_USERNAME: " +
				"identical usernames make the credential tier ambiguous")
		}
	}
	if cfg.tlsCert != "" && cfg.tlsKey == "" {
		return cfg, fmt.Errorf("FSCACHE_TLS_CERT=%q is set without FSCACHE_TLS_KEY: "+
			"set both (HTTPS) or neither (plain HTTP)", cfg.tlsCert)
	}
	if cfg.tlsKey != "" && cfg.tlsCert == "" {
		return cfg, fmt.Errorf("FSCACHE_TLS_KEY=%q is set without FSCACHE_TLS_CERT: "+
			"set both (HTTPS) or neither (plain HTTP)", cfg.tlsKey)
	}
	return cfg, nil
}

// x509KeyPair is tls.X509KeyPair behind a seam, so a test can stand in a
// parser that panics (REQ-TLS-001-AC4). Production keeps the real one.
var x509KeyPair = tls.X509KeyPair

// loadKeyPair reads the certificate and key files once, at startup, and
// builds the TLS certificate (REQ-TLS-001). A new certificate takes effect
// on the next start; nothing watches the files.
//
// Every error names the variable(s) and the path and never any file
// content. Errors from the standard library's parsers are deliberately not
// passed through: their text is not ours to vet, and a key parse error
// must not be a channel for key bytes. A panic in any parser is recovered
// into the same kind of plain error, with no stack trace and no panic
// value printed.
func loadKeyPair(certPath, keyPath string) (cert tls.Certificate, err error) {
	certPEM, err := readTLSFile("FSCACHE_TLS_CERT", certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readTLSFile("FSCACHE_TLS_KEY", keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer func() {
		if recover() != nil {
			cert, err = tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_CERT=%q and FSCACHE_TLS_KEY=%q "+
				"could not be parsed as a certificate and private key", certPath, keyPath)
		}
	}()
	certDER := firstPEMBlock(certPEM, func(typ string) bool { return typ == "CERTIFICATE" })
	if certDER == nil {
		return tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_CERT=%q holds no PEM CERTIFICATE block", certPath)
	}
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_CERT=%q: the certificate does not parse", certPath)
	}
	keyDER := firstPEMBlock(keyPEM, func(typ string) bool {
		return typ == "PRIVATE KEY" || strings.HasSuffix(typ, " PRIVATE KEY")
	})
	if keyDER == nil {
		return tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_KEY=%q holds no PEM PRIVATE KEY block", keyPath)
	}
	if !parsesAsPrivateKey(keyDER) {
		return tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_KEY=%q: the private key does not parse", keyPath)
	}
	cert, err = x509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("FSCACHE_TLS_CERT=%q and FSCACHE_TLS_KEY=%q are not a usable pair: "+
			"the private key does not match the certificate, or is of a type TLS cannot use", certPath, keyPath)
	}
	return cert, nil
}

// maxTLSFileBytes caps each TLS file read (1 MiB: room for a long chain).
// A larger file is refused rather than read whole into memory.
const maxTLSFileBytes = 1 << 20

// openTLSFile is the non-blocking open behind a seam, so a test can change
// the path between the check and the open.
var openTLSFile = openTLSFileNoWait

// readTLSFile reads the file the variable name points at, at most
// maxTLSFileBytes of it. Errors name the variable and the path and carry
// only the operating system's error (which names the path), never content.
//
// Only a regular file is read (a symlink to one is followed, as a
// Kubernetes Secret volume presents its files). The path is checked before
// the open, because opening a FIFO with no writer would block forever,
// before the bind and deaf to SIGTERM. The open itself does not wait (see
// openTLSFileNoWait) and the opened handle is checked again, so a path
// swapped for a FIFO in between is refused at once too.
func readTLSFile(name, path string) ([]byte, error) {
	notRegular := fmt.Errorf("%s=%q is not a regular file", name, path)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s=%q cannot be read: %w", name, path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, notRegular
	}
	f, err := openTLSFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s=%q cannot be read: %w", name, path, err)
	}
	defer func() { _ = f.Close() }()
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() {
		return nil, notRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTLSFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s=%q cannot be read: %w", name, path, err)
	}
	if len(b) > maxTLSFileBytes {
		return nil, fmt.Errorf("%s=%q is larger than %d bytes, the most the server reads", name, path, maxTLSFileBytes)
	}
	return b, nil
}

// firstPEMBlock returns the bytes of the first PEM block whose type want
// accepts, or nil when there is none.
func firstPEMBlock(data []byte, want func(string) bool) []byte {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil
		}
		if want(b.Type) {
			return b.Bytes
		}
	}
}

// parsesAsPrivateKey reports whether der is a private key in one of the
// encodings tls.X509KeyPair reads (PKCS #1, PKCS #8, SEC 1).
func parsesAsPrivateKey(der []byte) bool {
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(der)
	return err == nil
}

// knownEnv is the single source of truth for the FSCACHE_ names the
// server reads (REQ-CFG-005). A test pins it both ways: against the names
// loadConfig reads and against the README configuration table, so a new
// variable cannot be added to one and forgotten in the other.
var knownEnv = []string{
	"FSCACHE_ADDR",
	"FSCACHE_DATA_DIR",
	"FSCACHE_MAX_BYTES",
	"FSCACHE_MAX_BODY_BYTES",
	"FSCACHE_MAX_CONCURRENT_UPLOADS",
	"FSCACHE_USERNAME",
	"FSCACHE_PASSWORD",
	"FSCACHE_RO_USERNAME",
	"FSCACHE_RO_PASSWORD",
	"FSCACHE_TLS_CERT",
	"FSCACHE_TLS_KEY",
}

// warnUnknownEnv logs one warning per environment variable that starts
// with FSCACHE_ (case-sensitive) and is not in knownEnv, sorted by name,
// and never the value (values can be secrets). A name within Levenshtein
// distance 2 of a known one carries it as did_you_mean; the suggestion is
// always a known name, never user text. It never fails startup.
func warnUnknownEnv(log *slog.Logger, environ []string) {
	seen := map[string]bool{}
	var unknown []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "FSCACHE_") || slices.Contains(knownEnv, name) || seen[name] {
			continue
		}
		seen[name] = true
		unknown = append(unknown, name)
	}
	slices.Sort(unknown)
	for _, name := range unknown {
		if hint := nearestKnown(name); hint != "" {
			log.Warn("fscache: unknown environment variable ignored", "name", name, "did_you_mean", hint)
			continue
		}
		log.Warn("fscache: unknown environment variable ignored", "name", name)
	}
}

// nearestKnown returns the closest known name within distance 2, ties
// broken by knownEnv order, or "" when none is that close.
func nearestKnown(name string) string {
	best, bestD := "", 3
	for _, k := range knownEnv {
		if d := levenshtein(name, k); d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// reconcileDuration renders a reconcile's elapsed time as a Go duration
// string rounded to the millisecond ("1.235s"), the format of the
// duration attribute on the reconciled line.
func reconcileDuration(d time.Duration) string { return d.Round(time.Millisecond).String() }

// uncleanMarkerPath is the marker's location inside the data directory —
// beside the stores it speaks for, so it travels with the volume.
func uncleanMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, ".unclean-shutdown")
}

func markerPresent(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func writeMarker(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("removed on clean shutdown; presence at startup triggers reconciliation\n"), 0o600)
}

func clearMarker(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envSize parses a non-negative whole number (noun names it in errors) from the environment, failing
// closed (REQ-CFG-003): an unparseable value, trailing garbage, a
// negative number, or an overflow stops startup with the variable and the
// value named. A silent default here once turned a bounded cache
// unbounded on a units typo — the exact bug this replaces. strconv, not
// Sscanf: Sscanf's %d happily reads "12abc" as 12.
func envSize(key string, def int64, noun string) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a valid %s (whole non-negative decimal number): %w", key, v, noun, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s=%q is negative: %s %s cannot be negative", key, v, article(noun), noun)
	}
	return n, nil
}

// article picks "a" or "an" for the noun in an error message.
func article(noun string) string {
	if strings.ContainsRune("aeiou", rune(noun[0])) {
		return "an"
	}
	return "a"
}

// osExit is a seam so main's exit path is testable without ending the
// test process.
var osExit = os.Exit

// Metrics registry seams. Production uses Prometheus's process-global
// default (so the Go/process collectors it pre-registers appear on
// /metrics); tests swap in a fresh registry per invocation because the
// global cannot be registered against twice.
var (
	metricsRegisterer prometheus.Registerer = prometheus.DefaultRegisterer
	metricsGatherer   prometheus.Gatherer   = prometheus.DefaultGatherer
)

// Seams for the two defensive branches that only fire when a
// post-success operation fails (a store Close error, an HTTP Shutdown
// timeout). Behavior-preserving: production keeps the real methods.
var (
	cacheClose     = (*cache.Cache).Close
	cacheReconcile = (*cache.Cache).Reconcile
	httpShutdown   = (*http.Server).Shutdown
	httpServe      = (*http.Server).Serve
	httpServeTLS   = func(s *http.Server, ln net.Listener) error { return s.ServeTLS(ln, "", "") }
	clearMarkerFn  = clearMarker
	serverNew      = server.New
)

func main() { osExit(runMain()) }

// runMain builds the process logger, runs the server, and maps the
// outcome to a process exit code. Split from main so both branches are
// testable in-process (main itself is then a single delegating call).
func runMain() int {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fscache: fatal", "error", err)
		return 1
	}
	return 0
}

// run installs the OS-signal shutdown context and serves under it.
func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, log, nil)
}

// reconcileAfterCrash repairs the stores after an unclean shutdown, before
// anything is served, and logs what it adopted, dropped and removed.
func reconcileAfterCrash(c *cache.Cache, log *slog.Logger) error {
	log.Warn("fscache: unclean shutdown detected, reconciling stores before serving")
	began := time.Now()
	stats, err := cacheReconcile(c, context.Background())
	if err != nil {
		return fmt.Errorf("startup reconciliation: %w", err)
	}
	log.Info("fscache: reconciled",
		"duration", reconcileDuration(time.Since(began)),
		"adopted_blobs", stats.AdoptedBlobs,
		"dropped_records", stats.DroppedRecords,
		"removed_temp_files", stats.RemovedTempFiles)
	return nil
}

// logStarting is the startup line: the address actually bound (":0" shows
// the real port), the data directory and what is switched on. fips140
// announces the one property the -fips build exists for, so an assessor
// can see it at runtime.
func logStarting(log *slog.Logger, ln net.Listener, cfg config, tlsOn bool) {
	bi := buildinfo.Read()
	log.Info("fscache: starting",
		"version", bi.Version,
		"addr", ln.Addr().String(),
		"data_dir", cfg.dataDir,
		"max_bytes", cfg.maxBytes,
		"auth", enabledOrDisabled(cfg.username != ""),
		"tls", enabledOrDisabled(tlsOn),
		"fips140", bi.FIPSNote(),
	)
}

func enabledOrDisabled(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

// serve is the full server lifecycle under an injectable shutdown
// context. ready, when non-nil, is called once the HTTP server has been
// handed off to its goroutine — tests use it to drive a deterministic
// shutdown without racing on a real signal.
func serve(ctx context.Context, log *slog.Logger, ready func()) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// The TLS files are read and checked here, before the bind and before
	// anything under the data directory (REQ-TLS-001, REQ-CFG-004).
	var tlsCfg *tls.Config
	if cfg.tlsCert != "" {
		cert, err := loadKeyPair(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return err
		}
		tlsCfg = server.TLSConfig(cert)
	}
	warnUnknownEnv(log, os.Environ())

	// Bind the listen address before anything under the data directory is
	// created, opened or written (REQ-CFG-004): a bad or taken FSCACHE_ADDR
	// is refused with the data directory exactly as found. The socket is
	// served only after the stores are ready, so connections arriving
	// during a long reconcile wait in the kernel's listen backlog.
	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("FSCACHE_ADDR=%q cannot be listened on: %w", cfg.addr, err)
	}
	served := false
	defer func() {
		if !served {
			_ = ln.Close()
		}
	}()

	// Unclean-shutdown marker (REQ-STORE-005): present at startup means
	// the last process did not exit cleanly, so the stores may disagree
	// and reconciliation must run before serving. It is removed only
	// after a clean shutdown's successful Close — a crash, a kill, a
	// panic, a failed reconcile, a serving or shutdown error or a failed
	// close all leave it in place for the next start to see.
	marker := uncleanMarkerPath(cfg.dataDir)
	wasUnclean, err := markerPresent(marker)
	if err != nil {
		return fmt.Errorf("check shutdown marker: %w", err)
	}
	if err := writeMarker(marker); err != nil {
		return fmt.Errorf("write shutdown marker: %w", err)
	}

	blobs, err := blobstore.New(filepath.Join(cfg.dataDir, "blobs"))
	if err != nil {
		return fmt.Errorf("open blob store: %w", err)
	}

	meta, err := metadata.Open(filepath.Join(cfg.dataDir, "meta.db"))
	if err != nil {
		return fmt.Errorf("open metadata store: %w", err)
	}

	m := metrics.New(metricsRegisterer)

	c := cache.New(blobs, meta,
		cache.WithMaxBytes(cfg.maxBytes),
		cache.WithLogger(log),
		cache.WithOnEvict(func(key string, size int64) {
			m.EvictedTotal.Inc()
		}),
	)
	// keepMarker fails closed: the marker is kept on every exit (an error,
	// a panic, an early return) except the single clean return at the end,
	// after a graceful Shutdown and a serving goroutine that ended without
	// a serving error. A failed or panicking reconcile may leave the stores
	// half repaired (REQ-STORE-005-AC4); a serving or shutdown error closes
	// the HTTP server without waiting for active handlers, so an upload may
	// leave a blob with no index record (REQ-STORE-005-AC5). The deferred
	// cleanup clears the marker only when this is false and the stores
	// closed successfully.
	keepMarker := true
	defer func() {
		if err := cacheClose(c); err != nil {
			log.Error("fscache: store close failed; unclean marker kept", "error", err)
			return
		}
		if keepMarker {
			log.Warn("fscache: unclean marker kept, next start reconciles")
			return
		}
		if err := clearMarkerFn(marker); err != nil {
			log.Error("fscache: shutdown marker not cleared; next start will reconcile", "error", err)
		}
	}()

	if wasUnclean {
		if err := reconcileAfterCrash(c, log); err != nil {
			return err
		}
	}

	// The store sample (writable, free bytes) is taken once here, before the
	// bound listener is served, and then lazily on read (REQ-OBS-002-AC10). It probes the
	// blob store's root, on the same volume as the metadata index.
	sampler := storesample.New(filepath.Join(cfg.dataDir, "blobs"), storesample.Deps{}, storesample.Options{Log: log})
	sampler.Start()

	handler := serverNew(server.Config{
		Sampler:              sampler,
		Cache:                c,
		Metrics:              m,
		Registry:             metricsGatherer,
		Log:                  log,
		Auth:                 server.Credentials{Username: cfg.username, Password: cfg.password},
		ROAuth:               server.Credentials{Username: cfg.roUsername, Password: cfg.roPassword},
		MaxBodyBytes:         cfg.maxBodyBytes,
		MaxBytes:             cfg.maxBytes,
		MaxConcurrentUploads: int(cfg.maxConcurrentUploads),
	})

	httpServer := server.NewHTTPServer(cfg.addr, handler, tlsCfg)
	// Go's own server errors (TLS handshake failures and the like) go
	// through the process logger at DEBUG, not as bare lines on stderr: they
	// carry only client-supplied values, and a client can cause them at will,
	// so at the default level a flood of them writes nothing. NewErrorLog
	// also strips the socket addresses from each line (REQ-OBS-006).
	httpServer.ErrorLog = server.NewErrorLog(log.Handler())

	logStarting(log, ln, cfg, tlsCfg != nil)

	errCh := make(chan error, 1)
	served = true // Serve owns and closes the listener from here on
	// The serving goroutine gets its own copy of the seam (no later write
	// to the package variable can race with it) and is always reaped before
	// serve returns: the deferred Close stops Serve whatever path leaves
	// this function, then waits for the goroutine to exit.
	// With TLS on, the listener serves HTTPS only. A plain-HTTP request to
	// it never reaches the handler: Go's server answers 400 ("Client sent
	// an HTTP request to an HTTPS server") and closes the connection.
	serveFn := httpServe
	if tlsCfg != nil {
		serveFn = httpServeTLS
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serveFn(httpServer, ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	defer func() {
		_ = httpServer.Close()
		<-done
	}()

	if ready != nil {
		ready()
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		log.Info("fscache: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpShutdown(httpServer, shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	// Join the serving goroutine and read its result: a serving error that
	// arrived together with the shutdown signal is still an error.
	<-done
	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	default:
	}
	keepMarker = false // the one clean return
	return nil
}
