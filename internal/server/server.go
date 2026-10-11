// Package server implements the HTTP surface shared by both product
// frontends. Gradle's HttpBuildCache protocol and the Apache Maven Build
// Cache Extension's remote HTTP mode both reduce to GET/PUT/HEAD against a
// caller-supplied key — Gradle a single opaque hash, Maven a short path —
// so one handler set serves both (addendum §8: "Maven needs only a good
// server," which this is).
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/fosterstack/cache/internal/storesample"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Credentials, if both fields are non-empty, requires HTTP Basic Auth on
// every request (matching Maven settings.xml server basic-auth
// conventions; Gradle's HttpBuildCache also supports basic auth via
// credentials{} block). Empty Credentials disables auth — the open,
// self-hosted-on-a-trusted-network default.
type Credentials struct {
	Username string
	Password string
}

func (c Credentials) enabled() bool { return c.Username != "" && c.Password != "" }

// Store is what the HTTP layer needs from the cache. *cache.Cache is the only
// production implementation; the interface is a testability seam (tests
// wrap it to make a store write fail with a chosen error).
type Store interface {
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	Stat(key string) (int64, error)
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
	TotalSize() (int64, error)
	EntryCount() (int, error)
}

// Config configures New.
type Config struct {
	Cache Store
	// Sampler is the one shared store sample (writable, free bytes) that
	// /metrics and /statusz both read (REQ-OBS-002, REQ-OBS-003). Nil leaves
	// the disk gauges at 0 and /statusz reporting not writable.
	Sampler *storesample.Sampler
	Metrics *metrics.Metrics
	// Registry is gathered to serve /metrics. Defaults to
	// prometheus.DefaultGatherer, which is what Metrics must have been
	// registered against (see metrics.New) for /metrics to report
	// anything. Tests should pass the same *prometheus.Registry used to
	// construct Metrics to avoid colliding with the global registry.
	Registry prometheus.Gatherer
	Log      *slog.Logger
	Auth     Credentials
	// ROAuth is the optional read-only credential pair (REQ-AUTH-005):
	// valid for GET and HEAD, refused with 403 for writes.
	ROAuth Credentials
	// MaxBodyBytes caps request body size for PUT (0 = unlimited). Protects
	// against unbounded client uploads exhausting disk.
	MaxBodyBytes int64
	// MaxBytes is the configured store cap, reported by /statusz so an
	// operator can see used-vs-cap in one place. Reporting only; eviction
	// is the cache's own business. 0 means unlimited.
	MaxBytes int64
	// MaxConcurrentUploads bounds PUTs in flight (REQ-HTTP-002).
	// 0 disables the bound.
	MaxConcurrentUploads int
}

// Timeout constants (REQ-HTTP-001): generous where a legitimate transfer
// is slow, tight where only a stuck or idle connection waits.
const (
	ReadHeaderTimeout = 10 * time.Second
	IdleTimeout       = 120 * time.Second
	// ReadTimeout / WriteTimeout cover a full request: the documented
	// 1 GiB body cap over a slow CI link (~0.9 MB/s sustained) fits.
	ReadTimeout  = 20 * time.Minute
	WriteTimeout = 20 * time.Minute
)

// NewHTTPServer builds the http.Server with the required timeouts
// (REQ-HTTP-001) around the handler from New. Every timeout is explicit:
// an unset Go timeout is infinite, and an infinite timeout is a resource
// leak with a slow-enough client attached.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
	}
}

// New builds the top-level HTTP handler: cache GET/PUT/HEAD under "/",
// Prometheus metrics under /metrics, and an unauthenticated liveness probe
// at /healthz.
func New(cfg Config) http.Handler {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Registry == nil {
		cfg.Registry = prometheus.DefaultGatherer
	}
	status := &statusSource{cfg: cfg, started: time.Now()}

	// Seed the store gauges from the loaded store so /metrics agrees with
	// /statusz from the first scrape after a restart, not only after the
	// first upload (REQ-OBS-003-AC1).
	if cfg.Metrics != nil && cfg.Cache != nil {
		updateStoreGauges(cfg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	metricsHandler := promhttp.HandlerFor(cfg.Registry, promhttp.HandlerOpts{})
	var scrapeMu sync.Mutex // set the disk gauges and gather under one lock, so two scrapes can never export a mix of two samples
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		smp := diskSample(cfg) // the wait for a refresh (at most the sampler's few milliseconds) happens BEFORE the lock, so scrapes do not queue behind it
		buf := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
		scrapeMu.Lock()
		setDiskGauges(cfg, smp)
		metricsHandler.ServeHTTP(buf, r) // gathered into memory: the lock is not held while a slow client reads the response
		scrapeMu.Unlock()
		buf.writeTo(w)
	})

	// /statusz and the landing page sit behind the same Basic Auth as the
	// cache when auth is enabled (punch list #8d): they are read-only, so
	// the client credential — which already lives in every CI runner — is
	// a fine gate for looking. /healthz and /metrics stay open, matching
	// what liveness probes and Prometheus scrapers expect.
	mux.Handle("GET /statusz", withAuth(cfg.Auth, cfg.ROAuth, http.HandlerFunc(status.handleStatus)))

	// Exact-match "/{$}" so ONLY the bare root reaches the landing page.
	// Go's ServeMux gives the longest pattern precedence, so every real
	// cache key still routes to the cache handler below.
	mux.Handle("GET /{$}", withAuth(cfg.Auth, cfg.ROAuth, withMetrics(cfg.Metrics, http.HandlerFunc(status.handleRoot))))

	cacheHandler := withAuth(cfg.Auth, cfg.ROAuth, withMetrics(cfg.Metrics, withUploadBound(cfg, cacheEndpoint(cfg))))
	mux.Handle("/", cacheHandler)

	// The mux alone is not enough for two contracts (REQ-PROTO-003,
	// REQ-PROTO-007): http.ServeMux 307-redirects a path that needs
	// cleaning (dot-segments, doubled slashes) BEFORE any handler runs,
	// and its method-specific GET routes let a PUT/DELETE fall through to
	// the cache handler — which would store a blob under "healthz". The
	// front controller rejects malformed raw paths with 400 (no redirect)
	// and reserves the application endpoints across every method, so the
	// cache handler never sees them.
	return newFrontController(mux)
}

// reservedPaths are the application endpoints: read-only (GET/HEAD), and a
// write to any of them is a client error, never a cache entry.
var reservedPaths = map[string]bool{
	"/": true, "/healthz": true, "/metrics": true, "/statusz": true,
}

// newFrontController wraps the mux with raw-path validation and reserved-
// path method enforcement that must happen before ServeMux normalizes or
// routes.
func newFrontController(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reserved endpoints: GET/HEAD reach the mux; any other method is
		// 405 with the read-only Allow set and stores nothing.
		if reservedPaths[r.URL.Path] {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
		// Cache paths: reject a raw path that ServeMux would otherwise
		// redirect (a segment that is empty, ".", or ".." either literally
		// or percent-encoded), with 400 and no redirect. EscapedPath
		// preserves the on-the-wire segments so an encoded "%2e%2e" is
		// judged on the same footing as a literal "..".
		if rawPathIsMalformed(r.URL.EscapedPath()) {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// rawPathIsMalformed reports whether any segment of the raw request path
// is empty (a doubled or trailing slash), or is "." / ".." either
// literally or percent-encoded. A malformed cache path is a 400, never a
// redirect (REQ-PROTO-003-AC1); the blobstore's ValidateKey is the second
// line of defence on the decoded key.
func rawPathIsMalformed(escaped string) bool {
	trimmed := strings.TrimPrefix(escaped, "/")
	if trimmed == "" {
		return false // the bare root is handled as a reserved path
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" {
			return true // empty segment: doubled or trailing slash
		}
		dec, err := url.PathUnescape(seg)
		if err != nil {
			return true // an undecodable segment is not a valid key
		}
		if dec == "." || dec == ".." {
			return true
		}
	}
	return false
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// withAuth wraps h with HTTP Basic Auth when Credentials are configured.
// Constant-time comparison avoids leaking password length/prefix via
// timing (COMMIT-REQ style hygiene: this is exactly the kind of small
// correctness detail the addendum's algorithm-discipline section expects
// applied to all code, not just the crypto module choice).
//
// Two pairs (REQ-AUTH-005): the read-write pair passes everything
// through; the read-only pair passes GET and HEAD and answers writes
// with 403 and no WWW-Authenticate - the identity was accepted, the
// verb was refused, so re-presenting the same credentials cannot help.
// All four comparisons are evaluated on every request; nothing
// short-circuits on which pair matched.
func withAuth(creds, ro Credentials, next http.Handler) http.Handler {
	if !creds.enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		rwUserOK := subtle.ConstantTimeCompare([]byte(user), []byte(creds.Username)) == 1
		rwPassOK := subtle.ConstantTimeCompare([]byte(pass), []byte(creds.Password)) == 1
		roUserOK := subtle.ConstantTimeCompare([]byte(user), []byte(ro.Username)) == 1
		roPassOK := subtle.ConstantTimeCompare([]byte(pass), []byte(ro.Password)) == 1
		isRW := rwUserOK && rwPassOK
		isRO := ro.enabled() && roUserOK && roPassOK
		if !ok || (!isRW && !isRO) {
			w.Header().Set("WWW-Authenticate", `Basic realm="fosterstack-cache"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !isRW && r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only credentials", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withUploadBound refuses PUTs beyond the configured concurrency bound
// with 429 + Retry-After (REQ-HTTP-002). A non-blocking semaphore, not a
// queue: a build client treats any error as a cache miss and moves on, so
// making it wait would spend its build time to save our threads. Zero
// disables the bound.
func withUploadBound(cfg Config, next http.Handler) http.Handler {
	if cfg.MaxConcurrentUploads <= 0 {
		return next
	}
	slots := make(chan struct{}, cfg.MaxConcurrentUploads)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many concurrent uploads", http.StatusTooManyRequests)
		}
	})
}

// withMetrics records request count/duration by method and status.
func withMetrics(m *metrics.Metrics, next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		m.RequestsTotal.WithLabelValues(r.Method, strconv.Itoa(sw.status)).Inc()
		m.RequestDuration.WithLabelValues(r.Method).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// cacheEndpoint handles GET/PUT/HEAD for the cache key derived from the
// request path (leading slash stripped; see blobstore for validation).
func cacheEndpoint(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodGet:
			handleGet(w, r, cfg, key)
		case http.MethodHead:
			handleHead(w, cfg, key)
		case http.MethodPut:
			handlePut(w, r, cfg, key)
		default:
			w.Header().Set("Allow", "GET, PUT, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func handleGet(w http.ResponseWriter, r *http.Request, cfg Config, key string) {
	rc, size, err := cfg.Cache.Get(r.Context(), key)
	if err != nil {
		writeStoreError(w, cfg, err, "GET", key)
		return
	}
	defer func() { _ = rc.Close() }()
	if cfg.Metrics != nil {
		cfg.Metrics.CacheHitsTotal.Inc()
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	n, err := io.Copy(w, rc)
	if cfg.Metrics != nil {
		cfg.Metrics.BytesRead.Add(float64(n))
	}
	if err != nil {
		cfg.Log.Warn("server: GET: short write to client", "key", key, "error", err)
	}
}

func handleHead(w http.ResponseWriter, cfg Config, key string) {
	size, err := cfg.Cache.Stat(key)
	if err != nil {
		writeStoreError(w, cfg, err, "HEAD", key)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

func handlePut(w http.ResponseWriter, r *http.Request, cfg Config, key string) {
	// REQ-EVICT-002 fast path: an entry that declares itself larger than
	// the whole cache cap is refused before a byte is read. The cache
	// layer's capped reader is the backstop for chunked or mis-declared
	// bodies.
	if cfg.MaxBytes > 0 && r.ContentLength > cfg.MaxBytes {
		countPutError(cfg, cache.ErrEntryTooLarge, nil)
		writeStoreError(w, cfg, cache.ErrEntryTooLarge, "PUT", key)
		return
	}
	body := r.Body
	if cfg.MaxBodyBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
	}
	n, err := cfg.Cache.Put(r.Context(), key, body)
	if err != nil {
		countPutError(cfg, err, r.Context().Err())
		writeStoreError(w, cfg, err, "PUT", key)
		return
	}
	if cfg.Metrics != nil {
		cfg.Metrics.BytesWritten.Add(float64(n))
		updateStoreGauges(cfg)
	}
	w.WriteHeader(http.StatusCreated)
}

// updateStoreGauges refreshes the store_bytes/store_entries gauges after a
// successful write. Two extra read-only lookups per PUT (cheap: an
// in-memory bbolt view transaction each) versus letting these gauges sit
// at zero forever — which is what "Prometheus metrics" in the README
// would otherwise silently not mean for the two numbers an operator
// actually needs (bytes used vs. configured cap).
func updateStoreGauges(cfg Config) {
	if total, err := cfg.Cache.TotalSize(); err == nil {
		cfg.Metrics.StoreBytesTotal.Set(float64(total))
	} else {
		cfg.Log.Error("server: store_bytes gauge update failed", "error", err)
	}
	if n, err := cfg.Cache.EntryCount(); err == nil {
		cfg.Metrics.StoreEntries.Set(float64(n))
	} else {
		cfg.Log.Error("server: store_entries gauge update failed", "error", err)
	}
}

func writeStoreError(w http.ResponseWriter, cfg Config, err error, method, key string) {
	switch {
	case errors.Is(err, blobstore.ErrNotFound):
		if cfg.Metrics != nil && method == "GET" {
			cfg.Metrics.CacheMissTotal.Inc()
		}
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, blobstore.ErrInvalidKey):
		http.Error(w, "invalid key", http.StatusBadRequest)
	case errors.Is(err, cache.ErrEntryTooLarge):
		// Distinct from the body-limit 413 below: this entry can never
		// live in the cache at any transfer size, and the header says so
		// (REQ-EVICT-002-AC2 keeps the two rejections distinguishable).
		w.Header().Set("X-FSCache-Reject", "entry-exceeds-cache-cap")
		http.Error(w, "entry exceeds the configured cache cap", http.StatusRequestEntityTooLarge)
	default:
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		cfg.Log.Error("server: store error", "method", method, "key", key, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// diskSample reads the shared store sample (nil Sampler: the zero sample).
func diskSample(cfg Config) storesample.Sample {
	if cfg.Sampler == nil {
		return storesample.Sample{}
	}
	return cfg.Sampler.Get()
}

// bufferedResponse collects a response in memory so it can be written after a lock is released.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(status int)      { b.status = status }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) writeTo(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// setDiskGauges sets the two disk gauges from one sample.
func setDiskGauges(cfg Config, smp storesample.Sample) {
	if cfg.Metrics == nil || cfg.Sampler == nil {
		return
	}
	w := 0.0
	if smp.Writable {
		w = 1
	}
	cfg.Metrics.StoreWritable.Set(w)
	if betweenGaugeSets != nil {
		betweenGaugeSets() // test seam only: the gap between the two gauge writes (nil in production)
	}
	cfg.Metrics.StoreFreeBytes.Set(float64(smp.FreeBytes))
}

// betweenGaugeSets is nil outside tests.
var betweenGaugeSets func()

// countPutError records one failed PUT under exactly one reason and, for a
// disk failure, marks the shared sample stale so the next read measures again.
func countPutError(cfg Config, err, ctxErr error) {
	reason, counted := classifyPutError(err, ctxErr)
	if !counted {
		return
	}
	if cfg.Metrics != nil {
		cfg.Metrics.PutErrors.WithLabelValues(reason).Inc()
	}
	if (reason == "no_space" || reason == "read_only") && cfg.Sampler != nil {
		cfg.Sampler.MarkStale()
	}
}

// classifyPutError maps a failure of the store write path to the closed
// reason set. Precedence when a chain matches several: no_space, read_only,
// too_large, client_aborted, other. Refusals that are not store failures (a
// bad key) are not counted.
func classifyPutError(err, ctxErr error) (reason string, counted bool) {
	switch {
	case err == nil, errors.Is(err, blobstore.ErrInvalidKey):
		return "", false
	case isNoSpace(err):
		return "no_space", true
	case isReadOnly(err):
		return "read_only", true
	}
	var maxBytes *http.MaxBytesError
	switch {
	case errors.Is(err, cache.ErrEntryTooLarge), errors.As(err, &maxBytes):
		return "too_large", true
	case ctxErr != nil, errors.Is(err, context.Canceled), errors.Is(err, io.ErrUnexpectedEOF):
		return "client_aborted", true
	}
	return "other", true
}
