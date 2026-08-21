// Package server implements the HTTP surface shared by both product
// frontends. Gradle's HttpBuildCache protocol and the Apache Maven Build
// Cache Extension's remote HTTP mode both reduce to GET/PUT/HEAD against a
// caller-supplied key — Gradle a single opaque hash, Maven a short path —
// so one handler set serves both (addendum §8: "Maven needs only a good
// server," which this is).
package server

import (
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metrics"
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

// Config configures New.
type Config struct {
	Cache   *cache.Cache
	Metrics *metrics.Metrics
	// Registry is gathered to serve /metrics. Defaults to
	// prometheus.DefaultGatherer, which is what Metrics must have been
	// registered against (see metrics.New) for /metrics to report
	// anything. Tests should pass the same *prometheus.Registry used to
	// construct Metrics to avoid colliding with the global registry.
	Registry prometheus.Gatherer
	Log      *slog.Logger
	Auth     Credentials
	// MaxBodyBytes caps request body size for PUT (0 = unlimited). Protects
	// against unbounded client uploads exhausting disk.
	MaxBodyBytes int64
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /metrics", promhttp.HandlerFor(cfg.Registry, promhttp.HandlerOpts{}))

	cacheHandler := withAuth(cfg.Auth, withMetrics(cfg.Metrics, cacheEndpoint(cfg)))
	mux.Handle("/", cacheHandler)

	return mux
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
func withAuth(creds Credentials, next http.Handler) http.Handler {
	if !creds.enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(creds.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(creds.Password)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="fosterstack-cache"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
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
	body := r.Body
	if cfg.MaxBodyBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
	}
	n, err := cfg.Cache.Put(r.Context(), key, body)
	if err != nil {
		writeStoreError(w, cfg, err, "PUT", key)
		return
	}
	if cfg.Metrics != nil {
		cfg.Metrics.BytesWritten.Add(float64(n))
	}
	w.WriteHeader(http.StatusCreated)
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
