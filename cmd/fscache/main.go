// Command fscache is the FosterStack Cache server: a self-hosted,
// drop-in remote build cache speaking Gradle's HttpBuildCache protocol and
// the Apache Maven Build Cache Extension's remote HTTP mode.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/buildinfo"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/fosterstack/cache/internal/server"
	"github.com/prometheus/client_golang/prometheus"
)

type config struct {
	addr         string
	dataDir      string
	maxBytes     int64
	username     string
	password     string
	maxBodyBytes int64
}

func loadConfig() (config, error) {
	maxBytes, err := envSize("FSCACHE_MAX_BYTES", 0)
	if err != nil {
		return config{}, err
	}
	maxBodyBytes, err := envSize("FSCACHE_MAX_BODY_BYTES", 1<<30) // 1 GiB default cap per blob
	if err != nil {
		return config{}, err
	}
	cfg := config{
		addr:         envOr("FSCACHE_ADDR", ":8080"),
		dataDir:      envOr("FSCACHE_DATA_DIR", "./data"),
		maxBytes:     maxBytes,
		username:     os.Getenv("FSCACHE_USERNAME"),
		password:     os.Getenv("FSCACHE_PASSWORD"),
		maxBodyBytes: maxBodyBytes,
	}
	if (cfg.username == "") != (cfg.password == "") {
		return cfg, errors.New("FSCACHE_USERNAME and FSCACHE_PASSWORD must both be set or both be empty")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envSize parses a non-negative byte count from the environment, failing
// closed (REQ-CFG-003): an unparseable value, trailing garbage, a
// negative number, or an overflow stops startup with the variable and the
// value named. A silent default here once turned a bounded cache
// unbounded on a units typo — the exact bug this replaces. strconv, not
// Sscanf: Sscanf's %d happily reads "12abc" as 12.
func envSize(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a valid byte count (whole non-negative decimal number): %w", key, v, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s=%q is negative; a byte count cannot be", key, v)
	}
	return n, nil
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fscache: fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	blobs, err := blobstore.New(filepath.Join(cfg.dataDir, "blobs"))
	if err != nil {
		return fmt.Errorf("open blob store: %w", err)
	}

	meta, err := metadata.Open(filepath.Join(cfg.dataDir, "meta.db"))
	if err != nil {
		return fmt.Errorf("open metadata store: %w", err)
	}

	m := metrics.New(prometheus.DefaultRegisterer)

	c := cache.New(blobs, meta,
		cache.WithMaxBytes(cfg.maxBytes),
		cache.WithLogger(log),
		cache.WithOnEvict(func(key string, size int64) {
			m.EvictedTotal.Inc()
		}),
	)
	defer func() {
		if err := c.Close(); err != nil {
			log.Error("fscache: store close failed", "error", err)
		}
	}()

	handler := server.New(server.Config{
		Cache:        c,
		Metrics:      m,
		Registry:     prometheus.DefaultGatherer,
		Log:          log,
		Auth:         server.Credentials{Username: cfg.username, Password: cfg.password},
		MaxBodyBytes: cfg.maxBodyBytes,
		MaxBytes:     cfg.maxBytes,
	})

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	authNote := "disabled"
	if cfg.username != "" {
		authNote = "enabled"
	}
	// fips140 announces the one property the -fips build exists for.
	// Until now the startup line reported addr, data_dir, max_bytes and
	// auth and said nothing about FIPS, so the property a compliance buyer
	// chose this build for was unobservable at runtime. Same
	// posture-announcement shape as the auth field beside it; this is the
	// line an assessor screenshots.
	bi := buildinfo.Read()
	log.Info("fscache: starting",
		"version", bi.Version,
		"addr", cfg.addr,
		"data_dir", cfg.dataDir,
		"max_bytes", cfg.maxBytes,
		"auth", authNote,
		"fips140", bi.FIPSNote(),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		log.Info("fscache: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
