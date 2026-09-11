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

func loadConfig() config {
	cfg := config{
		addr:         envOr("FSCACHE_ADDR", ":8080"),
		dataDir:      envOr("FSCACHE_DATA_DIR", "./data"),
		maxBytes:     envInt64("FSCACHE_MAX_BYTES", 0),
		username:     os.Getenv("FSCACHE_USERNAME"),
		password:     os.Getenv("FSCACHE_PASSWORD"),
		maxBodyBytes: envInt64("FSCACHE_MAX_BODY_BYTES", 1<<30), // 1 GiB default cap per blob
	}
	return cfg
}

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

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fscache: fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := loadConfig()

	if (cfg.username == "") != (cfg.password == "") {
		return errors.New("FSCACHE_USERNAME and FSCACHE_PASSWORD must both be set or both be empty")
	}

	// Unclean-shutdown marker (REQ-STORE-005): present at startup means
	// the last process did not exit cleanly, so the stores may disagree
	// and reconciliation must run before serving. It is removed only
	// after a clean shutdown's successful Close — a crash, a kill, or a
	// failed close all leave it in place for the next start to see.
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
			log.Error("fscache: store close failed; unclean marker kept", "error", err)
			return
		}
		if err := clearMarker(marker); err != nil {
			log.Error("fscache: shutdown marker not cleared; next start will reconcile", "error", err)
		}
	}()

	if wasUnclean {
		log.Warn("fscache: unclean shutdown detected, reconciling stores before serving")
		stats, err := c.Reconcile(context.Background())
		if err != nil {
			return fmt.Errorf("startup reconciliation: %w", err)
		}
		log.Info("fscache: reconciled",
			"adopted_blobs", stats.AdoptedBlobs,
			"dropped_records", stats.DroppedRecords,
			"removed_temp_files", stats.RemovedTempFiles)
	}

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
