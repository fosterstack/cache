// Package metrics defines the Prometheus metrics exposed at /metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics groups every counter/histogram the server records. Constructed
// once at startup and passed to the HTTP handlers.
type Metrics struct {
	RequestsTotal   *prometheus.CounterVec
	CacheHitsTotal  prometheus.Counter
	CacheMissTotal  prometheus.Counter
	BytesWritten    prometheus.Counter
	BytesRead       prometheus.Counter
	RequestDuration *prometheus.HistogramVec
	EvictedTotal    prometheus.Counter
	StoreBytesTotal prometheus.Gauge
	StoreEntries    prometheus.Gauge
	// Disk trouble (REQ-OBS-002). The two gauges are set from the one shared
	// store sample just before a scrape; PutErrors has one series per reason,
	// all created at 0.
	StoreWritable  prometheus.Gauge
	StoreFreeBytes prometheus.Gauge
	PutErrors      *prometheus.CounterVec
}

// PutErrorReasons is the closed set of fscache_put_errors_total reasons.
var PutErrorReasons = []string{"no_space", "read_only", "too_large", "client_aborted", "other"}

// New registers and returns the standard metric set against reg. Pass
// prometheus.NewRegistry() in tests to avoid global-registry collisions
// across parallel test packages; pass prometheus.DefaultRegisterer in
// production so /metrics also gets the Go runtime collectors.
func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	m := &Metrics{
		RequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "http_requests_total",
			Help:      "Total HTTP requests, by method and status code.",
		}, []string{"method", "status"}),
		CacheHitsTotal: f.NewCounter(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "cache_hits_total",
			Help:      "Total GET requests served from the cache.",
		}),
		CacheMissTotal: f.NewCounter(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "cache_misses_total",
			Help:      "Total GET requests for a key not in the cache.",
		}),
		BytesWritten: f.NewCounter(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "bytes_written_total",
			Help:      "Total bytes accepted via PUT.",
		}),
		BytesRead: f.NewCounter(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "bytes_read_total",
			Help:      "Total bytes served via GET.",
		}),
		RequestDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "fscache",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency, by method.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method"}),
		EvictedTotal: f.NewCounter(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "evicted_entries_total",
			Help:      "Total entries removed by LRU eviction.",
		}),
		StoreBytesTotal: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "fscache",
			Name:      "store_bytes",
			Help:      "Current total bytes recorded in the store.",
		}),
		StoreEntries: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "fscache",
			Name:      "store_entries",
			Help:      "Current number of entries recorded in the store.",
		}),
		StoreWritable: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "fscache",
			Name:      "store_writable",
			Help:      "1 when the server could create, sync and delete a file in the data directory within the probe limit, else 0.",
		}),
		StoreFreeBytes: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "fscache",
			Name:      "store_free_bytes",
			Help:      "Bytes available to an unprivileged process on the filesystem that holds the data directory (what df shows as Avail); 0 if it could not be read. A float64 gauge: exact up to 2^53 bytes (/statusz gives the exact count).",
		}),
		PutErrors: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fscache",
			Name:      "put_errors_total",
			Help:      "PUTs that failed inside the store write path, by reason (no_space, read_only, too_large, client_aborted, other).",
		}, []string{"reason"}),
	}
	for _, r := range PutErrorReasons {
		m.PutErrors.WithLabelValues(r) // create the series at 0 so rate() and increase() work from the first scrape
	}
	return m
}
