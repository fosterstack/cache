package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/fosterstack/cache/internal/buildinfo"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Status is the read-only view of the running server, served as JSON at
// /statusz and rendered as HTML for browsers.
//
// Deliberately read-only, and deliberately not an admin UI (punch list
// #8b/#8d). Configuration is flags and environment on purpose: the running
// server always matches the deployment manifest in git, so there is no
// drift to reconcile and no mutable surface for whoever finds the port.
// The server cannot be reconfigured at runtime by anyone, including us.
// There is no settings editor and no purge button; purging is documented
// as wiping the volume and restarting, which is declarative and auditable.
type Status struct {
	Version       string  `json:"version"`
	Revision      string  `json:"revision,omitempty"`
	Modified      bool    `json:"build_modified,omitempty"`
	FIPS140       bool    `json:"fips140"`
	FIPS140Note   string  `json:"fips140_note"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Uptime        string  `json:"uptime"`

	StoreBytes   int64 `json:"store_bytes"`
	MaxBytes     int64 `json:"max_bytes"`
	StoreEntries int   `json:"store_entries"`

	CacheHits   float64  `json:"cache_hits"`
	CacheMisses float64  `json:"cache_misses"`
	HitRatio    *float64 `json:"hit_ratio,omitempty"`
	Evicted     float64  `json:"evicted_entries"`

	AuthEnabled bool `json:"auth_enabled"`
}

// counterValue reads a counter's current value straight from the metric
// itself, so /statusz and /metrics can never disagree about the same
// number — they are the same number.
func counterValue(c prometheus.Counter) float64 {
	if c == nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func (s *statusSource) snapshot() Status {
	bi := buildinfo.Read()
	up := time.Since(s.started)

	st := Status{
		Version:       bi.Version,
		Revision:      bi.Revision,
		Modified:      bi.Modified,
		FIPS140:       bi.FIPS140,
		FIPS140Note:   bi.FIPSNote(),
		UptimeSeconds: up.Seconds(),
		Uptime:        up.Round(time.Second).String(),
		MaxBytes:      s.cfg.MaxBytes,
		AuthEnabled:   s.cfg.Auth.enabled(),
	}

	if s.cfg.Cache != nil {
		if total, err := s.cfg.Cache.TotalSize(); err == nil {
			st.StoreBytes = total
		}
		if n, err := s.cfg.Cache.EntryCount(); err == nil {
			st.StoreEntries = n
		}
	}
	if m := s.cfg.Metrics; m != nil {
		st.CacheHits = counterValue(m.CacheHitsTotal)
		st.CacheMisses = counterValue(m.CacheMissTotal)
		st.Evicted = counterValue(m.EvictedTotal)
		if got := st.CacheHits + st.CacheMisses; got > 0 {
			r := st.CacheHits / got
			st.HitRatio = &r
		}
	}
	return st
}

type statusSource struct {
	cfg     Config
	started time.Time
}

// wantsHTML reports whether the caller looks like a browser. curl and
// Prometheus get JSON; a human gets the page.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *statusSource) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.snapshot()
	if !wantsHTML(r) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := statusTmpl.Execute(w, st.view()); err != nil {
		s.cfg.Log.Error("server: status template", "error", err)
	}
}

// handleRoot answers a plain browser GET of "/". Before this existed the
// root returned 400 "invalid key" — the cache handler treats the path as
// the key and an empty key is invalid — so anyone who pasted the server
// address into a browser got an error page for a server that was working
// perfectly. Cache traffic is unaffected: Gradle and Maven always request
// a non-empty key.
func (s *statusSource) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := landingTmpl.Execute(w, s.snapshot().view()); err != nil {
		s.cfg.Log.Error("server: landing template", "error", err)
	}
}

// statusView is Status prepared for display: byte counts humanised, ratio
// as a percentage.
type statusView struct {
	Status
	StoreHuman string
	MaxHuman   string
	UsedPct    string
	HitPct     string
}

func (s Status) view() statusView {
	v := statusView{Status: s, StoreHuman: humanBytes(s.StoreBytes), MaxHuman: "unlimited", UsedPct: ""}
	if s.MaxBytes > 0 {
		v.MaxHuman = humanBytes(s.MaxBytes)
		v.UsedPct = fmt.Sprintf("%.1f%%", 100*float64(s.StoreBytes)/float64(s.MaxBytes))
	}
	v.HitPct = "n/a"
	if s.HitRatio != nil {
		v.HitPct = fmt.Sprintf("%.1f%%", 100**s.HitRatio)
	}
	return v
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Templates are compiled into the binary. The production image is
// distroless with a single Go binary and no filesystem to read assets
// from, and it stays that way — no external files, no CDN, no fonts.
var statusTmpl = template.Must(template.New("status").Parse(pageHead + `
<h1>FosterStack Cache</h1>
<p class="sub">Status. This page is read-only.</p>
<table>
  <tr><th>Version</th><td>{{.Version}}{{if .Modified}} <span class="warn">(modified tree)</span>{{end}}</td></tr>
  {{if .Revision}}<tr><th>Commit</th><td class="mono">{{.Revision}}</td></tr>{{end}}
  <tr><th>FIPS 140-3</th><td>{{if .FIPS140}}<span class="ok">{{.FIPS140Note}}</span>{{else}}{{.FIPS140Note}}{{end}}</td></tr>
  <tr><th>Uptime</th><td>{{.Uptime}}</td></tr>
  <tr><th>Cache size</th><td>{{.StoreHuman}} of {{.MaxHuman}}{{if .UsedPct}} ({{.UsedPct}}){{end}}</td></tr>
  <tr><th>Entries</th><td>{{.StoreEntries}}</td></tr>
  <tr><th>Hits / misses</th><td>{{printf "%.0f" .CacheHits}} / {{printf "%.0f" .CacheMisses}} ({{.HitPct}} hit rate)</td></tr>
  <tr><th>Evicted</th><td>{{printf "%.0f" .Evicted}}</td></tr>
  <tr><th>Auth</th><td>{{if .AuthEnabled}}enabled{{else}}disabled{{end}}</td></tr>
</table>
<p class="sub">Counters are since process start. <a href="/metrics">/metrics</a> has the
full Prometheus set; this page shows the same numbers.
<a href="/statusz" class="mono">/statusz</a> returns JSON to anything that does not ask for HTML.</p>
` + pageFoot))

var landingTmpl = template.Must(template.New("landing").Parse(pageHead + `
<h1>FosterStack Cache</h1>
<p class="sub">A remote build cache for Gradle and Maven. This server is running.</p>
<p>You have reached the cache endpoint itself. Build tools address it directly —
point your build at this address; there is nothing to click here.</p>
<table>
  <tr><th>Version</th><td>{{.Version}}</td></tr>
  <tr><th>FIPS 140-3</th><td>{{if .FIPS140}}<span class="ok">{{.FIPS140Note}}</span>{{else}}{{.FIPS140Note}}{{end}}</td></tr>
  <tr><th>Uptime</th><td>{{.Uptime}}</td></tr>
</table>
<p class="sub">
  <a href="/statusz">Status</a> &middot;
  <a href="/metrics">Metrics</a> &middot;
  <a href="/healthz">Health</a> &middot;
  <a href="https://github.com/fosterstack/cache">Docs</a>
</p>
` + pageFoot))

const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FosterStack Cache</title><style>
:root{color-scheme:light dark}
body{font:16px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
max-width:44rem;margin:3rem auto;padding:0 1.25rem}
h1{font-size:1.5rem;margin:0 0 .25rem}
.sub{color:#6b7280;font-size:.925rem}
table{border-collapse:collapse;margin:1.5rem 0;width:100%}
th,td{text-align:left;padding:.45rem .75rem .45rem 0;border-bottom:1px solid #8883}
th{font-weight:600;width:11rem;color:#6b7280}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
.ok{color:#15803d;font-weight:600}
.warn{color:#b45309}
a{color:inherit}
</style></head><body>`

const pageFoot = `</body></html>`
