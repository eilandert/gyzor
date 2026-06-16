package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// metrics is a tiny hand-rolled Prometheus exposition (stdlib-only, no
// client_golang dependency). It tracks request counters, per-verdict counters
// and a latency histogram, and renders the text format at /metrics. It mirrors
// the gdcc/gazor sidecar metrics so the three siblings expose the same shape.
type metrics struct {
	checkTotal  uint64
	reportTotal uint64
	revokeTotal uint64
	errorTotal  uint64

	verdict struct {
		reject  uint64
		accept  uint64
		unknown uint64
	}

	mu      sync.Mutex
	buckets []float64
	bcounts []uint64
	sum     float64
	count   uint64
}

func newMetrics() *metrics {
	return &metrics{
		buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		bcounts: make([]uint64, 11),
	}
}

func (m *metrics) inc(p *uint64) { atomic.AddUint64(p, 1) }

func (m *metrics) verdictInc(action string) {
	switch action {
	case "reject":
		atomic.AddUint64(&m.verdict.reject, 1)
	case "accept":
		atomic.AddUint64(&m.verdict.accept, 1)
	default:
		atomic.AddUint64(&m.verdict.unknown, 1)
	}
}

func (m *metrics) observe(seconds float64) {
	m.mu.Lock()
	for i, b := range m.buckets {
		if seconds <= b {
			m.bcounts[i]++
		}
	}
	m.sum += seconds
	m.count++
	m.mu.Unlock()
}

// instrument times a handler and records its latency.
func (m *metrics) instrument(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		m.observe(time.Since(start).Seconds())
	}
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	counter := func(name, help string, v uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("gyzor_check_total", "Total /check requests.", atomic.LoadUint64(&m.checkTotal))
	counter("gyzor_report_total", "Total /report requests.", atomic.LoadUint64(&m.reportTotal))
	counter("gyzor_revoke_total", "Total /revoke requests.", atomic.LoadUint64(&m.revokeTotal))
	counter("gyzor_error_total", "Total backend errors.", atomic.LoadUint64(&m.errorTotal))

	fmt.Fprint(w, "# HELP gyzor_verdict_total Check verdicts by action.\n# TYPE gyzor_verdict_total counter\n")
	fmt.Fprintf(w, "gyzor_verdict_total{verdict=\"reject\"} %d\n", atomic.LoadUint64(&m.verdict.reject))
	fmt.Fprintf(w, "gyzor_verdict_total{verdict=\"accept\"} %d\n", atomic.LoadUint64(&m.verdict.accept))
	fmt.Fprintf(w, "gyzor_verdict_total{verdict=\"unknown\"} %d\n", atomic.LoadUint64(&m.verdict.unknown))

	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprint(w, "# HELP gyzor_latency_seconds Check/report/revoke latency.\n# TYPE gyzor_latency_seconds histogram\n")
	for i, b := range m.buckets {
		fmt.Fprintf(w, "gyzor_latency_seconds_bucket{le=\"%s\"} %d\n",
			strconv.FormatFloat(b, 'g', -1, 64), m.bcounts[i])
	}
	fmt.Fprintf(w, "gyzor_latency_seconds_bucket{le=\"+Inf\"} %d\n", m.count)
	fmt.Fprintf(w, "gyzor_latency_seconds_sum %s\n", strconv.FormatFloat(m.sum, 'g', -1, 64))
	fmt.Fprintf(w, "gyzor_latency_seconds_count %d\n", m.count)
}
