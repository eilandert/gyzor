package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eilandert/gyzor/pyzor"
)

// maxBody bounds a message read from an HTTP request body (pyzor messages are
// small; the digest is computed over the whole body).
const maxBody = 16 << 20 // 16 MiB

// serveConfig is resolved from flags/env (flag > env > default).
type serveConfig struct {
	listen    string // TCP address, e.g. "127.0.0.1:8078" (empty = disabled)
	unix      string // Unix socket path (empty = disabled)
	token     string // optional shared secret (Bearer or X-GYZOR-Token)
	maxConc   int    // max in-flight requests (bounded concurrency)
	rCount    int    // check verdict: report count strictly above this is a hit
	wlCount   int    // check verdict: whitelist count strictly above this clears it
	logStdout bool   // send info/access logs to stdout (errors stay on stderr)
	verbose   bool   // also log /check access lines (high volume)
}

// statusWriter captures the response status for the access log.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// safetyCheck refuses an unsafe-by-default configuration: a tokenless server
// must not expose its state-changing endpoints (/report, /revoke) to the
// network. With no token, only a loopback TCP bind (or a Unix socket) is
// allowed; binding all interfaces or a routable address requires a token.
func (cfg serveConfig) safetyCheck() error {
	if cfg.token != "" || cfg.listen == "" {
		return nil
	}
	if !isLoopbackListen(cfg.listen) {
		return fmt.Errorf("refusing to serve on %s without a token: set --token/GYZOR_TOKEN, or bind a loopback address (127.0.0.1)", cfg.listen)
	}
	return nil
}

// isLoopbackListen reports whether a TCP listen address binds only loopback. An
// empty host (":8078") means all interfaces — not loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// runServe starts the HTTP daemon: /check, /report, /revoke (gozer-shaped JSON),
// /metrics (Prometheus), /healthz. It mirrors the in-process library so a
// standalone gyzor can be a pyzor sidecar, parallel to `gdcc serve`.
func runServe(cli *pyzor.Client, cfg serveConfig, stderr io.Writer) int {
	// Two loggers: info/access (stdout when --log-stdout) and errors (always
	// stderr) so a log shipper can separate streams. No in-app timestamps —
	// the supervisor/container adds them.
	var infoW io.Writer = stderr
	if cfg.logStdout {
		infoW = os.Stdout
	}
	info := log.New(infoW, "gyzor: ", 0)
	errl := log.New(stderr, "gyzor: ", 0)

	if err := cfg.safetyCheck(); err != nil {
		errl.Println("serve:", err)
		return 2
	}
	if cfg.maxConc < 1 {
		cfg.maxConc = 8
	}
	m := newMetrics()
	// Bound in-flight requests: each fans out UDP queries to every pyzor server,
	// so an unbounded server is a socket/goroutine storm under load. Over the
	// limit -> 503.
	sem := make(chan struct{}, cfg.maxConc)
	gate := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next(w, r)
			default:
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
			}
		}
	}
	// access logs one line per request to the info stream. /check is high
	// volume, so it is logged only under --verbose; /report and /revoke always.
	access := func(name string, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
			next(sw, r)
			if name == "check" && !cfg.verbose {
				return
			}
			info.Printf("%s %d %.1fms", r.URL.Path, sw.code, float64(time.Since(start).Microseconds())/1000)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("/metrics", m)
	mux.HandleFunc("/check", cfg.auth(gate(access("check", m.instrument(checkHandler(cli, cfg, m))))))
	mux.HandleFunc("/report", cfg.auth(gate(access("report", m.instrument(reportHandler(cli, m))))))
	mux.HandleFunc("/revoke", cfg.auth(gate(access("revoke", m.instrument(revokeHandler(cli, m))))))

	// WriteTimeout must exceed the pyzor client budget so a slow upstream is
	// not cut off mid-answer; IdleTimeout bounds keep-alive connections.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      cli.Timeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var lns []net.Listener
	if cfg.listen != "" {
		ln, err := net.Listen("tcp", cfg.listen)
		if err != nil {
			errl.Println("listen:", err)
			return 1
		}
		lns = append(lns, ln)
		info.Println("listening on", cfg.listen)
	}
	if cfg.unix != "" {
		_ = os.Remove(cfg.unix)
		ln, err := net.Listen("unix", cfg.unix)
		if err != nil {
			errl.Println("listen unix:", err)
			return 1
		}
		lns = append(lns, ln)
		info.Println("listening on unix", cfg.unix)
	}
	if len(lns) == 0 {
		errl.Println("serve: no --listen or --unix configured")
		return 2
	}
	if cfg.verbose {
		info.Println("repo:", repoURL)
	}

	errc := make(chan error, len(lns))
	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			errc <- srv.Serve(ln)
		}(ln)
	}
	err := <-errc
	_ = srv.Close()
	wg.Wait()
	if err != nil && err != http.ErrServerClosed {
		errl.Println("serve:", err)
		return 1
	}
	return 0
}

// checkResponse is the gozer-compatible /check answer: action mirrors the gdcc
// sidecar (reject = listed spam, accept = clean), plus the raw counts and the
// per-server breakdown for debugging.
type checkResponse struct {
	Action    string       `json:"action"` // reject | accept
	Hit       bool         `json:"hit"`
	Count     int          `json:"count"`     // max report count across servers
	Whitelist int          `json:"whitelist"` // max whitelist count across servers
	Servers   []serverJSON `json:"servers,omitempty"`
}

type serverJSON struct {
	Server  string `json:"server"`
	Code    int    `json:"code"`
	Diag    string `json:"diag,omitempty"`
	Count   int    `json:"count"`
	WLCount int    `json:"wl_count"`
	Err     string `json:"err,omitempty"`
}

func checkHandler(cli *pyzor.Client, cfg serveConfig, m *metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msg, err := readBody(w, r)
		if err != nil {
			return
		}
		m.inc(&m.checkTotal)
		res := cli.Check(msg)
		out := checkResponse{Count: res.Count, Whitelist: res.Whitelist}
		for _, s := range res.Servers {
			sj := serverJSON{Server: s.Server.String(), Code: s.Code, Diag: s.Diag, Count: s.Count, WLCount: s.WLCount}
			if s.Err != nil {
				sj.Err = s.Err.Error()
				m.inc(&m.errorTotal)
			}
			out.Servers = append(out.Servers, sj)
		}
		// A partial-server failure is incomplete evidence, not a clean message:
		// report "unknown"/502 (matching the gdcc/gazor sidecars) instead of
		// conflating it with "accept". A hit needs every queried server to answer.
		if !res.AllOK() {
			out.Action = "unknown"
			m.verdictInc("unknown")
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		out.Hit = res.Hit(cfg.rCount, cfg.wlCount)
		out.Action = "accept"
		if out.Hit {
			out.Action = "reject"
		}
		m.verdictInc(out.Action)
		writeJSON(w, http.StatusOK, out)
	}
}

func reportHandler(cli *pyzor.Client, m *metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msg, err := readBody(w, r)
		if err != nil {
			return
		}
		m.inc(&m.reportTotal)
		ok := cli.Report(msg)
		if !ok {
			m.inc(&m.errorTotal)
			writeJSON(w, http.StatusBadGateway, map[string]bool{"reported": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"reported": true})
	}
}

func revokeHandler(cli *pyzor.Client, m *metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msg, err := readBody(w, r)
		if err != nil {
			return
		}
		m.inc(&m.revokeTotal)
		ok := cli.Whitelist(msg)
		if !ok {
			m.inc(&m.errorTotal)
			writeJSON(w, http.StatusBadGateway, map[string]bool{"revoked": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	}
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return nil, fmt.Errorf("method")
	}
	msg, err := readCapped(r.Body, maxBody)
	if err == errTooLarge {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return nil, err
	}
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return nil, err
	}
	return msg, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// auth wraps a handler with the optional shared-secret check (Bearer token or
// X-GYZOR-Token header). No token configured → open.
func (cfg serveConfig) auth(next http.HandlerFunc) http.HandlerFunc {
	if cfg.token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-GYZOR-Token")
		if got == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				got = strings.TrimPrefix(a, "Bearer ")
			}
		}
		if got != cfg.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
