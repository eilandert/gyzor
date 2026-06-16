package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eilandert/gyzor/pyzor"
)

// fakePyzor is a local UDP pyzor server for serve tests: it echoes the request
// Thread and answers Code 200 with the given count / whitelist count.
func fakePyzor(t *testing.T, count, wl int) pyzor.Server {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			thread := "0"
			for _, ln := range strings.Split(string(buf[:n]), "\n") {
				if strings.HasPrefix(ln, "Thread: ") {
					thread = strings.TrimSpace(ln[len("Thread: "):])
				}
			}
			resp := fmt.Sprintf("Code: 200\nDiag: OK\nPV: 2.1\nThread: %s\nCount: %d\nWL-Count: %d\n",
				thread, count, wl)
			_, _ = pc.WriteToUDP([]byte(resp), raddr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pyzor.Server{Host: host, Port: port}
}

func testClient(t *testing.T, count, wl int) *pyzor.Client {
	s := fakePyzor(t, count, wl)
	return pyzor.New(pyzor.Config{Servers: []pyzor.Server{s}, Timeout: time.Second})
}

const probe = "From: a@b.c\r\nSubject: hi\r\n\r\nthe quick brown fox jumps over the lazy dog today here now\r\n"

func TestServeCheckReject(t *testing.T) {
	cli := testClient(t, 10, 0)
	m := newMetrics()
	cfg := serveConfig{rCount: 5, wlCount: 0}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", strings.NewReader(probe))
	checkHandler(cli, cfg, m)(rec, req)
	var out checkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out.Action != "reject" || !out.Hit {
		t.Errorf("want reject/hit, got %+v", out)
	}
	if out.Count != 10 {
		t.Errorf("count = %d, want 10", out.Count)
	}
}

func TestServeCheckAcceptWhitelist(t *testing.T) {
	cli := testClient(t, 10, 3) // whitelisted clears the hit
	m := newMetrics()
	cfg := serveConfig{rCount: 5, wlCount: 0}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", strings.NewReader(probe))
	checkHandler(cli, cfg, m)(rec, req)
	var out checkResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Action != "accept" || out.Hit {
		t.Errorf("want accept/!hit, got %+v", out)
	}
}

func TestServeReport(t *testing.T) {
	cli := testClient(t, 0, 0)
	m := newMetrics()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/report", strings.NewReader(probe))
	reportHandler(cli, m)(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"reported\":true") {
		t.Errorf("report: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeRevoke(t *testing.T) {
	cli := testClient(t, 0, 0)
	m := newMetrics()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(probe))
	revokeHandler(cli, m)(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"revoked\":true") {
		t.Errorf("revoke: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeCheckGETRejected(t *testing.T) {
	cli := testClient(t, 0, 0)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/check", nil)
	checkHandler(cli, serveConfig{}, newMetrics())(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /check code = %d, want 405", rec.Code)
	}
}

func TestServeAuth(t *testing.T) {
	called := false
	h := serveConfig{token: "sek"}.auth(func(w http.ResponseWriter, r *http.Request) { called = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/check", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("no token: code=%d called=%v", rec.Code, called)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", nil)
	req.Header.Set("X-GYZOR-Token", "sek")
	h(rec, req)
	if !called {
		t.Error("valid X-GYZOR-Token should pass")
	}

	called = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/check", nil)
	req.Header.Set("Authorization", "Bearer sek")
	h(rec, req)
	if !called {
		t.Error("valid Bearer token should pass")
	}
}

func TestMetricsExposition(t *testing.T) {
	m := newMetrics()
	m.inc(&m.checkTotal)
	m.verdictInc("reject")
	m.observe(0.02)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"gyzor_check_total 1",
		"gyzor_verdict_total{verdict=\"reject\"} 1",
		"gyzor_latency_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
}
