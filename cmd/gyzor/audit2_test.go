package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/gyzor/pyzor"
)

// deadClient points at a closed loopback UDP port so Check yields a server
// error (no reply within the short timeout) — exercises the !AllOK path.
func deadClient() *pyzor.Client {
	return pyzor.New(pyzor.Config{
		Servers: []pyzor.Server{{Host: "127.0.0.1", Port: 1}},
		Timeout: 200 * time.Millisecond,
	})
}

func TestServeCheckPartialFailureIsUnknown(t *testing.T) {
	m := newMetrics()
	cfg := serveConfig{rCount: 0, wlCount: 0}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/check", strings.NewReader(probe))
	checkHandler(deadClient(), cfg, m)(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
	var out checkResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Action != "unknown" || out.Hit {
		t.Errorf("want unknown/!hit, got %+v", out)
	}
}

func TestSafetyCheck(t *testing.T) {
	if err := (serveConfig{listen: ":8078"}).safetyCheck(); err == nil {
		t.Error(":8078 without token should be refused")
	}
	if err := (serveConfig{listen: "127.0.0.1:8078"}).safetyCheck(); err != nil {
		t.Errorf("loopback without token should be allowed: %v", err)
	}
	if err := (serveConfig{listen: ":8078", token: "x"}).safetyCheck(); err != nil {
		t.Errorf("token set should allow any bind: %v", err)
	}
	if err := (serveConfig{unix: "/tmp/s"}).safetyCheck(); err != nil {
		t.Errorf("unix-only should be allowed: %v", err)
	}
}

func TestIsLoopbackListen(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8078": true, "localhost:8078": true, "[::1]:8078": true,
		":8078": false, "0.0.0.0:8078": false, "10.0.0.5:8078": false,
	} {
		if got := isLoopbackListen(addr); got != want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestReadCapped(t *testing.T) {
	if b, err := readCapped(strings.NewReader("12345"), 5); err != nil || len(b) != 5 {
		t.Errorf("exact max: %d bytes err %v", len(b), err)
	}
	if _, err := readCapped(strings.NewReader("123456"), 5); err != errTooLarge {
		t.Errorf("over max: want errTooLarge, got %v", err)
	}
}
