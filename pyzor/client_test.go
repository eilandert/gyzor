package pyzor

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeServer is a local UDP pyzor server for integration tests. reply receives the
// raw request and returns the response bytes (or nil to stay silent / simulate a
// timeout).
type fakeServer struct {
	pc   *net.UDPConn
	addr Server
}

func startFake(t *testing.T, reply func(req []byte) []byte) *fakeServer {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	fs := &fakeServer{pc: pc, addr: Server{Host: host, Port: port}}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := reply(append([]byte(nil), buf[:n]...)); resp != nil {
				_, _ = pc.WriteToUDP(resp, raddr)
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return fs
}

func threadOf(req []byte) string {
	for _, ln := range strings.Split(string(req), "\n") {
		if strings.HasPrefix(ln, "Thread: ") {
			return strings.TrimSpace(ln[len("Thread: "):])
		}
	}
	return "0"
}

func okResp(count, wl int) func([]byte) []byte {
	return func(req []byte) []byte {
		return []byte(fmt.Sprintf("Code: 200\nDiag: OK\nPV: 2.1\nThread: %s\nCount: %d\nWL-Count: %d\n",
			threadOf(req), count, wl))
	}
}

func clientFor(t *testing.T, servers ...Server) *Client {
	return New(Config{Servers: servers, Timeout: 500 * time.Millisecond})
}

func TestCheckSingleHit(t *testing.T) {
	s := startFake(t, okResp(10, 0))
	res := clientFor(t, s.addr).CheckDigest("d")
	if res.Count != 10 || res.Whitelist != 0 {
		t.Fatalf("count/wl = %d/%d", res.Count, res.Whitelist)
	}
	if !res.Hit(5, 0) {
		t.Error("expected hit")
	}
	if !res.AllOK() {
		t.Error("expected AllOK")
	}
}

func TestCheckWhitelistClearsHit(t *testing.T) {
	s := startFake(t, okResp(10, 3))
	res := clientFor(t, s.addr).CheckDigest("d")
	if res.Hit(5, 0) {
		t.Error("whitelisted server must not be a hit at wlCount=0")
	}
	if !res.Hit(5, 3) {
		t.Error("should hit when wlCount allows 3")
	}
}

// The audit's core bug: two servers each Count=1 must NOT sum to a hit at
// threshold 1. pyzor decides per-server.
func TestMultiServerDoesNotSum(t *testing.T) {
	s1 := startFake(t, okResp(1, 0))
	s2 := startFake(t, okResp(1, 0))
	res := clientFor(t, s1.addr, s2.addr).CheckDigest("d")
	if res.Count != 1 {
		t.Errorf("Count should be MAX (1), got %d", res.Count)
	}
	if res.Hit(1, 0) {
		t.Error("two servers at Count=1 must be a MISS at threshold 1 (no summing)")
	}
}

func TestWrongThreadRejected(t *testing.T) {
	s := startFake(t, func(req []byte) []byte {
		bad, _ := strconv.Atoi(threadOf(req))
		bad = (bad % 60000) + 1500 // different, still ok-range
		return []byte(fmt.Sprintf("Code: 200\nDiag: OK\nPV: 2.1\nThread: %d\nCount: 9\nWL-Count: 0\n", bad))
	})
	res := clientFor(t, s.addr).CheckDigest("d")
	if res.Servers[0].Err == nil {
		t.Fatal("expected error for mismatched thread")
	}
	if res.AllOK() || res.Hit(0, 0) {
		t.Error("a mismatched-thread reply must not count as authoritative")
	}
}

func TestIncompleteResponseRejected(t *testing.T) {
	s := startFake(t, func(req []byte) []byte {
		return []byte("Count: 99\nWL-Count: 0\n") // no Code/Diag/PV/Thread
	})
	res := clientFor(t, s.addr).CheckDigest("d")
	if res.Servers[0].Err == nil {
		t.Fatal("expected error for incomplete response")
	}
}

func TestTimeout(t *testing.T) {
	s := startFake(t, func(req []byte) []byte { return nil }) // silent
	start := time.Now()
	res := clientFor(t, s.addr).CheckDigest("d")
	if res.Servers[0].Err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("timeout took too long")
	}
}

func TestReportAllOKAndPartial(t *testing.T) {
	ok := startFake(t, okResp(0, 0))
	if !clientFor(t, ok.addr).ReportDigest("d") {
		t.Error("single OK server should report true")
	}
	// One OK, one silent (errors) -> not all OK -> false.
	silent := startFake(t, func(req []byte) []byte { return nil })
	if clientFor(t, ok.addr, silent.addr).ReportDigest("d") {
		t.Error("partial failure must make ReportDigest false")
	}
}

// Concurrency: several unreachable servers must not serialize their timeouts.
func TestConcurrentQueriesBoundLatency(t *testing.T) {
	silent := startFake(t, func(req []byte) []byte { return nil })
	servers := []Server{silent.addr, silent.addr, silent.addr, silent.addr}
	c := New(Config{Servers: servers, Timeout: 400 * time.Millisecond})
	start := time.Now()
	c.CheckDigest("d")
	// Sequential would be ~4*400ms=1.6s; concurrent should be ~400ms.
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Errorf("queries appear sequential: %v for 4 servers at 400ms timeout", elapsed)
	}
}
