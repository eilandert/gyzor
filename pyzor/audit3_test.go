package pyzor

import (
	"testing"
	"time"
)

func TestResolveCachesAndInvalidates(t *testing.T) {
	c := &Client{}
	s := Server{Host: "127.0.0.1", Port: 24441}
	a1, err := c.resolve(s)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := c.resolve(s)
	if a1 != a2 {
		t.Error("expected cached address reuse (same pointer)")
	}
	c.invalidateAddr(s)
	c.addrMu.Lock()
	_, ok := c.addrCache[s.addr()]
	c.addrMu.Unlock()
	if ok {
		t.Error("expected entry evicted after invalidateAddr")
	}
}

// TestFanoutBoundedManyServers: more servers than maxFanout still all get
// queried correctly (in bounded waves) and every result comes back.
func TestFanoutBoundedManyServers(t *testing.T) {
	const n = maxFanout*2 + 3
	servers := make([]Server, 0, n)
	for i := 0; i < n; i++ {
		fs := startFake(t, okResp(5, 0))
		servers = append(servers, fs.addr)
	}
	c := New(Config{Servers: servers, Timeout: time.Second})
	res := c.CheckDigest("digest")
	if len(res.Servers) != n {
		t.Fatalf("got %d results, want %d", len(res.Servers), n)
	}
	if !res.AllOK() {
		for _, sr := range res.Servers {
			if sr.Err != nil {
				t.Errorf("server %s error: %v", sr.Server, sr.Err)
			}
		}
	}
}
