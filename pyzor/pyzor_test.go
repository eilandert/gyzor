package pyzor

import (
	"strings"
	"testing"
)

// Golden vectors produced from pyzor's own account.py formulas (hash_key /
// sign_msg). If gyzor's crypto diverges, the public server rejects every
// request, so these are pinned.
func TestHashKeyGolden(t *testing.T) {
	cases := []struct {
		key, user, want string
	}{
		{"", "anonymous", "993fddad78000f2246ee74c4b1b9edcb89f91937"},
		{"deadbeef", "alice", "50c1547d7dc9d0b7426918bb468f50dec45da57c"},
	}
	for _, c := range cases {
		if got := hashKey(c.key, c.user); got != c.want {
			t.Errorf("hashKey(%q,%q)=%s want %s", c.key, c.user, got, c.want)
		}
	}
}

func TestSignMsgGolden(t *testing.T) {
	hashedAnon := hashKey("", anonymousUser)
	m := "Op: check\nOp-Digest: 9023f0f442cd7e98b2fc98b81e362aeb95b2e07e\n" +
		"Thread: 4242\nPV: 2.1\nUser: anonymous\nTime: 1700000000"
	want := "1ae6df14c8e304cbb06d73810602f9856d97b776"
	if got := signMsg(hashedAnon, 1700000000, m); got != want {
		t.Errorf("signMsg=%s want %s", got, want)
	}
}

// serialize must emit headers in the exact order pyzor does (Op, Op-Digest,
// [Op-Spec], Thread, PV, User, Time, Sig) and end with a blank line; the signed
// text is everything up to but excluding Sig.
func TestSerializeStructure(t *testing.T) {
	req := newRequest("report", "abc123", true)
	wire := string(req.serialize(Anonymous, 1700000000, 4242))

	if !strings.HasSuffix(wire, "\n\n") {
		t.Errorf("wire must end with blank line, got %q", wire[len(wire)-4:])
	}
	wantOrder := []string{"Op: report", "Op-Digest: abc123", "Op-Spec: 20,3,60,3",
		"Thread: 4242", "PV: 2.1", "User: anonymous", "Time: 1700000000", "Sig: "}
	last := -1
	for _, want := range wantOrder {
		idx := strings.Index(wire, want)
		if idx < 0 {
			t.Fatalf("missing header %q in:\n%s", want, wire)
		}
		if idx < last {
			t.Errorf("header %q out of order", want)
		}
		last = idx
	}
}

func TestCheckRequestNoSpec(t *testing.T) {
	req := newRequest("check", "abc123", false)
	wire := string(req.serialize(Anonymous, 1, 2000))
	if strings.Contains(wire, "Op-Spec") {
		t.Error("check request must not carry Op-Spec")
	}
}

func TestParseResponse(t *testing.T) {
	pkt := []byte("Code: 200\r\nDiag: OK\r\nPV: 2.1\r\nThread: 4242\r\nCount: 7\r\nWL-Count: 2\r\n")
	r := parseResponse(pkt)
	if !r.isOK() {
		t.Errorf("expected OK, code=%d", r.code())
	}
	if r.intField("Count") != 7 || r.intField("WL-Count") != 2 {
		t.Errorf("count=%d wl=%d", r.intField("Count"), r.intField("WL-Count"))
	}
}

func TestLoadServersFallback(t *testing.T) {
	s := LoadServers("/nonexistent/servers")
	if len(s) != 1 || s[0] != DefaultServer {
		t.Errorf("expected default public server, got %v", s)
	}
}
