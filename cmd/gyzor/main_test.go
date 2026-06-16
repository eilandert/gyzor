package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

// startFake is a minimal local UDP pyzor server for CLI tests.
func startFake(t *testing.T, reply func(req []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if r := reply(append([]byte(nil), buf[:n]...)); r != nil {
				_, _ = pc.WriteToUDP(r, raddr)
			}
		}
	}()
	return pc.LocalAddr().String()
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

func runCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIDigest(t *testing.T) {
	code, out, _ := runCLI(t, []string{"digest"}, "Subject: x\n\nhello body line here\n")
	if code != 0 || len(strings.TrimSpace(out)) != 40 {
		t.Fatalf("digest: code=%d out=%q", code, out)
	}
}

func TestCLICheckHit(t *testing.T) {
	addr := startFake(t, okResp(10, 0))
	code, out, _ := runCLI(t, []string{"--servers", addr, "--timeout", "500ms", "check"}, "spam body\n")
	if code != 0 {
		t.Errorf("expected hit (exit 0), got %d; out=%q", code, out)
	}
	if !strings.Contains(out, "(200, 'OK')") {
		t.Errorf("missing per-server line: %q", out)
	}
}

func TestCLICheckMiss(t *testing.T) {
	addr := startFake(t, okResp(0, 0))
	code, _, _ := runCLI(t, []string{"--servers", addr, "--timeout", "500ms", "check"}, "ham body\n")
	if code != 1 {
		t.Errorf("expected miss (exit 1), got %d", code)
	}
}

func TestCLICheckNoSum(t *testing.T) {
	a := startFake(t, okResp(1, 0))
	b := startFake(t, okResp(1, 0))
	// threshold 1 across two Count=1 servers: pyzor-correct = miss (no summing).
	code, _, _ := runCLI(t, []string{"--servers", a + "," + b, "--timeout", "500ms", "--r-count", "1", "check"}, "x\n")
	if code != 1 {
		t.Errorf("two Count=1 servers must miss at r-count=1, got exit %d", code)
	}
}

func TestCLIReport(t *testing.T) {
	addr := startFake(t, okResp(0, 0))
	code, _, _ := runCLI(t, []string{"--servers", addr, "--timeout", "500ms", "report"}, "spam\n")
	if code != 0 {
		t.Errorf("report should succeed, got %d", code)
	}
}

func TestCLIUnknownOp(t *testing.T) {
	code, _, errb := runCLI(t, []string{"bogus"}, "")
	if code != 2 || !strings.Contains(errb, "unknown op") {
		t.Errorf("expected usage error, code=%d err=%q", code, errb)
	}
}

func TestParseServersArg(t *testing.T) {
	// all entries valid -> parsed in order
	got, err := parseServersArg("a.example:24441, b.example:1234")
	if err != nil || len(got) != 2 || got[0].Port != 24441 || got[1].Port != 1234 {
		t.Fatalf("parsed = %+v err=%v", got, err)
	}
	// any invalid entry -> usage error (no silent skip, no fallback to another server)
	if _, err := parseServersArg("a.example:24441,bad"); err == nil {
		t.Error("invalid --servers entry must error, not be skipped")
	}
	if _, err := parseServersArg("   "); err == nil {
		t.Error("empty --servers must error")
	}
}

func TestCLIInvalidServersIsUsageError(t *testing.T) {
	code, _, errb := runCLI(t, []string{"--servers", "not-an-address", "check"}, "x\n")
	if code != 2 {
		t.Errorf("invalid --servers should exit 2 (usage), got %d", code)
	}
	if !strings.Contains(errb, "invalid --servers") {
		t.Errorf("expected usage message, got %q", errb)
	}
}

func TestCLIWhitelistOnOtherServerClearsHit(t *testing.T) {
	// A: a clear hit; B: whitelisted above the threshold. Reference pyzor clears
	// the hit because whitelist is global across servers -> overall miss.
	a := startFake(t, okResp(10, 0))
	b := startFake(t, okResp(0, 2))
	code, _, _ := runCLI(t, []string{"--servers", a + "," + b, "--timeout", "500ms",
		"--r-count", "1", "--wl-count", "1", "check"}, "x\n")
	if code != 1 {
		t.Errorf("whitelist on another server must clear the hit (miss, exit 1), got %d", code)
	}
}

func TestCLINotAllOKIsMiss(t *testing.T) {
	// A hits; B never replies (timeout) -> not all_ok -> overall miss.
	a := startFake(t, okResp(10, 0))
	dead := startFake(t, func([]byte) []byte { return nil }) // silent: forces a timeout
	code, _, _ := runCLI(t, []string{"--servers", a + "," + dead, "--timeout", "300ms",
		"--r-count", "1", "check"}, "x\n")
	if code != 1 {
		t.Errorf("a server error must make the check a miss (exit 1), got %d", code)
	}
}
