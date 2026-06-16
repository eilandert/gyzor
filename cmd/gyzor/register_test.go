package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var saltKeyLine = regexp.MustCompile(`(?m)^[0-9a-f]{40},[0-9a-f]{40}$`)

func TestCLIGenKey(t *testing.T) {
	code, out, errb := runCLI(t, []string{"genkey"}, "")
	if code != 0 {
		t.Fatalf("genkey exit=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "salt,key:") || !saltKeyLine.MatchString(out) {
		t.Fatalf("genkey output not in salt,key format: %q", out)
	}
}

func TestCLIRegisterGeneratesAndSaves(t *testing.T) {
	home := t.TempDir()
	code, out, errb := runCLI(t, []string{"--homedir", home, "--servers", "h.example:24441", "--user", "bob", "register"}, "")
	if code != 0 {
		t.Fatalf("register exit=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "give this username and key") {
		t.Fatalf("register did not print the key to hand to the admin: %q", out)
	}
	// Must report the file it saved to AND emit the identity as env-var lines.
	if !strings.Contains(out, "saved account") || !strings.Contains(out, filepath.Join(home, "accounts")) {
		t.Fatalf("register did not report the saved file path: %q", out)
	}
	if !strings.Contains(out, "\nGYZOR_USER=bob\n") {
		t.Fatalf("register did not emit a bare GYZOR_USER= env line: %q", out)
	}
	for _, want := range []string{"GYZOR_USER=bob", "GYZOR_SALT=", "GYZOR_KEY="} {
		if !strings.Contains(out, want) {
			t.Fatalf("register stdout missing env var %q: %q", want, out)
		}
	}
	data, err := os.ReadFile(filepath.Join(home, "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "h.example : 24441 : bob :") {
		t.Fatalf("accounts file missing bob entry: %q", data)
	}
}

func TestCLIRegisterPersistsProvidedSaltKey(t *testing.T) {
	home := t.TempDir()
	// --key as the combined "salt,key" field must be split and stored verbatim.
	code, out, errb := runCLI(t, []string{"--homedir", home, "--servers", "h.example:24441", "--user", "bob", "--key", "aaaa,bbbb", "register"}, "")
	if code != 0 {
		t.Fatalf("register exit=%d err=%q", code, errb)
	}
	data, err := os.ReadFile(filepath.Join(home, "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "h.example : 24441 : bob : aaaa,bbbb") {
		t.Fatalf("provided salt,key not persisted: %q", data)
	}
	// Env lines reflect the split salt,key even when the key was supplied.
	for _, want := range []string{"GYZOR_USER=bob", "GYZOR_SALT=aaaa", "GYZOR_KEY=bbbb"} {
		if !strings.Contains(out, want) {
			t.Fatalf("register stdout missing env var %q: %q", want, out)
		}
	}
}

func TestCLIRegisterRequiresUser(t *testing.T) {
	home := t.TempDir()
	code, _, errb := runCLI(t, []string{"--homedir", home, "register"}, "")
	if code != 2 || !strings.Contains(errb, "--user") {
		t.Fatalf("expected usage error for missing --user: code=%d err=%q", code, errb)
	}
}

func TestCLICredsFromFlagsSignRequest(t *testing.T) {
	var mu sync.Mutex
	var got string
	addr := startFake(t, func(req []byte) []byte {
		mu.Lock()
		got = string(req)
		mu.Unlock()
		return okResp(0, 0)(req)
	})
	code, _, errb := runCLI(t, []string{"--servers", addr, "--timeout", "500ms", "--user", "bob", "--key", "deadbeef", "check"}, "body\n")
	if code != 1 { // count 0 -> not a hit -> exit 1, but the request still went out signed
		t.Logf("check exit=%d err=%q (verdict, not the assertion)", code, errb)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(got, "User: bob") {
		t.Fatalf("request not signed with the flag identity: %q", got)
	}
}

func TestCLIKeyWithoutUserErrors(t *testing.T) {
	code, _, errb := runCLI(t, []string{"--servers", "h:1", "--key", "deadbeef", "check"}, "body\n")
	if code != 2 || !strings.Contains(errb, "--user") {
		t.Fatalf("expected usage error: code=%d err=%q", code, errb)
	}
}

func TestCLIUserWithoutKeyErrors(t *testing.T) {
	code, _, errb := runCLI(t, []string{"--servers", "h:1", "--user", "bob", "check"}, "body\n")
	if code != 2 || !strings.Contains(errb, "--key") {
		t.Fatalf("expected usage error: code=%d err=%q", code, errb)
	}
}
