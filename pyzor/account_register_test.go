package pyzor

import (
	"crypto/sha1" // #nosec G505 -- test mirrors the protocol's mandated SHA1
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestDeriveKeyParity pins the salt/key derivation formula (and the order of
// the hashed inputs) against an independently computed vector, so a future edit
// that reverses the concatenation or hashes the raw salt cannot pass silently.
func TestDeriveKeyParity(t *testing.T) {
	rawSalt := []byte("0123456789abcdef0123") // 20 bytes
	rawKey := []byte("ABCDEFGHIJKLMNOPQRST")  // 20 bytes

	saltDigest := sha1.Sum(rawSalt)
	wantSalt := hex.EncodeToString(saltDigest[:])

	// passphrase path: key = SHA1(salt_digest || passphrase)
	kh := sha1.New()
	kh.Write(saltDigest[:])
	kh.Write([]byte("secret"))
	wantKeyPass := hex.EncodeToString(kh.Sum(nil))

	if salt, key := deriveKey(rawSalt, nil, "secret"); salt != wantSalt || key != wantKeyPass {
		t.Fatalf("passphrase derive = %s,%s; want %s,%s", salt, key, wantSalt, wantKeyPass)
	}

	// random path: key = hex(rawKey), salt unchanged.
	if salt, key := deriveKey(rawSalt, rawKey, ""); salt != wantSalt || key != hex.EncodeToString(rawKey) {
		t.Fatalf("random derive = %s,%s; want %s,%s", salt, key, wantSalt, hex.EncodeToString(rawKey))
	}
}

func TestGenKeyFormat(t *testing.T) {
	s1, k1, err := GenKey("")
	if err != nil {
		t.Fatal(err)
	}
	s2, k2, err := GenKey("")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{s1, k1, s2, k2} {
		if !hex40.MatchString(v) {
			t.Fatalf("not 40-lower-hex: %q", v)
		}
	}
	if k1 == k2 || s1 == s2 {
		t.Fatalf("GenKey produced identical output across calls: salt %s/%s key %s/%s", s1, s2, k1, k2)
	}

	// passphrase path is also 40-hex and authenticates via hashKey without error.
	s3, k3, err := GenKey("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !hex40.MatchString(s3) || !hex40.MatchString(k3) {
		t.Fatalf("passphrase GenKey not 40-hex: %s,%s", s3, k3)
	}
}

func TestSaveAccountRoundTrip(t *testing.T) {
	home := t.TempDir()
	servers := []Server{{Host: "public.pyzor.org", Port: 24441}, {Host: "alt.example", Port: 24441}}
	acc := Account{Username: "bob", Salt: "deadbeef", Key: "cafebabe"}

	path, err := SaveAccount(home, servers, acc)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, "accounts") {
		t.Fatalf("path = %s", path)
	}

	// File must be private (0600) on non-Windows.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("accounts perm = %o, want 600", perm)
		}
	}

	got := LoadAccounts(path)
	for _, s := range servers {
		a, ok := got[s.addr()]
		if !ok {
			t.Fatalf("missing account for %s", s)
		}
		if a.Username != "bob" || a.Salt != "deadbeef" || a.Key != "cafebabe" {
			t.Fatalf("account for %s = %+v", s, a)
		}
	}

	// Re-register one server with a new key: it must overwrite (not duplicate)
	// that server while leaving the other untouched.
	if _, err := SaveAccount(home, servers[:1], Account{Username: "bob", Salt: "11", Key: "22"}); err != nil {
		t.Fatal(err)
	}
	got = LoadAccounts(path)
	if a := got[servers[0].addr()]; a.Key != "22" || a.Salt != "11" {
		t.Fatalf("re-register did not overwrite: %+v", a)
	}
	if a, ok := got[servers[1].addr()]; !ok || a.Key != "cafebabe" {
		t.Fatalf("re-register clobbered the other server: %+v ok=%v", a, ok)
	}
	if n := len(got); n != 2 {
		t.Fatalf("expected 2 accounts after re-register, got %d", n)
	}
}

func TestSaveAccountPreservesUnrelatedAndComments(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "accounts")
	const seed = "# my accounts\nkeep.example : 24441 : carol : aa,bb\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveAccount(home, []Server{{Host: "new.example", Port: 24441}}, Account{Username: "bob", Salt: "1", Key: "2"}); err != nil {
		t.Fatal(err)
	}
	got := LoadAccounts(path)
	if a, ok := got["keep.example:24441"]; !ok || a.Username != "carol" {
		t.Fatalf("unrelated entry lost: %+v ok=%v", a, ok)
	}
	if a, ok := got["new.example:24441"]; !ok || a.Username != "bob" {
		t.Fatalf("new entry missing: %+v ok=%v", a, ok)
	}
}

// TestDefaultAccountOverridesFile checks that a CLI/env identity wins over the
// per-server accounts map for every server.
func TestDefaultAccountOverridesFile(t *testing.T) {
	c := &Client{
		Accounts:       map[string]Account{"public.pyzor.org:24441": {Username: "fromfile", Key: "f"}},
		DefaultAccount: Account{Username: "cli", Key: "c"},
	}
	if a := c.account(Server{Host: "public.pyzor.org", Port: 24441}); a.Username != "cli" {
		t.Fatalf("DefaultAccount did not override file: %+v", a)
	}
	// Unset DefaultAccount -> fall back to the file, then anonymous.
	c.DefaultAccount = Account{}
	if a := c.account(Server{Host: "public.pyzor.org", Port: 24441}); a.Username != "fromfile" {
		t.Fatalf("expected file account, got %+v", a)
	}
	if a := c.account(Server{Host: "other", Port: 1}); a.Username != anonymousUser {
		t.Fatalf("expected anonymous, got %+v", a)
	}
}
