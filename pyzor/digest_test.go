package pyzor

import (
	"bufio"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
)

// corpus messages live in testdata/corpus/*.eml; expected digests (produced by
// REAL pyzor — see testdata/gen_expected.py) live in testdata/expected.tsv as
// "<name>\t<sha1hex>" lines. This is the make-or-break parity gate: gyzor must
// produce the identical digest pyzor would send to the server.
func TestParityAgainstPyzor(t *testing.T) {
	f, err := os.Open("testdata/expected.tsv")
	if err != nil {
		t.Skipf("no expected.tsv (run testdata/gen_expected.py with real pyzor): %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("bad expected.tsv line: %q", line)
		}
		name, want := parts[0], parts[1]
		raw, err := os.ReadFile("testdata/corpus/" + name)
		if err != nil {
			t.Fatalf("read corpus %s: %v", name, err)
		}
		got := Compute(raw)
		if got != want {
			t.Errorf("%s: digest mismatch\n  got  %s\n  want %s", name, got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Skip("expected.tsv empty")
	}
	t.Logf("parity verified over %d corpus messages", n)
}

func TestNormalizeOptimizedMatchesReference(t *testing.T) {
	long := regexp.MustCompile(`[^` + wsClass + `]{10,}`)
	ws := regexp.MustCompile(`[` + wsClass + `]`)
	reference := func(s string) string {
		s = strings.ReplaceAll(s, "\x00", "")
		s = long.ReplaceAllString(s, "")
		s = emailPtrn.ReplaceAllString(s, "")
		s = urlPtrn.ReplaceAllString(s, "")
		s = ws.ReplaceAllString(s, "")
		return strings.TrimFunc(s, isPySpace)
	}
	alphabet := []rune("abcXYZ09@:/._-\x00 \t\r\n\u0085\u00a0\u2028")
	rng := rand.New(rand.NewSource(1)) // #nosec G404 -- deterministic test data
	for i := 0; i < 10000; i++ {
		n := rng.Intn(128)
		runes := make([]rune, n)
		for j := range runes {
			runes[j] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(runes)
		if got, want := normalize(in), reference(in); got != want {
			t.Fatalf("normalize mismatch for %q\ngot  %q\nwant %q", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"hello world":                     "helloworld",
		"a b c":                           "abc", // whitespace removed; caller drops len<8
		"visit http://spam.example here":  "visithere",
		"mail me at joe@spam.example now": "mailmeatnow",
		"longtokenABCDEFGHIJ short":       "short",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAtomicShortMessage(t *testing.T) {
	// <=4 lines -> whole-message digest; just assert determinism + non-empty.
	msg := []byte("Subject: hi\r\n\r\nshortbody line\r\n")
	a := Compute(msg)
	b := Compute(msg)
	if a != b || len(a) != 40 {
		t.Fatalf("non-deterministic or wrong length digest: %q %q", a, b)
	}
}
