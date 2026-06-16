package pyzor

import "testing"

// FuzzCompute drives the MIME walker / normalizer with arbitrary bytes to ensure
// Compute never panics and always returns a 40-char hex digest, regardless of
// malformed headers, broken multipart boundaries, bad base64/QP, or odd charsets.
func FuzzCompute(f *testing.F) {
	seeds := []string{
		"Subject: x\r\n\r\nhello world body line here\r\n",
		"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nbroken",
		"Content-Type: text/html\r\n\r\n<script>x</script><p>read me now</p>",
		"Content-Transfer-Encoding: base64\r\nContent-Type: text/plain\r\n\r\n!!!notbase64",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got := Compute(raw)
		if len(got) != 40 {
			t.Fatalf("digest length %d (want 40) for input %q", len(got), raw)
		}
	})
}
