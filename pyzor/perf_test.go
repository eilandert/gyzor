package pyzor

import (
	"bytes"
	"testing"
)

func benchmarkHTMLMessage(size int) []byte {
	const header = "From: sender@example.net\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
	const chunk = `<p>Limited offer for selected customers. Visit http://spam.example/path now.</p>`
	msg := make([]byte, 0, size+len(header))
	msg = append(msg, header...)
	for len(msg) < size {
		msg = append(msg, chunk...)
	}
	return bytes.Clone(msg[:size])
}

func BenchmarkComputeHTML256K(b *testing.B) {
	msg := benchmarkHTMLMessage(256 << 10)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compute(msg)
	}
}
