// Throughput comparison counterpart to the Rust `throughput` test in
// src/sha2/sha256/digest.rs: same buffer size, warm-up, and best-of-5 methodology,
// so the reported MiB/s numbers are directly comparable.
//
// SHA-224 and SHA-256 run the same 64-round compression function and differ
// only in their initial state and output length, so their throughputs are
// expected to be the same. Both are reported anyway, since each is a separate
// function in both libraries.
//
// `go test -tags purego` makes crypto/sha256 skip its assembly and run its
// portable code instead -- the counterpart of the Rust scalar backend. impl
// (set in impl_*_test.go) names which of the two this run measured.
//
// On x86-64, `GODEBUG=cpu.sha=off go test` hides SHA-NI from crypto/sha256,
// which then runs its AVX2 assembly: the path Go takes on Intel cores that
// have AVX2 but no SHA-NI. Any GODEBUG setting is appended to the label, so
// such a run cannot be mistaken for the default one.
package sha256cmp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestThroughput(t *testing.T) {
	const size = 64 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = 0x61
	}
	mib := float64(len(data)) / (1024.0 * 1024.0)

	label := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		label += ", GODEBUG=" + godebug
	}

	digests := []struct {
		name string
		sum  func([]byte) []byte
	}{
		{"sha224", func(b []byte) []byte { d := sha256.Sum224(b); return d[:] }},
		{"sha256", func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }},
	}

	for _, f := range digests {
		// Warm up: a cold pass over a fresh buffer measures page faults as
		// much as SHA-256 itself.
		f.sum(data)

		var best float64
		var digest []byte
		for i := 0; i < 5; i++ {
			start := time.Now()
			digest = f.sum(data)
			if tp := mib / time.Since(start).Seconds(); tp > best {
				best = tp
			}
		}
		fmt.Printf("%s [%s]: %.0f MiB, best %.1f MiB/s (digest %x...)\n",
			f.name, label, mib, best, digest[:8])
	}
}

// TestKnownAnswers checks that the function being timed really is SHA-224 and
// SHA-256, so a mislabelled or broken build cannot produce a throughput figure.
func TestKnownAnswers(t *testing.T) {
	abc := []byte("abc")

	if got, want := fmt.Sprintf("%x", sha256.Sum224(abc)),
		"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"; got != want {
		t.Errorf("SHA-224(abc) = %s, want %s", got, want)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(abc)),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("SHA-256(abc) = %s, want %s", got, want)
	}
}
