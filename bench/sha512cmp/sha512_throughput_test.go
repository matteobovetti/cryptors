// Throughput comparison counterpart to the Rust `throughput` test in
// src/sha2/sha512/digest.rs: same buffer size, warm-up, and best-of-5
// methodology, so the reported MiB/s numbers are directly comparable.
//
// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 run the same 80-round
// compression function and differ only in their initial state and output
// length, so their throughputs are expected to be the same. All four are
// reported anyway, since each is a separate function in both libraries.
//
// `go test -tags purego` makes crypto/sha512 skip its assembly and run its
// portable code instead -- the counterpart of the Rust scalar backend. impl
// (set in impl_*_test.go) names which of the two this run measured. Any GODEBUG
// setting is appended to the label, so such a run cannot be mistaken for the
// default one.
package sha512cmp

import (
	"crypto/sha512"
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
		{"sha384", func(b []byte) []byte { d := sha512.Sum384(b); return d[:] }},
		{"sha512", func(b []byte) []byte { d := sha512.Sum512(b); return d[:] }},
		{"sha512_224", func(b []byte) []byte { d := sha512.Sum512_224(b); return d[:] }},
		{"sha512_256", func(b []byte) []byte { d := sha512.Sum512_256(b); return d[:] }},
	}

	for _, f := range digests {
		// Warm up: a cold pass over a fresh buffer measures page faults as
		// much as SHA-512 itself.
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

// TestKnownAnswers checks that the functions being timed really are SHA-384,
// SHA-512, SHA-512/224 and SHA-512/256, so a mislabelled or broken build cannot
// produce a throughput figure.
func TestKnownAnswers(t *testing.T) {
	abc := []byte("abc")

	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"SHA-384", fmt.Sprintf("%x", sha512.Sum384(abc)),
			"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
		{"SHA-512", fmt.Sprintf("%x", sha512.Sum512(abc)),
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{"SHA-512/224", fmt.Sprintf("%x", sha512.Sum512_224(abc)),
			"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
		{"SHA-512/256", fmt.Sprintf("%x", sha512.Sum512_256(abc)),
			"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
	} {
		if c.got != c.want {
			t.Errorf("%s(abc) = %s, want %s", c.name, c.got, c.want)
		}
	}
}
