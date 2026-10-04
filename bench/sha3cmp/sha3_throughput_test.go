// Throughput comparison counterpart to the Rust `throughput` and
// `throughput_many` tests in src/sha3/digest.rs: same buffer size, message
// split, warm-up, and best-of-5 methodology, so the reported MiB/s numbers are
// directly comparable.
//
// The four fixed digests are reported separately rather than averaged because
// they absorb different amounts of input per Keccak-f[1600] permutation --
// 144, 136, 104 and 72 bytes for SHA3-224/256/384/512 -- so their throughputs
// legitimately differ by more than 2x. SHAKE128/256 are wider still (168 and
// 136 bytes of rate) and are timed producing 32 bytes of output.
//
// The batch figure calls Go's crypto/sha3 one message at a time, because that
// is all its API offers -- there is no multi-buffer SHA-3 in the Go standard
// library. It exists so that the batch comparison is apples to apples on input
// shape: it is the same 1024 messages the Rust batch test hashes, and the
// difference is precisely what filling SIMD lanes with independent messages
// buys.
//
// `go test -tags purego` makes crypto/sha3 skip its assembly and run its
// portable Keccak instead -- the counterpart of the Rust scalar backend. impl
// (set in impl_*_test.go) names which of the two this run measured.
package sha3cmp

import (
	"crypto/sha3"
	"fmt"
	"testing"
	"time"
)

const (
	total     = 64 * 1024 * 1024
	msgSize   = 64 * 1024
	outputLen = 32
)

func TestThroughput(t *testing.T) {
	data := make([]byte, total)
	for i := range data {
		data[i] = 0x61
	}
	mib := float64(len(data)) / (1024.0 * 1024.0)

	// Fixed-size digests, single message. Warm up first: a cold pass over a
	// fresh buffer measures page faults as much as SHA-3 itself.
	warm := sha3.Sum256(data)
	_ = warm

	fixed := []struct {
		name string
		sum  func([]byte) []byte
	}{
		{"sha3-224", func(b []byte) []byte { d := sha3.Sum224(b); return d[:] }},
		{"sha3-256", func(b []byte) []byte { d := sha3.Sum256(b); return d[:] }},
		{"sha3-384", func(b []byte) []byte { d := sha3.Sum384(b); return d[:] }},
		{"sha3-512", func(b []byte) []byte { d := sha3.Sum512(b); return d[:] }},
	}

	var single256 float64
	for _, f := range fixed {
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
		if f.name == "sha3-256" {
			single256 = best
		}
		fmt.Printf("%s single [%s]: %.0f MiB, best %.1f MiB/s (digest %x)\n",
			f.name, impl, mib, best, digest)
	}

	// Extendable-output functions, single message, 32 bytes of output.
	xofs := []struct {
		name string
		sum  func([]byte) []byte
	}{
		{"shake128", func(b []byte) []byte { return shakeSum(sha3.NewSHAKE128(), b) }},
		{"shake256", func(b []byte) []byte { return shakeSum(sha3.NewSHAKE256(), b) }},
	}

	for _, x := range xofs {
		x.sum(data)

		var best float64
		var digest []byte
		for i := 0; i < 5; i++ {
			start := time.Now()
			digest = x.sum(data)
			if tp := mib / time.Since(start).Seconds(); tp > best {
				best = tp
			}
		}
		fmt.Printf("%s single [%s]: %.0f MiB, best %.1f MiB/s (%d-byte output %x)\n",
			x.name, impl, mib, best, outputLen, digest)
	}

	// Batch: the same 64 MiB split into independent messages, hashed in a loop.
	messages := make([][]byte, 0, total/msgSize)
	for off := 0; off+msgSize <= len(data); off += msgSize {
		messages = append(messages, data[off:off+msgSize])
	}
	sumAll(messages)

	var batch float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		sumAll(messages)
		if tp := mib / time.Since(start).Seconds(); tp > batch {
			batch = tp
		}
	}
	fmt.Printf("sha3-256 batch [%s, sequential]: %d x %d KiB = %.0f MiB, "+
		"best %.1f MiB/s (%.2fx single)\n",
		impl, len(messages), msgSize/1024, mib, batch, batch/single256)
}

// shakeSum absorbs input and squeezes outputLen bytes, the XOF equivalent of
// the one-shot Sum helpers the fixed digests expose.
func shakeSum(h *sha3.SHAKE, input []byte) []byte {
	h.Write(input)
	out := make([]byte, outputLen)
	h.Read(out)
	return out
}

func sumAll(messages [][]byte) [][32]byte {
	out := make([][32]byte, len(messages))
	for i, m := range messages {
		out[i] = sha3.Sum256(m)
	}
	return out
}
