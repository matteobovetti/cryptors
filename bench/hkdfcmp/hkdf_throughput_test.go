// Throughput comparison counterpart to the Rust `throughput` test in
// src/hkdf/kdf.rs: same inputs, same number of calls per pass, same warm-up
// and same best-of-5 methodology, so the reported figures are directly
// comparable.
//
// Two workloads, for SHA-256 and SHA-512:
//
//   - Expand as far as HKDF goes, 255 blocks (8160 bytes with SHA-256, 16320
//     with SHA-512), expands times per pass, in MiB/s. The output is the same
//     every time, and its last bytes, printed at the end, are those of block
//     255.
//   - Extract and Expand from a 32-byte secret to a 32-byte key, derives times
//     per pass, in operations per second. Each key is the secret of the next,
//     so the calls form one chain, and the last key, printed at the end,
//     identifies the whole run. The Rust test prints the same one.
//
// The salt and info are those of RFC 5869 A.1, and so is the secret of the
// first workload.
package hkdfcmp

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
	"time"
)

const (
	// Longest outputs expanded per pass.
	expands = 4096
	// Short keys derived per pass.
	derives = 200_000
)

// counting returns n bytes counting up from zero. The salt of RFC 5869 A.1 is
// the first 13.
func counting(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

var (
	a1IKM  = []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	a1Salt = counting(13)
	a1Info = string([]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9})
)

// bestRate runs pass once to warm up, then five times, and returns the best of
// the five in passes per second.
func bestRate(t *testing.T, pass func() error) float64 {
	// The first pass is slowed down by page faults and CPU clock ramp-up, not
	// just HKDF itself, so it is not timed.
	if err := pass(); err != nil {
		t.Fatal(err)
	}
	var best float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		if err := pass(); err != nil {
			t.Fatal(err)
		}
		if rate := 1 / time.Since(start).Seconds(); rate > best {
			best = rate
		}
	}
	return best
}

func TestThroughput(t *testing.T) {
	hashes := []struct {
		name string
		new  func() hash.Hash
	}{
		{"sha256", sha256.New},
		{"sha512", sha512.New},
	}

	for _, h := range hashes {
		prk, err := hkdf.Extract(h.new, a1IKM, a1Salt)
		if err != nil {
			t.Fatal(err)
		}
		maxLen := 255 * h.new().Size()

		var okm []byte
		rate := bestRate(t, func() error {
			for i := 0; i < expands; i++ {
				if okm, err = hkdf.Expand(h.new, prk, a1Info, maxLen); err != nil {
					return err
				}
			}
			return nil
		})
		mib := float64(expands*maxLen) / (1024 * 1024)
		fmt.Printf("hkdf-%s expand %d bytes [Go crypto/hkdf]: %d per pass, best %.1f MiB/s (last bytes %x)\n",
			h.name, maxLen, expands, rate*mib, okm[len(okm)-8:])

		key := counting(32)
		rate = bestRate(t, func() error {
			for i := 0; i < derives; i++ {
				if key, err = hkdf.Key(h.new, key, a1Salt, a1Info, 32); err != nil {
					return err
				}
			}
			return nil
		})
		fmt.Printf("hkdf-%s derive 32 bytes [Go crypto/hkdf]: %d per pass, best %.0f ops/s (last key %x...)\n",
			h.name, derives, rate*derives, key[:8])
	}
}

// TestKnownAnswers checks that what is being timed really is HKDF, so a
// mislabelled or broken build fails the run instead of passing as a
// throughput figure: RFC 5869 A.1, and the longest output from A.1's inputs
// with each of the two hashes, whose SHA-256 is the one that the
// `longest_output` test of src/hkdf/kdf.rs expects (from OpenSSL as well).
func TestKnownAnswers(t *testing.T) {
	okm, err := hkdf.Key(sha256.New, a1IKM, a1Salt, a1Info, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(okm); got != want {
		t.Errorf("HKDF-SHA256(RFC 5869 A.1) = %s, want %s", got, want)
	}

	longest := []struct {
		name string
		new  func() hash.Hash
		want string
	}{
		{"SHA-256", sha256.New, "06ce7419405a88a66ba5c9795579cb05130c85101924d187552a0f7f57deb091"},
		{"SHA-512", sha512.New, "d623a5f5bc03bad6fef4c74bef4bf03770338d155b256c333cae9a3ca8f77e45"},
	}
	for _, l := range longest {
		okm, err := hkdf.Key(l.new, a1IKM, a1Salt, a1Info, 255*l.new().Size())
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(okm)); got != l.want {
			t.Errorf("SHA-256 of the longest HKDF-%s output = %s, want %s", l.name, got, l.want)
		}
	}
}
