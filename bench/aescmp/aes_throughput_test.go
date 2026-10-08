// Throughput comparison counterpart to the Rust `throughput` test in
// src/aes/cipher.rs: same buffer size, same input, same warm-up, and same
// best-of-5 methodology, so the reported MiB/s numbers are directly
// comparable.
//
// A block cipher transforms one 16-byte block per call, so the buffer is
// processed block by block, each block independent of the others (ECB, with no
// mode of operation on top), through the cipher.Block interface the way a
// caller would use it. The data is transformed in place and the passes are not
// undone, so the first block printed at the end identifies the whole run. It is
// the same for every implementation that is correct, and the Rust test prints
// the same figure for the same input.
//
// `go test -tags purego` makes crypto/aes skip its assembly and run its
// portable code instead -- the counterpart of the Rust scalar backend. impl
// (set in impl_*_test.go) names which of the two this run measured.
//
// Any GODEBUG setting is appended to the label, so such a run cannot be
// mistaken for the default one.
package aescmp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestThroughput(t *testing.T) {
	const size = 64 * 1024 * 1024

	// Block i starts the byte pattern at 16*i, as in the Rust test.
	pattern := make([]byte, size)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	data := make([]byte, size)
	mib := float64(size) / (1024.0 * 1024.0)

	label := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		label += ", GODEBUG=" + godebug
	}

	for _, keyLen := range []int{16, 24, 32} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		directions := []struct {
			name string
			run  func(dst, src []byte)
		}{
			{"encrypt", block.Encrypt},
			{"decrypt", block.Decrypt},
		}
		for _, d := range directions {
			pass := func() {
				for off := 0; off < len(data); off += aes.BlockSize {
					b := data[off : off+aes.BlockSize]
					d.run(b, b)
				}
			}

			// Warm up: a cold pass over a fresh buffer measures page faults as
			// much as AES itself.
			copy(data, pattern)
			pass()

			var best float64
			for i := 0; i < 5; i++ {
				start := time.Now()
				pass()
				if tp := mib / time.Since(start).Seconds(); tp > best {
					best = tp
				}
			}
			fmt.Printf("aes%d %s [%s]: %.0f MiB, best %.1f MiB/s (first block %x...)\n",
				keyLen*8, d.name, label, mib, best, data[:8])
		}
	}
}

// TestThroughputBulk is a reference point with no Rust counterpart: Go's own
// bulk path. cipher.Block takes one block per call, and at 16 bytes a call the
// call itself is a large part of what TestThroughput measures. CTR mode hands
// the whole buffer to crypto/aes at once, which on platforms with assembly
// encrypts several counter blocks at a time. It also does more work per block
// than an ECB loop (it builds the counters and XORs the keystream into the
// data), so its figures are not a like-for-like comparison with TestThroughput
// or with the Rust test. They show how much of the gap in TestThroughput is
// the call overhead rather than AES.
func TestThroughputBulk(t *testing.T) {
	const size = 64 * 1024 * 1024
	data := make([]byte, size)
	mib := float64(size) / (1024.0 * 1024.0)

	label := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		label += ", GODEBUG=" + godebug
	}

	for _, keyLen := range []int{16, 24, 32} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))

		stream.XORKeyStream(data, data)

		var best float64
		for i := 0; i < 5; i++ {
			start := time.Now()
			stream.XORKeyStream(data, data)
			if tp := mib / time.Since(start).Seconds(); tp > best {
				best = tp
			}
		}
		fmt.Printf("aes%d ctr [%s]: %.0f MiB, best %.1f MiB/s\n", keyLen*8, label, mib, best)
	}
}

// TestKnownAnswers checks that the function being timed really is AES, with
// the examples NIST publishes for FIPS 197 (Appendix C of its 2001 edition), so
// a mislabelled or broken build fails the run instead of passing as a
// throughput figure.
func TestKnownAnswers(t *testing.T) {
	plaintext, _ := hex.DecodeString("00112233445566778899aabbccddeeff")

	vectors := []struct{ key, ciphertext string }{
		{"000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},
		{"000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"},
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"},
	}
	for _, v := range vectors {
		key, _ := hex.DecodeString(v.key)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, aes.BlockSize)
		block.Encrypt(got, plaintext)
		if fmt.Sprintf("%x", got) != v.ciphertext {
			t.Errorf("AES-%d encrypt = %x, want %s", len(key)*8, got, v.ciphertext)
		}

		back := make([]byte, aes.BlockSize)
		block.Decrypt(back, got)
		if fmt.Sprintf("%x", back) != "00112233445566778899aabbccddeeff" {
			t.Errorf("AES-%d decrypt = %x, want the plaintext", len(key)*8, back)
		}
	}
}
