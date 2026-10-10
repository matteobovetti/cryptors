// Throughput comparison counterpart to the Rust `throughput` test in
// src/hmac/mac.rs: same key, messages, warm-up and best-of-5 methodology, so
// the reported figures are directly comparable.
//
// Three workloads per hash, as on the Rust side:
//
//   - One 64 MiB message, in MiB/s, next to the bare hash over the same bytes.
//     Both libraries stream the message into the hash, so HMAC should run at
//     the speed of the hash.
//   - 1,000,000 messages of 64 bytes under one key, in tags per second, next
//     to the bare hash of each message. Both libraries hash the two padded
//     keys once and start every tag from the saved states (FIPS 198-1 section
//     6), so a 64-byte message under SHA-256 costs three runs of the
//     compression function, one more than hashing it bare.
//   - The same messages with the key set afresh for each one (hmac.New in Go,
//     the one-call hmac::hmac in Rust), which hashes the key's two blocks
//     every time: what HKDF pays per call.
//
// Each run prints the tag of the long message and the XOR of all the short
// messages' tags, which the Rust test prints too, so that both sides visibly
// computed the same thing.
package hmaccmp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
	"time"
)

const (
	size       = 64 * 1024 * 1024
	shortLen   = 64
	shortCount = 1_000_000
)

type function struct {
	name string
	new  func() hash.Hash
}

var functions = []function{
	{"sha256", sha256.New},
	{"sha512", sha512.New},
	{"sha1", sha1.New},
	{"md5", md5.New},
}

// bestOfFive runs pass once to warm up, then five times, and returns the
// shortest time in seconds. The first pass over a fresh buffer is slowed down
// by page faults and CPU clock ramp-up, not just HMAC itself.
func bestOfFive(pass func()) float64 {
	pass()
	best := 0.0
	for i := 0; i < 5; i++ {
		start := time.Now()
		pass()
		if elapsed := time.Since(start).Seconds(); best == 0 || elapsed < best {
			best = elapsed
		}
	}
	return best
}

func TestThroughput(t *testing.T) {
	// The same inputs as the Rust test: a 32-byte key 0x00, 0x01, ..., and a
	// message that does not repeat within a block. The short messages are the
	// first 64,000,000 bytes of the long one, in 64-byte pieces.
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	mib := float64(size) / (1024.0 * 1024.0)

	for _, f := range functions {
		mac := hmac.New(f.new, key)
		bare := f.new()

		// One long message, against the bare hash over the same bytes.
		var tag []byte
		hmacSecs := bestOfFive(func() {
			mac.Reset()
			mac.Write(data)
			tag = mac.Sum(tag[:0])
		})
		var digest []byte
		hashSecs := bestOfFive(func() {
			bare.Reset()
			bare.Write(data)
			digest = bare.Sum(digest[:0])
		})
		fmt.Printf("hmac-%s, one %.0f MiB message [Go crypto/hmac]: best %.1f MiB/s; bare %s %.1f MiB/s (tag %x...)\n",
			f.name, mib, mib/hmacSecs, f.name, mib/hashSecs, tag[:8])

		// Many short messages under one key, against the bare hash of each
		// message. Each pass XORs every tag (or digest) into `folded`, as the
		// Rust test does.
		folded := make([]byte, mac.Size())
		fold := func(tagOf func(message []byte) []byte) {
			clear(folded)
			for off := 0; off < shortCount*shortLen; off += shortLen {
				out := tagOf(data[off : off+shortLen])
				for i := range folded {
					folded[i] ^= out[i]
				}
			}
		}
		hmacSecs = bestOfFive(func() {
			fold(func(message []byte) []byte {
				mac.Reset()
				mac.Write(message)
				tag = mac.Sum(tag[:0])
				return tag
			})
		})
		hmacFolded := append([]byte(nil), folded...)
		hashSecs = bestOfFive(func() {
			fold(func(message []byte) []byte {
				bare.Reset()
				bare.Write(message)
				digest = bare.Sum(digest[:0])
				return digest
			})
		})
		fmt.Printf("hmac-%s, %d x %d B messages, keyed once [Go crypto/hmac]: best %.0f ops/s; bare %s of each message %.0f ops/s (tags XORed %x...)\n",
			f.name, shortCount, shortLen, shortCount/hmacSecs, f.name, shortCount/hashSecs, hmacFolded[:8])

		// The same messages, keyed afresh for each one: hmac.New hashes the
		// key's two blocks every time.
		keyedSecs := bestOfFive(func() {
			fold(func(message []byte) []byte {
				fresh := hmac.New(f.new, key)
				fresh.Write(message)
				tag = fresh.Sum(tag[:0])
				return tag
			})
		})
		fmt.Printf("hmac-%s, %d x %d B messages, keyed for each [Go crypto/hmac]: best %.0f ops/s (tags XORed %x...)\n",
			f.name, shortCount, shortLen, shortCount/keyedSecs, folded[:8])
	}
}

// TestKnownAnswers checks that the functions being timed really are
// HMAC-SHA-256, HMAC-SHA-512, HMAC-SHA-1 and HMAC-MD5, so a mislabelled or
// broken build cannot produce a throughput figure. The vectors are test case 2
// of RFC 4231 and of RFC 2202.
func TestKnownAnswers(t *testing.T) {
	key, message := []byte("Jefe"), []byte("what do ya want for nothing?")
	want := map[string]string{
		"sha256": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		"sha512": "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
			"9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		"sha1": "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
		"md5":  "750c783e6ab0b503eaa86e310a5db738",
	}
	for _, f := range functions {
		mac := hmac.New(f.new, key)
		mac.Write(message)
		if got := fmt.Sprintf("%x", mac.Sum(nil)); got != want[f.name] {
			t.Errorf("HMAC-%s = %s, want %s", f.name, got, want[f.name])
		}
	}
}
