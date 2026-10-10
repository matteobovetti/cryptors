// Throughput comparison counterpart to the Rust `throughput` test in
// src/hpke/tests.rs: the same suites, the same inputs, the same sizes, the same
// warm-up and best-of-5 method, so the reported figures are directly
// comparable.
//
// Everything is in Base mode, with the info "cryptors hpke benchmark". Two
// things are timed:
//
//   - setup: NewSender and NewRecipient (SetupBaseS and SetupBaseR) with each
//     of the four KEMs, its own KDF and AES-128-GCM, to the recipient key
//     DeriveKeyPair(00 01 ..), as many bytes as a private key: 1000 setups
//     per pass for X25519, 400 for P-256, 100 for P-384 and 50 for P-521, in
//     operations per second;
//   - seal and open: 64 MiB of the byte pattern i % 251, as 1024 messages of
//     64 KiB with no associated data, through one fresh context per pass, for
//     DHKEM(X25519), HKDF-SHA256 and each of AES-128-GCM and AES-256-GCM.
//
// Go draws the ephemeral key of NewSender from crypto/rand and offers no way
// to supply one, so its encapsulated keys and ciphertexts differ from run to
// run and from the Rust test's. The cross-check that both print is therefore
// on the receiving side, which is deterministic: for each KEM, an export of
// the receiving context for the encapsulated key of DeriveKeyPair(20 21 ..).
//
// `go test -tags purego` makes Go skip its assembly and run its portable
// code. impl (set in impl_*_test.go) names which of the two this run measured.
package hpkecmp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

const (
	size       = 64 * 1024 * 1024
	messageLen = 64 * 1024
)

// bestOfFive runs pass once to warm up, then five times, and keeps the
// shortest of the times it reports. The first pass is slowed by page faults
// and clock ramp-up, not just HPKE. A pass times itself, so that setting up
// its context stays out of the bulk figures.
func bestOfFive(pass func() float64) float64 {
	pass()
	best := math.Inf(1)
	for i := 0; i < 5; i++ {
		best = math.Min(best, pass())
	}
	return best
}

// ikm is n bytes counting up from start, wrapping at 256.
func ikm(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func TestThroughput(t *testing.T) {
	info := []byte("cryptors hpke benchmark")

	var checks []string
	setups := []struct {
		name   string
		curve  ecdh.Curve
		kdf    hpke.KDF
		nsk    int
		setups int
	}{
		{"X25519HkdfSha256", ecdh.X25519(), hpke.HKDFSHA256(), 32, 1000},
		{"P256HkdfSha256", ecdh.P256(), hpke.HKDFSHA256(), 32, 400},
		{"P384HkdfSha384", ecdh.P384(), hpke.HKDFSHA384(), 48, 100},
		{"P521HkdfSha512", ecdh.P521(), hpke.HKDFSHA512(), 66, 50},
	}
	for _, s := range setups {
		kem, aead := hpke.DHKEM(s.curve), hpke.AES128GCM()
		skR, err := kem.DeriveKeyPair(ikm(0x00, s.nsk))
		if err != nil {
			t.Fatal(err)
		}
		pkR := skR.PublicKey()
		seconds := bestOfFive(func() float64 {
			start := time.Now()
			for i := 0; i < s.setups; i++ {
				enc, sender, err := hpke.NewSender(pkR, s.kdf, aead, info)
				if err != nil {
					t.Fatal(err)
				}
				recipient, err := hpke.NewRecipient(enc, skR, s.kdf, aead, info)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = sender, recipient
			}
			return time.Since(start).Seconds()
		})
		fmt.Printf("hpke setup [%s, %s]: %d x SetupBaseS + SetupBaseR, best %.1f ops/s (%.1f us each)\n",
			impl, s.name, s.setups, float64(s.setups)/seconds, seconds*1e6/float64(s.setups))

		skE, err := kem.DeriveKeyPair(ikm(0x20, s.nsk))
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := hpke.NewRecipient(skE.PublicKey().Bytes(), skR, s.kdf, aead, info)
		if err != nil {
			t.Fatal(err)
		}
		check, err := recipient.Export("cryptors hpke benchmark", 8)
		if err != nil {
			t.Fatal(err)
		}
		checks = append(checks, fmt.Sprintf("%x", check))
	}

	pattern := make([]byte, size)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	mib := float64(size) / (1024.0 * 1024.0)
	kem, kdf := hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256()
	skR, err := kem.DeriveKeyPair(ikm(0x00, 32))
	if err != nil {
		t.Fatal(err)
	}
	pkR := skR.PublicKey()
	aeads := []struct {
		name string
		aead hpke.AEAD
	}{
		{"Aes128Gcm", hpke.AES128GCM()},
		{"Aes256Gcm", hpke.AES256GCM()},
	}
	for _, a := range aeads {
		var enc []byte
		ciphertexts := make([][]byte, 0, size/messageLen)
		seal := bestOfFive(func() float64 {
			e, sender, err := hpke.NewSender(pkR, kdf, a.aead, info)
			if err != nil {
				t.Fatal(err)
			}
			enc = e
			ciphertexts = ciphertexts[:0]
			start := time.Now()
			for off := 0; off < size; off += messageLen {
				ct, err := sender.Seal(nil, pattern[off:off+messageLen])
				if err != nil {
					t.Fatal(err)
				}
				ciphertexts = append(ciphertexts, ct)
			}
			return time.Since(start).Seconds()
		})

		var last []byte
		open := bestOfFive(func() float64 {
			recipient, err := hpke.NewRecipient(enc, skR, kdf, a.aead, info)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for _, ct := range ciphertexts {
				last, err = recipient.Open(nil, ct)
				if err != nil {
					t.Fatal(err)
				}
			}
			return time.Since(start).Seconds()
		})
		if !bytes.Equal(last, pattern[size-messageLen:]) {
			t.Fatal("the last message did not open to its plaintext")
		}
		fmt.Printf("hpke seal [%s, %s]: %.0f MiB in 64 KiB messages, best %.1f MiB/s\n", impl, a.name, mib, mib/seal)
		fmt.Printf("hpke open [%s, %s]: %.0f MiB in 64 KiB messages, best %.1f MiB/s\n", impl, a.name, mib, mib/open)
	}
	fmt.Printf("hpke cross-check: exports %s\n", strings.Join(checks, " "))
}
