// Throughput comparison counterpart to the Rust `throughput` test in
// src/pbkdf2/kdf.rs: same inputs, same number of calls per pass, same warm-up
// and same best-of-5 methodology, so the reported figures are directly
// comparable.
//
// Two workloads, for SHA-1, SHA-256 and SHA-512:
//
//   - A password hash: a key of one output of the hash, 100,000 iterations,
//     derives times per pass, in millions of iterations per second. Each key is
//     the password of the next derivation, so the calls form one chain, and the
//     last key, printed at the end, identifies the whole run. The Rust test
//     prints the same one.
//   - A single iteration, as when PBKDF2 only stretches a key a little: the cost
//     is the keying of HMAC and two of its calls, shortDerives times per pass,
//     in operations per second. The keys form a chain the same way.
//
// The salt is the 16 bytes counting up from zero, and the first password is
// the hash's output length counting up from zero.
package pbkdf2cmp

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
	"time"
)

const (
	// Iterations of each long derivation.
	iterations = 100_000
	// Long derivations per pass.
	derives = 10
	// One-iteration derivations per pass.
	shortDerives = 200_000
)

// counting returns n bytes counting up from zero.
func counting(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// bestRate runs pass once to warm up, then five times, and returns the best of
// the five in passes per second.
func bestRate(t *testing.T, pass func() error) float64 {
	// The first pass is slowed down by page faults and CPU clock ramp-up, not
	// just PBKDF2 itself, so it is not timed.
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
		{"sha1", sha1.New},
		{"sha256", sha256.New},
		{"sha512", sha512.New},
	}
	salt := counting(16)

	for _, h := range hashes {
		size := h.new().Size()

		key := counting(size)
		rate := bestRate(t, func() (err error) {
			for i := 0; i < derives; i++ {
				if key, err = pbkdf2.Key(h.new, string(key), salt, iterations, size); err != nil {
					return err
				}
			}
			return nil
		})
		fmt.Printf("pbkdf2-%s %d iterations [Go crypto/pbkdf2]: %d per pass, best %.2f M iterations/s (last key %x...)\n",
			h.name, iterations, derives, rate*derives*iterations/1e6, key[:8])

		key = counting(size)
		rate = bestRate(t, func() (err error) {
			for i := 0; i < shortDerives; i++ {
				if key, err = pbkdf2.Key(h.new, string(key), salt, 1, size); err != nil {
					return err
				}
			}
			return nil
		})
		fmt.Printf("pbkdf2-%s 1 iteration [Go crypto/pbkdf2]: %d per pass, best %.0f ops/s (last key %x...)\n",
			h.name, shortDerives, rate*shortDerives, key[:8])
	}
}

// TestKnownAnswers checks that what is being timed really is PBKDF2, so a
// mislabelled or broken build fails the run instead of passing as a
// throughput figure: RFC 6070's first three vectors for HMAC-SHA-1, RFC 7914's
// first for HMAC-SHA-256, and the first step of each chain that is timed, which
// `benchmark_inputs_have_the_known_answers` in src/pbkdf2/kdf.rs pins too (the
// values are Python's hashlib and OpenSSL's as well).
func TestKnownAnswers(t *testing.T) {
	cases := []struct {
		name     string
		new      func() hash.Hash
		password string
		salt     []byte
		iter     int
		want     string
	}{
		{"SHA-1 (RFC 6070)", sha1.New, "password", []byte("salt"), 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"SHA-1 (RFC 6070)", sha1.New, "password", []byte("salt"), 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"SHA-1 (RFC 6070)", sha1.New, "password", []byte("salt"), 4096, "4b007901b765489abead49d926f721d065a429c1"},
		{"SHA-256 (RFC 7914)", sha256.New, "passwd", []byte("salt"), 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
	}
	for _, h := range []struct {
		name  string
		new   func() hash.Hash
		wants [2]string
	}{
		{"SHA-1", sha1.New, [2]string{"d3c2bc6bba9ac36b41d4481e3d8ca7e5fc11c4e0", "a284998ce9e51d7f74a3723d0fd561ddbc9e8f89"}},
		{"SHA-256", sha256.New, [2]string{"2daef9c73f5ce29c2a48a1cd2554c459fa9410539bdda2983e53090683e8182b", "69c3e3ff3a7669afd1a0cb1986cec67e9ad23ef6110cc4da74f9d366e690bd1c"}},
		{"SHA-512", sha512.New, [2]string{
			"884e89d142973182656d441fb521b3b1f527c408c06cb2671899bf71889288974e936b1bb277632dcfe70e5b6374119d0f1a68987d46eea9b24e77dd6fe211eb",
			"e8d825502a21b2fd43fb3afef897277df37630cff78defabe8cd0807d612da730f318d97ab40e4d55669d0c79152b85d01d31dd8fb2113fc66ab56c0949a0862"}},
	} {
		for i, iter := range []int{1, 100_000} {
			cases = append(cases, struct {
				name     string
				new      func() hash.Hash
				password string
				salt     []byte
				iter     int
				want     string
			}{h.name + " (benchmark inputs)", h.new, string(counting(h.new().Size())), counting(16), iter, h.wants[i]})
		}
	}
	for _, c := range cases {
		dk, err := pbkdf2.Key(c.new, c.password, c.salt, c.iter, len(c.want)/2)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(dk); got != c.want {
			t.Errorf("PBKDF2-%s, %d iterations = %s, want %s", c.name, c.iter, got, c.want)
		}
	}
}
