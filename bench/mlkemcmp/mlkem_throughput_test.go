// Throughput comparison counterpart to the Rust `throughput` test in
// src/mlkem/keypair.rs: the same four operations on the same key, timed the same
// way, so the reported microseconds per operation are directly comparable.
//
// The operations are those of the two sides of a key encapsulation:
//
//	new decapsulation key  NewDecapsulationKey768: expands a seed of 64 bytes into
//	                       the secret vector, the matrix A and the encapsulation
//	                       key (cryptors: DecapsulationKey::from_seed)
//	new encapsulation key  NewEncapsulationKey768: checks the key (the modulus
//	                       check), hashes it, and expands the matrix A
//	                       (EncapsulationKey::from_bytes)
//	encapsulate            EncapsulationKey768.Encapsulate, with its 32 random
//	                       bytes from the system random source
//	                       (EncapsulationKey::encapsulate, with a cheap generator)
//	decapsulate            DecapsulationKey768.Decapsulate of a good ciphertext
//	                       (DecapsulationKey::decapsulate)
//
// Both sides keep the matrix A in the key, which is why building a key costs
// more than hashing it, and why encapsulating and decapsulating do not expand
// it again.
//
// Go has ML-KEM-768 and ML-KEM-1024; it has no ML-KEM-512, so the Rust test
// has a row for that set that this side does not.
//
// The "encapsulate" row of the Rust side reads its 32 random bytes from a cheap
// generator (xorshift64*), and this side reads them from the system, which
// crypto/mlkem does whatever the caller wants: the cost of one read of 32 bytes
// is a fraction of a microsecond here. The ciphertexts of the two sides differ,
// as any two encapsulations do.
//
// Each row is run for about 50 ms to size a batch of about 100 ms, and the best
// of five batches is reported. The first 8 bytes of the shared secret of a fixed
// message are printed, and are the same for every correct implementation given
// the same key; the Rust test prints them too.
//
// `go test -tags purego` makes crypto/mlkem run on a portable Keccak instead of
// the assembly one. impl (set in impl_*_test.go) names which of the two this run
// measured.
package mlkemcmp

import (
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

var sink byte
var sinkKey any

// timeOp is the timing of the other comparisons: a warm-up call, a pass of
// 50 ms that sizes a batch of about 100 ms, and the best of five batches, in
// microseconds per call.
func timeOp(op func()) float64 {
	op()
	start := time.Now()
	calls := 0
	for time.Since(start) < 50*time.Millisecond {
		op()
		calls++
	}
	batch := max(2*calls, 1)

	best := 0.0
	for range 5 {
		start := time.Now()
		for range batch {
			op()
		}
		micros := float64(time.Since(start).Nanoseconds()) / 1000 / float64(batch)
		if best == 0 || micros < best {
			best = micros
		}
	}
	return best
}

type encapsulationKey interface {
	Bytes() []byte
	Encapsulate() ([]byte, []byte)
}

type decapsulationKey[E encapsulationKey] interface {
	Bytes() []byte
	Decapsulate([]byte) ([]byte, error)
	EncapsulationKey() E
}

// set is one parameter set, with the functions of its types.
type set[E encapsulationKey, D decapsulationKey[E]] struct {
	name                string
	newDecapsulationKey func([]byte) (D, error)
	newEncapsulationKey func([]byte) (E, error)
	// encapsulate is the derandomized encapsulation of crypto/mlkem/mlkemtest.
	encapsulate func(E, []byte) ([]byte, []byte, error)
}

// seed is the decapsulation key of the benchmark: the pattern that the Rust test
// builds. message is the message that the known answers encapsulate.
func seed() []byte {
	s := make([]byte, mlkem.SeedSize)
	for i := range s {
		s[i] = byte(i*37 + 11)
	}
	return s
}

func message() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(i*7 + 3)
	}
	return m
}

func run[E encapsulationKey, D decapsulationKey[E]](t *testing.T, s set[E, D]) {
	key, err := s.newDecapsulationKey(seed())
	if err != nil {
		t.Fatal(err)
	}
	public := key.EncapsulationKey().Bytes()
	encKey, err := s.newEncapsulationKey(public)
	if err != nil {
		t.Fatal(err)
	}
	secret, ciphertext, err := s.encapsulate(encKey, message())
	if err != nil {
		t.Fatal(err)
	}
	got, err := key.Decapsulate(ciphertext)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%s: the ciphertext does not decapsulate to its secret: %v", s.name, err)
	}

	rows := []struct {
		name string
		op   func()
	}{
		{"new decapsulation key", func() {
			k, _ := s.newDecapsulationKey(seed())
			sink ^= k.Bytes()[0]
		}},
		{"new encapsulation key", func() {
			k, _ := s.newEncapsulationKey(public)
			sinkKey = k
		}},
		{"encapsulate", func() {
			k, c := encKey.Encapsulate()
			sink ^= k[0] ^ c[0]
		}},
		{"decapsulate", func() {
			k, _ := key.Decapsulate(ciphertext)
			sink ^= k[0]
		}},
	}
	for _, r := range rows {
		micros := timeOp(r.op)
		fmt.Printf("%s %s [%s]: best %.1f us/op, %.0f ops/s (secret %x...)\n",
			s.name, r.name, label(), micros, 1e6/micros, secret[:8])
	}
}

func TestThroughput(t *testing.T) {
	run(t, set[*mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768]{
		"ML-KEM-768", mlkem.NewDecapsulationKey768, mlkem.NewEncapsulationKey768, mlkemtest.Encapsulate768,
	})
	run(t, set[*mlkem.EncapsulationKey1024, *mlkem.DecapsulationKey1024]{
		"ML-KEM-1024", mlkem.NewDecapsulationKey1024, mlkem.NewEncapsulationKey1024, mlkemtest.Encapsulate1024,
	})
}

func label() string { return impl }

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestKnownAnswers checks that the functions being timed really are ML-KEM,
// with answers that the Rust tests reproduce too, so a mislabelled or broken
// build fails the run instead of passing as a throughput figure:
//
//   - the encapsulation key that the seed of Project Wycheproof's first
//     key-generation case makes (the hash of it is Wycheproof's);
//   - the key, ciphertext and secret of the benchmark's seed and message, which
//     OpenSSL 3.6 makes too.
//
// It also decapsulates a ciphertext that is not good, and checks that the
// result is a secret, the same one every time, and not the good one. (There is
// no ML-KEM-512 in Go; the Rust test has the OpenSSL answers for that set.)
func TestKnownAnswers(t *testing.T) {
	wycheproofSeed, _ := hex.DecodeString("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f")

	checkSet(t, set[*mlkem.EncapsulationKey768, *mlkem.DecapsulationKey768]{
		"ML-KEM-768", mlkem.NewDecapsulationKey768, mlkem.NewEncapsulationKey768, mlkemtest.Encapsulate768,
	}, wycheproofSeed, knownAnswer{
		wycheproofEK: "86adbca81f4fee893e2fb58fb98aa2fe188f501fed268d7f4056f8c05c4e53c4",
		ek:           "3551836042378fc51134435724fcf6d3ac6531d5d22a4d1fc75c8fe26f3dfea2",
		c:            "5df7b3192c32af799acc6c9293f1c4249f550b92f40de6b7e3dea8e2b2c08a90",
		k:            "c94802d6a83178e950663f680924c90a81d942500a2b78311f30a4a65d4e86d5",
	})
	checkSet(t, set[*mlkem.EncapsulationKey1024, *mlkem.DecapsulationKey1024]{
		"ML-KEM-1024", mlkem.NewDecapsulationKey1024, mlkem.NewEncapsulationKey1024, mlkemtest.Encapsulate1024,
	}, wycheproofSeed, knownAnswer{
		wycheproofEK: "61b95ec8c32ae85ad7a17ae5b9c2dfb083e05f767da3ba9a0a8092ea6b4cbf7a",
		ek:           "58ac67963c019909dc04bc575bc07ca0b2812fc20e38323a50e3b0b6fb23664b",
		c:            "7bcbe35dbf7b276145cbb53eeb2f9e75472933e903477237d7cd4b99d785e6c4",
		k:            "1f7a3dcc9117d97a0f5c4f442472084283825c9b3fef98b67117ead40fb2854f",
	})
}

// knownAnswer is what a correct implementation makes: hashes (SHA-256) of the
// encapsulation key of Wycheproof's seed, and of the key and the ciphertext of
// the benchmark's seed and message, and the secret that goes with them.
type knownAnswer struct {
	wycheproofEK, ek, c, k string
}

func checkSet[E encapsulationKey, D decapsulationKey[E]](t *testing.T, s set[E, D], wycheproofSeed []byte, want knownAnswer) {
	wycheproof, err := s.newDecapsulationKey(wycheproofSeed)
	if err != nil {
		t.Fatal(err)
	}
	if got := sum(wycheproof.EncapsulationKey().Bytes()); got != want.wycheproofEK {
		t.Errorf("%s: Wycheproof's encapsulation key hash %s, want %s", s.name, got, want.wycheproofEK)
	}

	key, err := s.newDecapsulationKey(seed())
	if err != nil {
		t.Fatal(err)
	}
	if got := sum(key.EncapsulationKey().Bytes()); got != want.ek {
		t.Errorf("%s: encapsulation key hash %s, want %s", s.name, got, want.ek)
	}
	secret, ciphertext, err := s.encapsulate(key.EncapsulationKey(), message())
	if err != nil {
		t.Fatal(err)
	}
	if got := sum(ciphertext); got != want.c {
		t.Errorf("%s: ciphertext hash %s, want %s", s.name, got, want.c)
	}
	if got := hex.EncodeToString(secret); got != want.k {
		t.Errorf("%s: secret %s, want %s", s.name, got, want.k)
	}
	if got, err := key.Decapsulate(ciphertext); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("%s: the ciphertext does not decapsulate to its secret: %v", s.name, err)
	}

	// A ciphertext that is not good gives a secret of its own, the same every time.
	changed := bytes.Clone(ciphertext)
	changed[0] ^= 1
	first, err := key.Decapsulate(changed)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := key.Decapsulate(changed)
	if !bytes.Equal(first, second) || bytes.Equal(first, secret) || len(first) != 32 {
		t.Errorf("%s: implicit rejection did not give a secret of its own", s.name)
	}
}
