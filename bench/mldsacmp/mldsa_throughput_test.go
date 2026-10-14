// Throughput comparison counterpart to the Rust `throughput` test in
// src/mldsa/keypair.rs: the same five operations on the same key, timed the same
// way, so the reported microseconds per operation are directly comparable.
//
// The operations are those of a signer and a verifier:
//
//	new private key     mldsa.NewPrivateKey: expands a seed into the matrix A,
//	                    the secret vectors and the public key
//	                    (cryptors: PrivateKey::from_seed)
//	new public key      mldsa.NewPublicKey: checks the length and hashes the key
//	                    (PublicKey::from_bytes)
//	sign                PrivateKey.Sign: a hedged signature, with its 32 random
//	                    bytes from the system random source
//	                    (PrivateKey::sign, with a cheap generator)
//	sign deterministic  PrivateKey.SignDeterministic
//	                    (PrivateKey::sign_deterministic)
//	verify              mldsa.Verify (PublicKey::verify)
//
// All of them sign and verify a message of 64 bytes with an empty context. The
// signing rows go through 256 different messages in turn, because how many
// attempts a signature takes depends on the message (a signature is made by
// rejection sampling, and the average is four to five attempts for the three
// parameter sets): one message would time that message. A batch of about 100 ms
// holds more signatures than that, so each batch signs all of them, and the
// deterministic row does the same work on both sides, signature for signature.
//
// The "sign" row of the Rust side reads its 32 random bytes from a cheap
// generator (xorshift64*), and this side reads them from the system, which
// crypto/mldsa does whatever reader it is given: the cost of one read of 32
// bytes is a fraction of a microsecond here. The signatures of the two sides
// differ, as any two hedged signatures do.
//
// Each row is run for about 50 ms to size a batch of about 100 ms, and the best
// of five batches is reported. The first 8 bytes of the deterministic signature
// of the first message are printed, and are the same for every correct
// implementation given the same key; the Rust test prints them too.
//
// `go test -tags purego` makes crypto/mldsa run on a portable Keccak instead of
// the assembly one. impl (set in impl_*_test.go) names which of the two this run
// measured.
package mldsacmp

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

var sink byte

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

type set struct {
	name   string
	params mldsa.Parameters
}

var sets = []set{
	{"ML-DSA-44", mldsa.MLDSA44()},
	{"ML-DSA-65", mldsa.MLDSA65()},
	{"ML-DSA-87", mldsa.MLDSA87()},
}

// seed is the private key of the benchmark: the pattern that the Rust test
// builds.
func seed() []byte {
	s := make([]byte, mldsa.PrivateKeySize)
	for i := range s {
		s[i] = byte(i*37 + 11)
	}
	return s
}

// messages are the 256 messages of 64 bytes that the signing rows go through:
// the Rust test builds the same.
func messages() [][]byte {
	out := make([][]byte, 256)
	for i := range out {
		out[i] = make([]byte, 64)
		for j := range out[i] {
			out[i][j] = byte(3*i + j)
		}
	}
	return out
}

func TestThroughput(t *testing.T) {
	msgs := messages()
	for _, s := range sets {
		key, err := mldsa.NewPrivateKey(s.params, seed())
		if err != nil {
			t.Fatal(err)
		}
		public := key.PublicKey().Bytes()
		publicKey, err := mldsa.NewPublicKey(s.params, public)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := key.SignDeterministic(msgs[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := mldsa.Verify(publicKey, msgs[0], signature, nil); err != nil {
			t.Fatalf("%s: the deterministic signature does not verify: %v", s.name, err)
		}
		hedged, err := key.Sign(nil, msgs[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := mldsa.Verify(publicKey, msgs[0], hedged, nil); err != nil {
			t.Fatalf("%s: the hedged signature does not verify: %v", s.name, err)
		}

		nextHedged, nextDeterministic := 0, 0
		rows := []struct {
			name string
			op   func()
		}{
			{"new private key", func() {
				k, _ := mldsa.NewPrivateKey(s.params, seed())
				sink ^= k.Bytes()[0]
			}},
			{"new public key", func() {
				p, _ := mldsa.NewPublicKey(s.params, public)
				sink ^= p.Bytes()[0]
			}},
			{"sign", func() {
				nextHedged = (nextHedged + 1) % len(msgs)
				sig, _ := key.Sign(nil, msgs[nextHedged], nil)
				sink ^= sig[0]
			}},
			{"sign deterministic", func() {
				nextDeterministic = (nextDeterministic + 1) % len(msgs)
				sig, _ := key.SignDeterministic(msgs[nextDeterministic], nil)
				sink ^= sig[0]
			}},
			{"verify", func() {
				if mldsa.Verify(publicKey, msgs[0], signature, nil) == nil {
					sink ^= 1
				}
			}},
		}
		for _, r := range rows {
			micros := timeOp(r.op)
			fmt.Printf("%s %s [%s]: best %.1f us/op, %.0f ops/s (signature %x...)\n",
				s.name, r.name, label(), micros, 1e6/micros, signature[:8])
		}
	}
}

func label() string { return impl }

// TestKnownAnswers checks that the functions being timed really are ML-DSA,
// with the first deterministic signature of Project Wycheproof's signing files
// (test 1, "baseline": the seed of 32 bytes of 0x2a and the message "Hello
// world", with an empty context), which the Rust tests reproduce too, so a
// mislabelled or broken build fails the run instead of passing as a throughput
// figure.
func TestKnownAnswers(t *testing.T) {
	vectors := []struct {
		set       string
		publicKey string // SHA-256 of the public key
		signature string // SHA-256 of the signature
	}{
		{"ML-DSA-44",
			"d87f8ca136ac1aa55e2d6c4521680efb3a378cbb9bc0bfb446e9c60893931ea3",
			"8cd6fc03daa72e87210a4e721523e84c14f27733789075e65736744d4787fdd5"},
		{"ML-DSA-65",
			"b7acce2ddb11f8cc1aa46e2bafac6eacfa2b732ef192bd636ad8d3a56d649c66",
			"39fbbb0d97a52c79844213b325af823a7f16a174e00a5b3daeb3e6e6d1c89681"},
		{"ML-DSA-87",
			"d43128fa8a8c785c1d44c9e7db538dbf9dd88fe6c8ad911a344bcec1017c6d54",
			"1ad45bd0419e694375bd38ec11d8e0c228ab9ffac2fce4adbe6218d9c949e293"},
	}
	seed := bytes.Repeat([]byte{0x2a}, 32)
	message := []byte("Hello world")
	for _, v := range vectors {
		var params mldsa.Parameters
		for _, s := range sets {
			if s.name == v.set {
				params = s.params
			}
		}
		key, err := mldsa.NewPrivateKey(params, seed)
		if err != nil {
			t.Fatal(err)
		}
		publicKey := sha256.Sum256(key.PublicKey().Bytes())
		if got := hex.EncodeToString(publicKey[:]); got != v.publicKey {
			t.Errorf("%s: public key hash %s, want %s", v.set, got, v.publicKey)
		}
		signature, err := key.SignDeterministic(message, nil)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(signature)
		if got := hex.EncodeToString(sum[:]); got != v.signature {
			t.Errorf("%s: signature hash %s, want %s", v.set, got, v.signature)
		}
		if err := mldsa.Verify(key.PublicKey(), message, signature, nil); err != nil {
			t.Errorf("%s: %v", v.set, err)
		}
		// A different context is a different signature.
		withContext, err := key.SignDeterministic(message, &mldsa.Options{Context: "ctx"})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(withContext, signature) {
			t.Errorf("%s: the context changed nothing", v.set)
		}
		if err := mldsa.Verify(key.PublicKey(), message, withContext, &mldsa.Options{Context: "ctx"}); err != nil {
			t.Errorf("%s: %v", v.set, err)
		}
	}
}
