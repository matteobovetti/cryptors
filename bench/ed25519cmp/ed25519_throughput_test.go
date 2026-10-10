// Throughput comparison counterpart to the Rust `throughput` test in
// src/ed25519/signature.rs: the same operations on the same seed and message,
// timed the same way, so the reported microseconds per operation are directly
// comparable.
//
// The operations are:
//
//	new signing key    NewKeyFromSeed: hashes the seed and multiplies the base
//	                   point, to have the public key (cryptors:
//	                   SigningKey::from_seed)
//	new verifying key  decodes the public key, a point, and nothing else (see
//	                   decodeOnly below) (VerifyingKey::from_bytes)
//	sign               Sign, a 128-byte message (SigningKey::sign)
//	verify             Verify, which takes the public key as bytes and decodes
//	                   it every time (VerifyingKey::from_bytes, then verify)
//
// Each is run for about 50 ms to size a batch of about 100 ms, and the best of
// five batches is reported. The first 8 bytes of the public key and of the
// signature are printed, and are the same for every correct implementation
// given the same seed and message; the Rust test prints them too.
//
// `go test -tags purego` makes crypto/ed25519 skip its assembly: on amd64 the
// field multiplication and SHA-512, on arm64 only SHA-512, as Go has no arm64
// assembly for the curve. impl (set in impl_*_test.go) names which build this
// run measured.
package ed25519cmp

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// sink keeps the compiler from discarding the results of the timed calls.
var sink byte

// timeOp returns the best of five batches of op, in microseconds per call.
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
		micros := time.Since(start).Seconds() * 1e6 / float64(batch)
		if best == 0 || micros < best {
			best = micros
		}
	}
	return best
}

// decodeOnly decodes pub as crypto/ed25519 does at the start of every
// verification, and stops there. The package has no call that only decodes a
// key, but in Go 1.27.1 VerifyWithOptions decodes the key first (it returns
// "bad public key" if that fails) and checks the length of the signature
// after, so an empty signature makes it return just past the decoding.
func decodeOnly(pub ed25519.PublicKey) error {
	return ed25519.VerifyWithOptions(pub, nil, nil, &ed25519.Options{})
}

func TestThroughput(t *testing.T) {
	// The seed 0, 1, ..., 31 and a 128-byte message whose byte i is i.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	message := make([]byte, 128)
	for i := range message {
		message[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, message)
	if err := decodeOnly(pub); err == nil || err.Error() != "ed25519: bad signature length: 0" {
		t.Fatalf("decodeOnly no longer stops after the decoding: %v", err)
	}

	rows := []struct {
		name string
		op   func()
	}{
		{"new signing key", func() {
			sink ^= ed25519.NewKeyFromSeed(seed)[32]
		}},
		{"new verifying key", func() {
			if decodeOnly(pub) == nil {
				sink ^= 1
			}
		}},
		{"sign", func() {
			sink ^= ed25519.Sign(priv, message)[0]
		}},
		{"verify", func() {
			if !ed25519.Verify(pub, message, sig) {
				t.Fatal("signature did not verify")
			}
		}},
	}
	for _, r := range rows {
		micros := timeOp(r.op)
		fmt.Printf("ed25519 %s [%s]: best %.2f us/op, %.0f ops/s (public key %x..., signature %x...)\n",
			r.name, impl, micros, 1e6/micros, pub[:8], sig[:8])
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed), priv) || !bytes.Equal(ed25519.Sign(priv, message), sig) {
		t.Fatal("the timed operations gave different results")
	}
}

// TestKnownAnswers checks that the functions being timed really are Ed25519,
// with RFC 8032 section 7.1, test 1, so a broken build cannot produce a
// figure.
func TestKnownAnswers(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPub := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	wantSig := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pub); got != wantPub {
		t.Errorf("public key = %s, want %s", got, wantPub)
	}
	sig := ed25519.Sign(priv, nil)
	if got := hex.EncodeToString(sig); got != wantSig {
		t.Errorf("signature = %s, want %s", got, wantSig)
	}
	if !ed25519.Verify(pub, nil, sig) {
		t.Error("the RFC's signature does not verify")
	}
}

// TestManyKeys recomputes the vectors of `many_keys` in
// src/ed25519/signature.rs: 256 keys derived from SHA-256, each signing a
// message of i bytes under Ed25519, Ed25519ctx (a context of 1 + i % 255
// bytes) and Ed25519ph (a context of i % 256 bytes), and checks the SHA-256 of
// the outputs against the values the Rust test expects.
func TestManyKeys(t *testing.T) {
	pure, ctx, ph := sha256.New(), sha256.New(), sha256.New()
	for i := 0; i < 256; i++ {
		label := append([]byte("ed25519 seed"), byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		seed := sha256.Sum256(label)
		message := make([]byte, i)
		for j := range message {
			message[j] = byte((i + j) % 251)
		}
		context := make([]byte, 1+i%255)
		for j := range context {
			context[j] = byte(i + 3*j)
		}
		phContext := make([]byte, i%256)
		for j := range phContext {
			phContext[j] = byte(5*i + j)
		}

		priv := ed25519.NewKeyFromSeed(seed[:])
		pure.Write(priv.Public().(ed25519.PublicKey))
		pure.Write(ed25519.Sign(priv, message))
		s, err := priv.Sign(nil, message, &ed25519.Options{Context: string(context)})
		if err != nil {
			t.Fatal(err)
		}
		ctx.Write(s)
		digest := sha512.Sum512(message)
		s, err = priv.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512, Context: string(phContext)})
		if err != nil {
			t.Fatal(err)
		}
		ph.Write(s)
	}
	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{"Ed25519", pure.Sum(nil), "61e2c2076500cdf120cd960371e774695e145342d12662560f6b3fddf9c574f6"},
		{"Ed25519ctx", ctx.Sum(nil), "4b18e9309e673a78c6385fa5f21e4a2ec0b65990e468abf8e147791c6e536e60"},
		{"Ed25519ph", ph.Sum(nil), "364c585f986f31fc18147f6511c62cdf64e77f52856c2835d5f5d851f9662503"},
	} {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s: SHA-256 of the outputs = %s, want %s", c.name, got, c.want)
		}
	}
}
