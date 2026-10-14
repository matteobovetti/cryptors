// Throughput comparison counterpart to the Rust `throughput` test in
// src/rc4/cipher.rs: same buffer size, same input, same warm-up, and same
// best-of-5 methodology, so the reported MiB/s numbers are directly
// comparable.
//
// RC4 is a stream cipher, so the whole buffer goes through one call of
// XORKeyStream, in place. The keystream runs on from one pass to the next and
// the passes are not undone, so the first bytes printed at the end identify the
// whole run. It is the same for every implementation that is correct, and the
// Rust test prints the same figure for the same input.
//
// crypto/rc4 is portable Go on every platform: it has no assembly, so unlike
// crypto/aes there is no `-tags purego` counterpart to run, and one Go figure
// stands against the one Rust implementation.
//
// Any GODEBUG setting is appended to the label, so such a run cannot be
// mistaken for the default one.
package rc4cmp

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

// impl names what is being timed.
const impl = "Go crypto/rc4"

func TestThroughput(t *testing.T) {
	const size = 32 * 1024 * 1024

	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	mib := float64(size) / (1024.0 * 1024.0)

	label := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		label += ", GODEBUG=" + godebug
	}

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Warm up: a cold pass over a fresh buffer measures page faults as much as
	// the cipher itself.
	cipher.XORKeyStream(data, data)

	var best float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		cipher.XORKeyStream(data, data)
		if tp := mib / time.Since(start).Seconds(); tp > best {
			best = tp
		}
	}
	fmt.Printf("rc4 [%s]: %.0f MiB, best %.1f MiB/s (first bytes %x...)\n",
		label, mib, best, data[:16])

	// The Rust test must have printed the same bytes. They were also computed
	// with OpenSSL (`openssl enc -rc4` with the legacy provider), so a broken
	// build fails instead of passing as a figure.
	if got, want := fmt.Sprintf("%x", data[:16]), "35646a449a501195eeb6fa0e0eb74ec2"; got != want {
		t.Errorf("first bytes after six passes = %s, want %s", got, want)
	}
}

// TestKnownAnswers checks that the function being timed really is RC4, with
// RFC 6229's first vector and the three examples of Wikipedia, and with the
// SHA-256 of the keystream under every length of key that
// `every_key_length` in src/rc4/cipher.rs expects.
func TestKnownAnswers(t *testing.T) {
	key, _ := hex.DecodeString("0102030405")
	c, err := rc4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := make([]byte, 16)
	c.XORKeyStream(stream, stream)
	if got, want := fmt.Sprintf("%x", stream), "b2396305f03dc027ccc3524a0a1118a8"; got != want {
		t.Errorf("RFC 6229, key 0102030405: %s, want %s", got, want)
	}

	messages := []struct{ key, plaintext, want string }{
		{"Key", "Plaintext", "bbf316e8d940af0ad3"},
		{"Wiki", "pedia", "1021bf0420"},
		{"Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"},
	}
	for _, m := range messages {
		c, err := rc4.NewCipher([]byte(m.key))
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(m.plaintext))
		c.XORKeyStream(got, []byte(m.plaintext))
		if fmt.Sprintf("%x", got) != m.want {
			t.Errorf("key %q: %x, want %s", m.key, got, m.want)
		}
	}

	h := sha256.New()
	for n := 1; n <= 256; n++ {
		k := make([]byte, n)
		for i := range k {
			k[i] = byte(i*7 + n*13 + 5)
		}
		c, err := rc4.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 300)
		c.XORKeyStream(b, b)
		h.Write(b)
	}
	if got, want := fmt.Sprintf("%x", h.Sum(nil)), "a8bb54507f36397bf013fc5cc7538a5ddad0b1f813cd986bd949a7b7e78342b1"; got != want {
		t.Errorf("every key length: %s, want %s", got, want)
	}
}
