// Throughput comparison counterpart to the Rust `throughput` test in
// src/rsa/keypair.rs: the same keys, the same inputs and the same operations,
// timed the same way, so the reported microseconds per operation are directly
// comparable.
//
// The keys are the three of src/rsa/testdata/interop.txt that have 2,048, 3,072
// and 4,096 bits (made by OpenSSL), which this reads from there. The operations
// are those of Go's own benchmarks of crypto/rsa (rsa_test.go), on a message of
// 13 bytes ("Hello Gophers") and the SHA-256 digest of "testing":
//
//	new private key   PrivateKey.Precompute on a key with only N, E, D and the
//	                  primes, which runs the checks of FIPS 186-5 and computes the
//	                  numbers of the CRT (cryptors: PrivateKey::from_components)
//	OAEP decrypt      DecryptOAEP with SHA-256 and no label
//	OAEP encrypt      EncryptOAEP with SHA-256 and no label
//	PKCS1v15 decrypt  DecryptPKCS1v15
//	PKCS1v15 encrypt  EncryptPKCS1v15
//	sign PKCS1v15     SignPKCS1v15 of the digest, with SHA-256
//	verify PKCS1v15   VerifyPKCS1v15
//	sign PSS          SignPSS of the digest, with a salt as long as the hash
//	verify PSS        VerifyPSS with the same
//	generate key      GenerateKey for 2,048 bits, from the 708 candidates of
//	                  c2sp.org/CCTV/keygen's benchmark (src/rsa/testdata/
//	                  candidates2048.txt), which make a generation of average length
//
// The cryptors rows have a row more: "new public key", which checks the modulus
// and sets up Montgomery's arithmetic for it. Go has no such row, because it does
// that in every call that uses a public key (encrypt and verify), where cryptors
// does it once per key.
//
// The randomized operations (the two encryptions and the PSS signature) read a
// cheap xorshift64* reader, the same one on both sides, so that the time
// measured is theirs and not the system random source's. crypto/rsa ignores the
// reader it is given, and reads the system random source instead, unless
// GODEBUG=cryptocustomrand=1, so TestThroughput sets that for itself.
//
// Each is run for about 50 ms to size a batch of about 100 ms, and the best of
// five batches is reported. The first 8 bytes of the PKCS #1 v1.5 signature,
// which every correct implementation makes alike, are printed, and the Rust test
// prints them too.
//
// `go test -tags purego` makes crypto/rsa skip its assembly and run its portable
// code instead. impl (set in impl_*_test.go) names which of the two this run
// measured. Any GODEBUG setting the run was started with is appended to the
// label, so such a run cannot be mistaken for the default one; the
// cryptocustomrand=1 that the tests add is not, as every run has it.
package rsacmp

import (
	"bytes"
	"crypto"
	_ "crypto/md5" // crypto.MD5, for the hash table of TestKnownAnswers
	"crypto/rsa"
	_ "crypto/sha1" // crypto.SHA1
	"crypto/sha256"
	_ "crypto/sha512" // crypto.SHA384, SHA512, SHA512_224 and SHA512_256
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// record is a [kind] block of a data file of the Rust tests: key = value lines.
type record struct {
	kind   string
	fields map[string]string
}

// readRecords reads a data file in the form of src/rsa/testdata: records that
// start with [kind] and hold key = value lines, with # for comments.
func readRecords(t testing.TB, path string) []record {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []record
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			records = append(records, record{strings.Trim(line, "[]"), map[string]string{}})
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			t.Fatalf("%s: not a field: %q", path, line)
		}
		records[len(records)-1].fields[key] = value
	}
	return records
}

const (
	interop    = "../../src/rsa/testdata/interop.txt"
	candidates = "../../src/rsa/testdata/candidates2048.txt"
)

func unhex(t testing.TB, s string) []byte {
	if s == "-" {
		return nil
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func number(t testing.TB, s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("not a number: %q", s)
	}
	return n
}

// privateKey builds the key of a [key] record, with N, E, D and the primes
// only, as an application that stores them would have it: Precompute has not
// run.
func privateKey(t testing.TB, r record) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: number(t, r.fields["n"]), E: int(number(t, r.fields["e"]).Int64())},
		D:         number(t, r.fields["d"]),
		Primes:    []*big.Int{number(t, r.fields["p"]), number(t, r.fields["q"])},
	}
}

func keyNamed(t testing.TB, records []record, name string) record {
	for _, r := range records {
		if r.kind == "key" && r.fields["name"] == name {
			return r
		}
	}
	t.Fatalf("no key named %s", name)
	return record{}
}

// godebug is the GODEBUG setting the run was started with, read when the
// package is initialized, before any test adds to it.
var godebug = os.Getenv("GODEBUG")

func label() string {
	l := impl
	if godebug != "" {
		l += ", GODEBUG=" + godebug
	}
	return l
}

// customRand makes crypto/rsa read the reader it is given for the rest of the
// test. Whatever the run's GODEBUG set stays in effect: of two settings of the
// same name, the last one counts.
func customRand(t *testing.T) {
	setting := "cryptocustomrand=1"
	if godebug != "" {
		setting = godebug + "," + setting
	}
	t.Setenv("GODEBUG", setting)
}

// noise is a cheap source of bytes for the randomized operations, so that the
// time measured is the operation and not the system random source: xorshift64*,
// the Noise reader of the Rust test, from the same starting state, so that both
// sides read the same bytes.
type noise uint64

func (r *noise) Read(p []byte) (int, error) {
	// crypto/rsa reads one byte from a reader it is given, half of the time and
	// at random (randutil.MaybeReadByte), and throws it away. Answering that
	// read without taking a byte from the stream keeps the bytes the operation
	// reads the same as on the Rust side, where there is no such read.
	if len(p) == 1 {
		return 1, nil
	}
	for i := range p {
		*r ^= *r >> 12
		*r ^= *r << 25
		*r ^= *r >> 27
		p[i] = byte((*r * 0x2545f4914f6cdd1d) >> 56)
	}
	return len(p), nil
}

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
		micros := float64(time.Since(start).Nanoseconds()) / 1e3 / float64(batch)
		if best == 0 || micros < best {
			best = micros
		}
	}
	return best
}

func TestThroughput(t *testing.T) {
	customRand(t)
	records := readRecords(t, interop)
	message := []byte("Hello Gophers")
	digest := sha256.Sum256([]byte("testing"))

	for _, bits := range []int{2048, 3072, 4096} {
		key := privateKey(t, keyNamed(t, records, fmt.Sprintf("rsa%d", bits)))
		key.Precompute()
		if err := key.Validate(); err != nil {
			t.Fatal(err)
		}
		pub := &key.PublicKey

		rng := noise(0x9e3779b97f4a7c15)
		oaep, err := rsa.EncryptOAEP(sha256.New(), &rng, pub, message, nil)
		if err != nil {
			t.Fatal(err)
		}
		pkcs1, err := rsa.EncryptPKCS1v15(&rng, pub, message)
		if err != nil {
			t.Fatal(err)
		}
		v15, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		pss, err := rsa.SignPSS(&rng, key, crypto.SHA256, digest[:], opts)
		if err != nil {
			t.Fatal(err)
		}

		// With the same bytes from the reader, the same ciphertext and signature:
		// the reader is what the operation reads, not the system random source.
		first, second := noise(1), noise(1)
		a, _ := rsa.EncryptOAEP(sha256.New(), &first, pub, message, nil)
		b, _ := rsa.EncryptOAEP(sha256.New(), &second, pub, message, nil)
		if !bytes.Equal(a, b) {
			t.Fatal("crypto/rsa did not encrypt with the bytes of the reader")
		}

		rng = noise(0x9e3779b97f4a7c15)
		rows := []struct {
			name string
			op   func()
		}{
			{"new private key", func() {
				k := &rsa.PrivateKey{PublicKey: key.PublicKey, D: key.D, Primes: key.Primes}
				k.Precompute()
				sink ^= byte(k.Precomputed.Dp.Uint64())
			}},
			{"OAEP decrypt", func() {
				p, err := rsa.DecryptOAEP(sha256.New(), nil, key, oaep, nil)
				if err != nil || !bytes.Equal(p, message) {
					t.Fatal("OAEP decrypt")
				}
				sink ^= p[0]
			}},
			{"OAEP encrypt", func() {
				c, _ := rsa.EncryptOAEP(sha256.New(), &rng, pub, message, nil)
				sink ^= c[0]
			}},
			{"PKCS1v15 decrypt", func() {
				p, err := rsa.DecryptPKCS1v15(nil, key, pkcs1)
				if err != nil || !bytes.Equal(p, message) {
					t.Fatal("PKCS1v15 decrypt")
				}
				sink ^= p[0]
			}},
			{"PKCS1v15 encrypt", func() {
				c, _ := rsa.EncryptPKCS1v15(&rng, pub, message)
				sink ^= c[0]
			}},
			{"sign PKCS1v15", func() {
				s, _ := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
				sink ^= s[0]
			}},
			{"verify PKCS1v15", func() {
				if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], v15) != nil {
					t.Fatal("verify PKCS1v15")
				}
			}},
			{"sign PSS", func() {
				s, _ := rsa.SignPSS(&rng, key, crypto.SHA256, digest[:], opts)
				sink ^= s[0]
			}},
			{"verify PSS", func() {
				if rsa.VerifyPSS(pub, crypto.SHA256, digest[:], pss, opts) != nil {
					t.Fatal("verify PSS")
				}
			}},
		}
		for _, r := range rows {
			micros := timeOp(r.op)
			fmt.Printf("rsa-%d %s [%s]: best %.1f us/op, %.0f ops/s (signature %x...)\n",
				bits, r.name, label(), micros, 1e6/micros, v15[:8])
		}
	}

	primes, err := os.ReadFile(candidates)
	if err != nil {
		t.Fatal(err)
	}
	micros := timeOp(func() {
		k, err := rsa.GenerateKey(candidateReader(t, string(primes)), 2048)
		if err != nil {
			t.Fatal(err)
		}
		sink ^= byte(k.N.Uint64())
	})
	fmt.Printf("rsa-2048 generate key [%s]: best %.1f us/op, %.2f ops/s\n", label(), micros, 1e6/micros)
}

// candidateReader feeds the prime candidates of a text file, one per line in
// hex, to GenerateKey, one for each read, as Go's own benchmark does.
func candidateReader(t testing.TB, text string) io.Reader {
	return readerFunc(func(p []byte) (int, error) {
		// GenerateKey reads one byte, at random, and throws it away
		// (randutil.MaybeReadByte); that must not use up a line.
		if len(p) == 1 {
			return 1, nil
		}
		var line string
		for line == "" || line[0] == '#' {
			var ok bool
			line, text, ok = strings.Cut(text, "\n")
			if !ok {
				return 0, io.EOF
			}
		}
		b := unhex(t, line)
		if len(b) != len(p) {
			return 0, fmt.Errorf("unexpected read length: %d", len(p))
		}
		copy(p, b)
		return len(p), nil
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// TestKnownAnswers checks that the functions being timed really are RSA, with
// what OpenSSL made with the three keys (src/rsa/testdata/interop.txt, which the
// Rust tests check too): the PKCS #1 v1.5 signatures of "Test.\n" and of the
// longer message there, which are deterministic, the OAEP ciphertexts and the
// PSS signatures; and with the key that the benchmark's candidates make, whose
// modulus and private exponent are pinned in
// `the_benchmark_candidates_make_this_key` in src/rsa/keygen.rs (Python's
// integers make the same). A mislabelled or broken build fails the run instead
// of passing as a throughput figure.
func TestKnownAnswers(t *testing.T) {
	customRand(t)
	records := readRecords(t, interop)
	keys := map[string]*rsa.PrivateKey{}
	for _, r := range records {
		if r.kind == "key" {
			k := privateKey(t, r)
			k.Precompute()
			if err := k.Validate(); err != nil {
				t.Fatalf("%s: %v", r.fields["name"], err)
			}
			keys[r.fields["name"]] = k
		}
	}
	hashes := map[string]crypto.Hash{
		"SHA-1": crypto.SHA1, "SHA-224": crypto.SHA224, "SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384,
		"SHA-512": crypto.SHA512, "SHA-512/224": crypto.SHA512_224, "SHA-512/256": crypto.SHA512_256,
		"MD5": crypto.MD5,
	}
	counts := map[string]int{}
	for _, r := range records {
		f := r.fields
		switch r.kind {
		case "oaep":
			// Go has no OAEP for the SHA-512/t hashes in this file and takes the
			// same hash for MGF1 unless told otherwise.
			opts := &rsa.OAEPOptions{Hash: hashes[f["hash"]], MGFHash: hashes[f["mgf_hash"]], Label: unhex(t, f["label"])}
			got, err := keys[f["key"]].Decrypt(nil, unhex(t, f["ct"]), opts)
			if err != nil || !bytes.Equal(got, unhex(t, f["msg"])) {
				t.Errorf("OAEP %s %s: %x, %v", f["key"], f["hash"], got, err)
			}
		case "pkcs1-encrypt":
			got, err := rsa.DecryptPKCS1v15(nil, keys[f["key"]], unhex(t, f["ct"]))
			if err != nil || !bytes.Equal(got, unhex(t, f["msg"])) {
				t.Errorf("PKCS1v15 decrypt %s: %v", f["key"], err)
			}
		case "pkcs1-sign":
			h := hashes[f["hash"]]
			d := h.New()
			d.Write(unhex(t, f["msg"]))
			sig, err := rsa.SignPKCS1v15(nil, keys[f["key"]], h, d.Sum(nil))
			if err != nil || hex.EncodeToString(sig) != f["sig"] {
				t.Errorf("sign PKCS1v15 %s %s: %x, %v", f["key"], f["hash"], sig, err)
			}
		case "pss":
			h := hashes[f["hash"]]
			d := h.New()
			d.Write(unhex(t, f["msg"]))
			var slen int
			fmt.Sscan(f["slen"], &slen)
			// Go's zero salt length means "detect it", so a signature with none is
			// checked that way, which accepts it too.
			opts := &rsa.PSSOptions{SaltLength: slen}
			if err := rsa.VerifyPSS(&keys[f["key"]].PublicKey, h, d.Sum(nil), unhex(t, f["sig"]), opts); err != nil {
				t.Errorf("verify PSS %s %s %d: %v", f["key"], f["hash"], slen, err)
			}
		case "key":
			continue
		}
		counts[r.kind]++
	}
	if counts["oaep"] != 96 || counts["pkcs1-encrypt"] != 21 || counts["pkcs1-sign"] != 60 || counts["pss"] != 138 {
		t.Errorf("checked %v", counts)
	}

	// The benchmark's candidates make the key whose digests the Rust test pins.
	primes, err := os.ReadFile(candidates)
	if err != nil {
		t.Fatal(err)
	}
	k, err := rsa.GenerateKey(candidateReader(t, string(primes)), 2048)
	if err != nil {
		t.Fatal(err)
	}
	n, d := sha256.Sum256(k.N.FillBytes(make([]byte, 256))), sha256.Sum256(k.D.FillBytes(make([]byte, 256)))
	if got := hex.EncodeToString(n[:]); got != "2b14b537f6c8a92b5005cffc963ab8dd672a92918791aa62cb2c483aa016e6c4" {
		t.Errorf("modulus of the generated key: %s", got)
	}
	if got := hex.EncodeToString(d[:]); got != "d343ce441505b283259746b0915a95b55a5ea03deefc9067241c218c422660a0" {
		t.Errorf("private exponent of the generated key: %s", got)
	}
}
