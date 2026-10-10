// Throughput comparison counterpart to the Rust `throughput` test in
// src/ecdsa/keypair.rs: the same five operations on the same key and digest,
// timed the same way, so the reported microseconds per operation are directly
// comparable.
//
// The operations are those of a signer and a verifier:
//
//	new private key     ecdsa.ParseRawPrivateKey: checks the scalar and
//	                    multiplies the generator by it, to have the public key
//	                    (cryptors: PrivateKey::from_bytes)
//	new public key      ecdsa.ParseUncompressedPublicKey: decodes a point and
//	                    checks that it is on the curve (PublicKey::from_bytes)
//	sign                ecdsa.SignASN1: a randomized signature, in DER
//	                    (PrivateKey::sign_prehash, then Signature::to_der)
//	sign deterministic  PrivateKey.Sign with no reader: the deterministic
//	                    signature of RFC 6979, in DER
//	                    (PrivateKey::sign_prehash_deterministic, then to_der)
//	verify              ecdsa.VerifyASN1: decodes a DER signature and checks
//	                    it (Signature::from_der, then PublicKey::verify_prehash)
//
// Both sides sign and verify a digest: the 64-byte message is hashed once,
// outside the timed calls, with SHA-256 for P-224 and P-256, SHA-384 for P-384
// and SHA-512 for P-521.
//
// The "sign" row of both sides excludes the cost of the system random source:
// the bytes that the signer mixes into its nonce come from a cheap xorshift64*
// reader, the same one on both sides. crypto/ecdsa ignores the reader it is
// given, and reads the system random source instead, unless
// GODEBUG=cryptocustomrand=1, so TestThroughput sets that for itself.
//
// Each is run for about 50 ms to size a batch of about 100 ms, and the best of
// five batches is reported. The first 8 bytes of the deterministic signature,
// in DER, are printed, and are the same for every correct implementation given
// the same key and digest; the Rust test prints them too.
//
// `go test -tags purego` makes crypto/ecdsa skip its assembly and run its
// portable code instead. impl (set in impl_*_test.go) names which of the two
// this run measured. Any GODEBUG setting the run was started with is appended
// to the label, so such a run cannot be mistaken for the default one; the
// cryptocustomrand=1 that the tests add is not, as every run has it.
package ecdsacmp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256" // crypto.SHA256, for Sign and sum
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"
	"time"
)

// curve is one of the curves of the Rust test, with the length of its scalars
// and the hash its messages are signed with.
type curve struct {
	name  string
	curve elliptic.Curve
	n     int
	hash  crypto.Hash
}

var curves = []curve{
	{"P-224", elliptic.P224(), 28, crypto.SHA256},
	{"P-256", elliptic.P256(), 32, crypto.SHA256},
	{"P-384", elliptic.P384(), 48, crypto.SHA384},
	{"P-521", elliptic.P521(), 66, crypto.SHA512},
}

func curveNamed(t *testing.T, name string) curve {
	for _, c := range curves {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no curve named %s", name)
	return curve{}
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

// customRand makes crypto/ecdsa read the reader it is given for the rest of
// the test. Whatever the run's GODEBUG set stays in effect: of two settings of
// the same name, the last one counts.
func customRand(t *testing.T) {
	setting := "cryptocustomrand=1"
	if godebug != "" {
		setting = godebug + "," + setting
	}
	t.Setenv("GODEBUG", setting)
}

// scalar is a private key of n bytes that is valid on every curve here: a fixed
// pattern with a top byte below the order of each. The Rust test builds the
// same bytes.
func scalar(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(seed + i*37)
	}
	if n == 66 {
		b[0] = 0x01
	} else {
		b[0] = 0x7f
	}
	return b
}

// sum is the digest of message under h.
func sum(h crypto.Hash, message []byte) []byte {
	d := h.New()
	d.Write(message)
	return d.Sum(nil)
}

// noise is a cheap source of bytes for the randomized signature, so that the
// time measured is the signing and not the system random source: xorshift64*,
// the Noise reader of the Rust test, from the same starting state, so that
// both sides read the same bytes.
type noise uint64

func (r *noise) Read(p []byte) (int, error) {
	// crypto/ecdsa reads one byte from a reader it is given, half of the time
	// and at random (randutil.MaybeReadByte), and throws it away. Answering
	// that read without taking a byte from the stream keeps the bytes the
	// signer reads the same as on the Rust side, where there is no such read.
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
		micros := float64(time.Since(start).Microseconds()) / float64(batch)
		if best == 0 || micros < best {
			best = micros
		}
	}
	return best
}

func TestThroughput(t *testing.T) {
	customRand(t)
	message := make([]byte, 64)
	for i := range message {
		message[i] = byte(i)
	}

	for _, c := range curves {
		private := scalar(c.n, 11)
		key, err := ecdsa.ParseRawPrivateKey(c.curve, private)
		if err != nil {
			t.Fatal(err)
		}
		public, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(c.curve, public); err != nil {
			t.Fatal(err)
		}

		digest := sum(c.hash, message)
		der, err := key.Sign(nil, digest, c.hash)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
			t.Fatalf("%s: the deterministic signature does not verify", c.name)
		}

		// With the same bytes from the reader, the same signature: the
		// reader is what the signer reads, not the system random source.
		first, second := noise(0x9e3779b97f4a7c15), noise(0x9e3779b97f4a7c15)
		hedged, err := ecdsa.SignASN1(&first, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ecdsa.SignASN1(&second, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hedged, again) {
			t.Fatalf("%s: crypto/ecdsa did not sign with the bytes of the reader", c.name)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest, hedged) {
			t.Fatalf("%s: the randomized signature does not verify", c.name)
		}

		rng := noise(0x9e3779b97f4a7c15)
		rows := []struct {
			name string
			op   func()
		}{
			{"new private key", func() {
				k, _ := ecdsa.ParseRawPrivateKey(c.curve, private)
				sink ^= byte(k.X.Uint64())
			}},
			{"new public key", func() {
				p, _ := ecdsa.ParseUncompressedPublicKey(c.curve, public)
				sink ^= byte(p.X.Uint64())
			}},
			{"sign", func() {
				s, _ := ecdsa.SignASN1(&rng, key, digest)
				sink ^= s[len(s)-1]
			}},
			{"sign deterministic", func() {
				s, _ := key.Sign(nil, digest, c.hash)
				sink ^= s[len(s)-1]
			}},
			{"verify", func() {
				if ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
					sink ^= 1
				}
			}},
		}
		for _, r := range rows {
			micros := timeOp(r.op)
			fmt.Printf("%s %s [%s]: best %.1f us/op, %.0f ops/s (signature %x...)\n",
				c.name, r.name, label(), micros, 1e6/micros, der[:8])
		}
	}
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rs returns the two numbers of a DER signature, each as a big-endian string
// of n bytes: r || s, the form of the Rust Signature::as_bytes.
func rs(t *testing.T, der []byte, n int) (r, s []byte) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes after the signature", len(rest))
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 8*n || sig.S.BitLen() > 8*n {
		t.Fatalf("signature out of range: %x", der)
	}
	return sig.R.FillBytes(make([]byte, n)), sig.S.FillBytes(make([]byte, n))
}

// TestKnownAnswers checks that the functions being timed really are ECDSA, with
// deterministic signatures of RFC 6979, appendix A.2 (the RFC6979 rows of
// src/ecdsa/vectors.rs that use the hashes of TestThroughput), so a
// mislabelled or broken build fails the run instead of passing as a
// throughput figure.
func TestKnownAnswers(t *testing.T) {
	vectors := []struct {
		curve                 string
		hash                  crypto.Hash
		message               string
		private, public, r, s string
	}{
		{
			"P-224", crypto.SHA256, "sample",
			"f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1",
			"0400cf08da5ad719e42707fa431292dea11244d64fc51610d94b130d6ceeab6f3debe455e3dbf85416f7030cbd94f34f2d6f232c69f3c1385a",
			"61aa3da010e8e8406c656bc477a7a7189895e7e840cdfe8ff42307ba",
			"bc814050dab5d23770879494f9e0a680dc1af7161991bde692b10101",
		},
		{
			"P-256", crypto.SHA256, "sample",
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
			"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
			"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
			"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
		},
		{
			"P-256", crypto.SHA256, "test",
			"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
			"0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
			"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
			"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
		},
		{
			"P-384", crypto.SHA384, "sample",
			"6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
			"04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
			"94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
			"99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
		},
		{
			"P-521", crypto.SHA512, "sample",
			"00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
			"0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
			"00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa",
			"00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a",
		},
	}
	for _, v := range vectors {
		c := curveNamed(t, v.curve)
		what := fmt.Sprintf("%s %v %q", v.curve, v.hash, v.message)

		key, err := ecdsa.ParseRawPrivateKey(c.curve, unhex(t, v.private))
		if err != nil {
			t.Fatal(err)
		}
		public, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(public); got != v.public {
			t.Errorf("%s: public key = %s, want %s", what, got, v.public)
		}

		digest := sum(v.hash, []byte(v.message))
		der, err := key.Sign(nil, digest, v.hash)
		if err != nil {
			t.Fatal(err)
		}
		r, s := rs(t, der, c.n)
		if got := hex.EncodeToString(r); got != v.r {
			t.Errorf("%s: r = %s, want %s", what, got, v.r)
		}
		if got := hex.EncodeToString(s); got != v.s {
			t.Errorf("%s: s = %s, want %s", what, got, v.s)
		}

		peer, err := ecdsa.ParseUncompressedPublicKey(c.curve, unhex(t, v.public))
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(peer, digest, der) {
			t.Errorf("%s: the signature does not verify", what)
		}
		if ecdsa.VerifyASN1(peer, sum(v.hash, []byte("another message")), der) {
			t.Errorf("%s: the signature verifies for another message", what)
		}
	}
}

// script is a reader that returns the bytes it was given, in order, then
// fails. It answers the one-byte read of randutil.MaybeReadByte (see noise)
// without taking a byte.
type script []byte

func (r *script) Read(p []byte) (int, error) {
	if len(p) == 1 {
		return 1, nil
	}
	if len(*r) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *r)
	*r = (*r)[n:]
	return n, nil
}

// TestHedged checks the randomized signature, which TestThroughput times with
// bytes of its own, against the HEDGED rows of src/ecdsa/vectors.rs: for a
// private key, a digest and the bytes the signer reads, the DER signature
// (draft-irtf-cfrg-det-sigs-with-noise, section 4, with HMAC_DRBG on SHA-512).
// crypto/ecdsa made them, given these bytes, and the Rust test checks that
// cryptors makes the same ones. The digests are shorter than, as long as and
// longer than the order.
func TestHedged(t *testing.T) {
	customRand(t)
	vectors := []struct {
		curve                               string
		private, digest, entropy, signature string
	}{
		{
			"P-224",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
			"19638b54c0e9ed139208ad86b03da1b04318a73e7c04af123dfd2ac2b0fef644",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be",
			"303d021c420d80bfdea7d87f58833a7b4a2a2021fb1789db394ae207404d2891021d0087bafc7e5b7e3511817d4ff45d04dbb66724b8d35b7d3aa13ef0a3c9",
		},
		{
			"P-224",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
			"7c351c0da11fad2091bc8c2d70ac1f54f378976295f05da348b234d06d63a7373ed056e5aa8dd2f87c28d0b51e8407ebc40c49695c7327397bfd09fd1e24bb5e",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be",
			"303e021d00a3231779df04f425685a5483b3684fd23c2f046ad41d0c93206c900c021d009fa332cc7fd56ead14706e12ce27a2fad16bc9002592e4b4d75e23e0",
		},
		{
			"P-224",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
			"05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be",
			"303e021d00e88ab3b45173190c3688022306f49fb517180a2dff40ce7c6ac050ef021d008cf4cb3413408d60f0fda0d5941242984bba6e9f40e55b9ef078abe9",
		},
		{
			"P-224",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
			"090c0f1215181b1e2124272a2d303336393c3f42",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be",
			"303d021c3531b5634ea71d9522e908204c28491076b4b0920bf964f4a5bf64f4021d00c55721c01179d5a01b3afc84ee05bd25a191891969252df12ff27bbb",
		},
		{
			"P-224",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2",
			"02070c11161b20252a2f34393e43484d52575c61666b70757a7f8489",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be",
			"303d021c497e3ca51283ef70dcd0fb9e3efa1b6b5b51d139a282bb1351b1d13d021d00e24f49350dc78fbe1a08a236eb547cd6cf1c171dd4ef0858fbd10c36",
		},
		{
			"P-256",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
			"19638b54c0e9ed139208ad86b03da1b04318a73e7c04af123dfd2ac2b0fef644",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
			"3045022061308fa7a7cfba81d8cb3ff364984200ae780e29b5f77e1cf13ed3c5cff9d731022100e26dc16ab59efc89a287cc3574c61bfde91690ec258a32cd07608732f49365e5",
		},
		{
			"P-256",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
			"7c351c0da11fad2091bc8c2d70ac1f54f378976295f05da348b234d06d63a7373ed056e5aa8dd2f87c28d0b51e8407ebc40c49695c7327397bfd09fd1e24bb5e",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
			"30440220310e42a4a8ca95479b105fd967723471fe7fa6f6257440b83e99d5c862d2863a02207e87e6028555a77f7ea3d9af7c396ae5b4fd603925664f557b937adba20b63e8",
		},
		{
			"P-256",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
			"05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
			"3046022100c6fb951a51bad08dbc138d230b1314af47ff9d464638063128cfb5a2ef480ec9022100f21a5522d73d0a007bca412761e326dc6104ac04640e00964260d94c2133a603",
		},
		{
			"P-256",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
			"090c0f1215181b1e2124272a2d303336393c3f42",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
			"3045022100a4032590b4f657aa89ed2403ed10d87eea7205b063ab4990cf1568b8cdf878ca02202a06517df1cb0094610e160d7882da40c86b86c100eb85b1459ae68b89357a5e",
		},
		{
			"P-256",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
			"02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989d",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
			"30460221008abb7093bb53dc73d2ecab2d68c6637f3a072807a2f877d4787b19ba039994c7022100c3797ff4f8b996db84752d61e0f0ceb80f8c36ecedb1a398c16d0b55a6f5eba5",
		},
		{
			"P-384",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
			"79038bb1e79c42c8281c670867645d754f07b0f230ddabb7804c1db335682912b4796b25446dc5e942151e4fb1533da6",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
			"30660231008e13c2aceb44322535da82b9c88bf9f0d5b0d2ea86576bc701cb8ac145ac3644f519dc128b32499e7ac94fd8ace28c2f023100bb7ef7d6733266316257a170787fe0ee88fbeb6cef72a7895a21b0909ccd9fb8369110ebd848c7694f3b35667ae8b94f",
		},
		{
			"P-384",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
			"7c351c0da11fad2091bc8c2d70ac1f54f378976295f05da348b234d06d63a7373ed056e5aa8dd2f87c28d0b51e8407ebc40c49695c7327397bfd09fd1e24bb5e",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
			"3065023100959858bda9a71d3ce4acafd1efbffe441b0c79741fd2e1cc013dc147b0d1800fd7cffe6de641646429543d2c723b4c2f0230026675ce0926dccb18c699ef97d0fd7b58b4499a917366ebbf427b4dd681f5a4f7acb115717a9179a7e9b38a352e347d",
		},
		{
			"P-384",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
			"05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
			"3065023100dc64451e480e083e91d25ba229af3423e895a6dfd69613d33eed6fc29fd38c1d7bb926efd9f003a7ded1d816ca887f15023015d31a4edcc832ecdaed1aa380cd8e60f5c137ff5f38c7afac60b45bc0c7ad45e17bcc8956562b2b903c562e3b17bf35",
		},
		{
			"P-384",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
			"090c0f1215181b1e2124272a2d303336393c3f42",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
			"30640230378252b7ef2918df0d9fc5de4f269778ae9a5d29e5a21c25ae8973b0aca6a40959777c69139efa24e6911b4dabf258c602300f3aca62929cc824fd8b701db915f01bc8e587de7c9c155a7c62d065a0a5569e1e29e360d28e03751010dad4148aadbd",
		},
		{
			"P-384",
			"7f30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
			"02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8ed",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
			"306402301d2987c78092553e32dfea4a105e9c47e3aaf2aa1f4251eed7130981b595dc096920cbc1c647bcceab9e5de51ffc4cc0023021ae5540676927daf980797312c903a3d847e486c1cd6a6c6857c8d8c1bda84adaeedcf9e70db5d22b2f15875f18d096",
		},
		{
			"P-521",
			"0130557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b70",
			"7c351c0da11fad2091bc8c2d70ac1f54f378976295f05da348b234d06d63a7373ed056e5aa8dd2f87c28d0b51e8407ebc40c49695c7327397bfd09fd1e24bb5e",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8",
			"308187024200eaf12548992a0b420d95290d8afdd2650561905837e746220095df22992f32cdb0563e183b7b71da938bbd90fdb32aa48c59a65d2f981b07658d89cd83edf6bbf40241290bfd3e42a692df14bc0f36b837fc454944e36f5f006279800afbefc755e2463a114cb2b59187c6fb00656047f07f858a38ddaf3fe788bcd91c445ea101437e39",
		},
		{
			"P-521",
			"0130557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b70",
			"05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8",
			"30818602412d97d832bf8ddae297e20897e4924a5013c5ec5b1d42e0bdae4c3caa2aa743cfa5dbe8d7590dec1808e7a5c8756a0b6df833d10662089bbe850815b6a8d438c5be024151bb075f32fca207bdf55f279aca184485ea20682f41050c3e5d7930a01eb403f84a817bb62dc6b37dbaa825442705aaec6291101c17d86fa7f76dac060982bde0",
		},
		{
			"P-521",
			"0130557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b70",
			"090c0f1215181b1e2124272a2d303336393c3f42",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8",
			"308187024201c2007809c333eeabc10d224c182c3a06e43ae47d1a43a31892443ca1cc44a8e741825c7d9bf6a36eff9f98deea09e454df8dd5034ca14445e126a353614003cebb02417c00d6a5d155ea943170b209d922e74b5ae3ea56efc9717c6b843a326a6bd866f084c44d1bd8496d2ce90168578a69f4e44675fce4c22e4eb0ff127f0eef69d4b0",
		},
		{
			"P-521",
			"0130557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b70",
			"02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d4247",
			"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8",
			"308188024200a353c7955ee6878320b86bd8bb18b1dc1ad999107aecb7ba4c7bbf7d3e931e4c5fd516f05952ef8a1146c09048fe14c236545e655bbfc16e5dfa48e6d77155c84c024201b9c6459d64b7d5b559a0158f7470773c731a9778e3365e91a9b29fd899d7bb7a27dd220a488499324bddb16ed7b4472f3ee7d3a16cad43907b79403d1055dc254d",
		},
	}
	for _, v := range vectors {
		c := curveNamed(t, v.curve)
		what := fmt.Sprintf("%s digest of %d bytes", v.curve, len(v.digest)/2)

		key, err := ecdsa.ParseRawPrivateKey(c.curve, unhex(t, v.private))
		if err != nil {
			t.Fatal(err)
		}
		entropy := script(unhex(t, v.entropy))
		digest := unhex(t, v.digest)
		der, err := ecdsa.SignASN1(&entropy, key, digest)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(entropy) != 0 {
			t.Errorf("%s: %d of the bytes were not read", what, len(entropy))
		}
		if got := hex.EncodeToString(der); got != v.signature {
			t.Errorf("%s: signature = %s, want %s", what, got, v.signature)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
			t.Errorf("%s: the signature does not verify", what)
		}
	}
}

// chainSteps is CHAIN_STEPS of src/ecdsa/vectors.rs.
const chainSteps = 16

// chain runs the chained-signatures test of src/ecdsa/keypair.rs (see `derive`
// and `check_chain` there): in each round a key derived from the state, with
// SHA-512, signs the state with deterministic ECDSA, and the next state is the
// SHA-512 of the state, the signature (r || s) and the public key. The two
// values it reaches, after the first round and after the last, are those the
// Rust test expects, which OpenSSL produced.
func chain(t *testing.T, c curve, h crypto.Hash) (afterFirst, last string) {
	mask := byte(0xff)
	if c.n == 66 {
		mask = 0x01 // the order of P-521 has 521 bits
	}

	derive := func(state []byte) *ecdsa.PrivateKey {
		for counter := 0; counter < 256; counter++ {
			var material []byte
			for part := byte(0); part < 2; part++ {
				d := sha512.Sum512(append(append([]byte{}, state...), 0, byte(counter), part))
				material = append(material, d[:]...)
			}
			candidate := append([]byte{}, material[:c.n]...)
			candidate[0] &= mask
			if key, err := ecdsa.ParseRawPrivateKey(c.curve, candidate); err == nil {
				return key
			}
		}
		t.Fatal("256 candidates in a row were refused")
		return nil
	}

	start := sha512.Sum512([]byte("cryptors ecdsa chain " + c.name))
	state := start[:]
	for round := 0; round < chainSteps; round++ {
		key := derive(state)
		digest := sum(h, state)
		der, err := key.Sign(nil, digest, h)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
			t.Fatalf("%s: round %d does not verify", c.name, round)
		}
		r, s := rs(t, der, c.n)
		public, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		input := append(append([]byte{}, state...), r...)
		input = append(input, s...)
		input = append(input, public...)
		next := sha512.Sum512(input)
		state = next[:]
		if round == 0 {
			afterFirst = hex.EncodeToString(state)
		}
	}
	return afterFirst, hex.EncodeToString(state)
}

func TestChain(t *testing.T) {
	want := []struct {
		curve       string
		hash        crypto.Hash
		first, last string
	}{
		{"P-224", crypto.SHA256, "69c5f70e2d0b5fd851383563bac0c80344f79047c81a8b9d436796d726e12c070d3c7763aa06f3e9f976355fcdabac422a6f9540f4d77a56094805d8996c34b5", "d95402b92f4f79abd398b5f1ad21636585dcb55ed6ac42ca220efcafe39fdc631f3c06e9a2825f729dfb109f65e30bfbb0773a86c3ae2cc062abc4dbb86d5b53"},
		{"P-256", crypto.SHA256, "eb3842c99e94db32963e872fa0297c2b64c6aa1af2d464a5444d5539bdaa673a92dc2ac7a518f8043514380377e95738d6748d996698358d155157546a2c5642", "b736e6f26041614f576977eb9746ef273c7da3804651ea0777b8a635fd1be98d0fffa06711698c777576ad5f0f43ea5a3dd8a8d869bcebb0449d698ba97c70c8"},
		{"P-384", crypto.SHA384, "8b4113334ceefaf41322c321be99c2478a2d882d91430b05905b2b16c1090e7558ded7bc9e275886ddf0e8f8a60a78f398eda569779be18d0f377592e466eeb2", "c8685dce458a66ac78eed77b00008e54bc355dabd06d879d7154c327faf0677410f7c6050e62e413f9803421de729e64c306163f63c719f6f6355b1f5531b18f"},
		{"P-521", crypto.SHA512, "d76d94e6f549f2c63db6272e37420cf2d4df692cf57212e398fc3b958a29510853602f00a81616da2dd87aa43b067f1de50329d0602afe92f243e2a43343777d", "b8520773f45274e4244f89f6c11353a02da3fbccc8441146bf44f486a942b5685a6285da5f2a847e33e707226c9bebb37e00eff2cf57980f781d5f38350d140c"},
	}
	for _, w := range want {
		first, last := chain(t, curveNamed(t, w.curve), w.hash)
		if first != w.first || last != w.last {
			t.Errorf("%s chain = %s, %s; want %s, %s", w.curve, first, last, w.first, w.last)
		}
	}
}
