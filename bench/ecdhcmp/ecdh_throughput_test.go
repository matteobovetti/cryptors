// Throughput comparison counterpart to the Rust `throughput` test in
// src/ecdh/keypair.rs: the same four operations on the same keys, timed the
// same way, so the reported microseconds per operation are directly
// comparable.
//
// The operations are those of one side of a handshake:
//
//	new private key  Curve.NewPrivateKey: checks the scalar and multiplies the
//	                 generator by it, to have the public key (cryptors:
//	                 PrivateKey::from_bytes)
//	new public key   Curve.NewPublicKey: decodes a point and checks that it is
//	                 on the curve (PublicKey::from_bytes)
//	ecdh             PrivateKey.ECDH (PrivateKey::diffie_hellman)
//	handshake        the three in a row
//
// Each is run for about 50 ms to size a batch of about 100 ms, and the best of
// five batches is reported. The first 8 bytes of the shared secret are
// printed, and are the same for every correct implementation given the same
// keys; the Rust test prints them too.
//
// `go test -tags purego` makes crypto/ecdh skip its assembly and run its
// portable code instead. impl (set in impl_*_test.go) names which of the two
// this run measured. Any GODEBUG setting is appended to the label, so such a
// run cannot be mistaken for the default one.
package ecdhcmp

import (
	"crypto/ecdh"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

var curves = []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()}

func label() string {
	l := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		l += ", GODEBUG=" + godebug
	}
	return l
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

func privateKeyLen(c ecdh.Curve) int {
	switch c {
	case ecdh.P384():
		return 48
	case ecdh.P521():
		return 66
	}
	return 32
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
	for _, curve := range curves {
		n := privateKeyLen(curve)
		private := scalar(n, 11)
		peerPrivate, err := curve.NewPrivateKey(scalar(n, 53))
		if err != nil {
			t.Fatal(err)
		}
		peer := peerPrivate.PublicKey().Bytes()

		key, err := curve.NewPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		peerKey, err := curve.NewPublicKey(peer)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := key.ECDH(peerKey)
		if err != nil {
			t.Fatal(err)
		}

		rows := []struct {
			name string
			op   func()
		}{
			{"new private key", func() {
				k, _ := curve.NewPrivateKey(private)
				sink ^= k.PublicKey().Bytes()[0]
			}},
			{"new public key", func() {
				p, _ := curve.NewPublicKey(peer)
				sink ^= p.Bytes()[0]
			}},
			{"ecdh", func() {
				s, _ := key.ECDH(peerKey)
				sink ^= s[0]
			}},
			{"handshake", func() {
				k, _ := curve.NewPrivateKey(private)
				p, _ := curve.NewPublicKey(peer)
				s, _ := k.ECDH(p)
				sink ^= s[0]
			}},
		}
		for _, r := range rows {
			micros := timeOp(r.op)
			fmt.Printf("%s %s [%s]: best %.1f us/op, %.0f ops/s (secret %x...)\n",
				curve, r.name, label(), micros, 1e6/micros, secret[:8])
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

// TestKnownAnswers checks that the functions being timed really are ECDH, with
// the vectors of NIST's CAVS 14.1 (SP 800-56A) and RFC 7748, section 6.1, so a
// mislabelled or broken build fails the run instead of passing as a
// throughput figure.
func TestKnownAnswers(t *testing.T) {
	vectors := []struct {
		curve                       ecdh.Curve
		private, public, peer, want string
	}{
		{
			ecdh.P256(),
			"7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
			"04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230" +
				"28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
			"04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287" +
				"db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
			"46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
		},
		{
			ecdh.P384(),
			"3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
			"049803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f" +
				"ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
			"04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066" +
				"ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
			"5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
		},
		{
			ecdh.P521(),
			"017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
			"0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5" +
				"01b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
			"0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d" +
				"01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
			"005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
		},
		{
			ecdh.X25519(),
			"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
			"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
		},
	}
	for _, v := range vectors {
		key, err := v.curve.NewPrivateKey(unhex(t, v.private))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", key.PublicKey().Bytes()); got != v.public {
			t.Errorf("%s public key = %s, want %s", v.curve, got, v.public)
		}
		peer, err := v.curve.NewPublicKey(unhex(t, v.peer))
		if err != nil {
			t.Fatal(err)
		}
		secret, err := key.ECDH(peer)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", secret); got != v.want {
			t.Errorf("%s secret = %s, want %s", v.curve, got, v.want)
		}
	}
}

// chain derives, with SHA-512, the keys of the chained test in
// src/ecdh/keypair.rs (see `derive` and `check_chain` there) and runs it:
// rounds of two derived keys exchanging with each other, each round seeded by
// the hash of the last. The two values it reaches, after the first round and
// after the last, are those the Rust test expects, which OpenSSL produced.
func chain(t *testing.T, curve ecdh.Curve, mask byte) (afterFirst, last string) {
	const rounds = 16
	n := privateKeyLen(curve)

	derive := func(state []byte, which byte) *ecdh.PrivateKey {
		for counter := 0; counter < 256; counter++ {
			var material []byte
			for part := byte(0); part < 2; part++ {
				h := sha512.Sum512(append(append([]byte{}, state...), which, byte(counter), part))
				material = append(material, h[:]...)
			}
			candidate := append([]byte{}, material[:n]...)
			candidate[0] &= mask
			if key, err := curve.NewPrivateKey(candidate); err == nil {
				return key
			}
		}
		t.Fatal("256 candidates in a row were refused")
		return nil
	}

	h := sha512.Sum512([]byte("cryptors ecdh chain " + fmt.Sprint(curve)))
	state := h[:]
	for round := 0; round < rounds; round++ {
		a, b := derive(state, 0), derive(state, 1)
		fromA, err := a.ECDH(b.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		fromB, err := b.ECDH(a.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if string(fromA) != string(fromB) {
			t.Fatalf("%s: the two sides disagree in round %d", curve, round)
		}
		input := append(append([]byte{}, state...), fromA...)
		input = append(input, a.PublicKey().Bytes()...)
		input = append(input, b.PublicKey().Bytes()...)
		sum := sha512.Sum512(input)
		state = sum[:]
		if round == 0 {
			afterFirst = hex.EncodeToString(state)
		}
	}
	return afterFirst, hex.EncodeToString(state)
}

func TestChain(t *testing.T) {
	want := map[string][2]string{
		"P-256": {
			"ee141111b85d1bf1ed6ce1e20208ee81dca91eb4fed60d8c389c6f1ad49c206404eca6e763da854d8f897119597bb6f0351d4cd5f8a73636249fb8c398f28166",
			"ce1c52709eefd21a333f87a2cff61e96c6ba95186973953c2c64b51dfaa20aa2cf482b1cbce3b84d517730be0cf12cc7f0a862c9c040d5d4144d1e591ec70b36",
		},
		"P-384": {
			"05d0e24a64586c6001409287fc26515d5da163afebb3de67d46f95e04ab763d59a464b3605ffe4593f7fac317166ff907099026716c398f69ff10b16b7286006",
			"2d8b7003ff37f5425a2ee30da0bccdc11d3a696a37cb86eeff072389dcb49fec54886e2266ea36f52c375ffa30e2bff80d7ae3d9d8bb3fc03c1c5a53f70ede45",
		},
		"P-521": {
			"cfb0c50071e89ab82b369a90535d2229e03a941c7e4cb88c34710d9da83c9c30ca1deb135a2cde65a0a54ab95516b93b65f054945bf5eb569ef4fdc23d6ebe96",
			"c0f9d01a13dd21939a9a9bb4d779209655aedd1b04609fcfffab31ca0b62823f60ba2d94d262633fed2c48102d1cdce9167d29facc7d2e829f3d12345ee32eb7",
		},
		"X25519": {
			"d2fc5bb0eb8a6698cc9fb3892848c6a333d2a811fbbfc79faf6cec7ac5a0156e2e860617187ff2bd4a57809f581a16166c58ac1bbe328deac41059d4ebdb554e",
			"6fbb8ce1f996ab1e5d0f4101fb7d2a73492ca2df72cec826524bd32f3507b611295a8f2411ae4337a0822254c9f677c3f407a641c282e6d863e8b149381ff062",
		},
	}
	for _, curve := range curves {
		mask := byte(0xff)
		if curve == ecdh.P521() {
			mask = 0x01
		}
		first, last := chain(t, curve, mask)
		w := want[fmt.Sprint(curve)]
		if first != w[0] || last != w[1] {
			t.Errorf("%s chain = %s, %s; want %s, %s", curve, first, last, w[0], w[1])
		}
	}
}
