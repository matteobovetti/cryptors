# ECDH

Elliptic Curve Diffie-Hellman: two parties exchange public keys over an open channel and each derives the same shared
secret. It is neither a `Digest` nor a `BlockCipher`. Keys are generic over the curve, one of four types implementing
the sealed trait `Curve`, so mixing keys of two curves is a compile error. P-224 is only in [ECDSA](ecdsa.md).

| Curve | Type | Private key | Public key | Shared secret | Defined in |
|-------|------|-------------|------------|---------------|------------|
| NIST P-256 | `P256` | 32 bytes | 65 bytes | 32 bytes | [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final), [SEC 1](https://www.secg.org/sec1-v2.pdf) |
| NIST P-384 | `P384` | 48 bytes | 97 bytes | 48 bytes | the same |
| NIST P-521 | `P521` | 66 bytes | 133 bytes | 66 bytes | the same |
| Curve25519 | `X25519` | 32 bytes | 32 bytes | 32 bytes | [RFC 7748](https://www.rfc-editor.org/info/rfc7748) |

- **NIST curves**: a public key is an uncompressed point, `0x04` and both coordinates (SEC 1, 2.3.3). The shared secret
  is the x-coordinate of the shared point (SEC 1, 3.3.1; NIST SP 800-56A Rev. 3, 5.7.1.2).
- **X25519**: any 32 bytes are a public key (RFC 7748).

## Usage

```rust
use cryptors::ecdh::{P256, PrivateKey, PublicKey, X25519};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// RFC 7748, section 6.1.
let alice = PrivateKey::<X25519>::from_bytes(&unhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
)).unwrap();
let bob = PrivateKey::<X25519>::from_bytes(&unhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
)).unwrap();
assert_eq!(
    alice.public_key().as_bytes(),
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
);

// Public keys arrive as bytes; this is where a bad key is refused.
let bobs_public = PublicKey::<X25519>::from_bytes(bob.public_key().as_bytes()).unwrap();

let from_alice = alice.diffie_hellman(&bobs_public).unwrap();
let from_bob = bob.diffie_hellman(alice.public_key()).unwrap();
assert_eq!(from_alice, from_bob);
assert_eq!(
    from_alice.as_bytes(),
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
);

// NIST curves work the same way (a NIST CAVS vector for P-256).
let private = PrivateKey::<P256>::from_bytes(&unhex(
    "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
)).unwrap();
let peer = PublicKey::<P256>::from_bytes(&unhex(concat!(
    "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
    "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
))).unwrap();
assert_eq!(
    private.diffie_hellman(&peer).unwrap().as_bytes(),
    unhex("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b")
);

// A point off the curve is refused when the key is built.
let mut off_the_curve = peer.as_bytes().to_vec();
off_the_curve[64] ^= 1;
assert!(PublicKey::<P256>::from_bytes(&off_the_curve).is_err());
```

Real keys come from `PrivateKey::generate`. `std` has no stable secure RNG, so it reads from any `std::io::Read`:

```rust
use cryptors::ecdh::{P384, PrivateKey};
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do
let key = PrivateKey::<P384>::generate(&mut rng)?;
// Send key.public_key().as_bytes() to the other side.
```

`examples/ecdh.rs` runs a full exchange on all four curves: `cargo run --release --example ecdh`.

## Security

Security levels: 128, 192 and 256 bits for P-256, P-384 and P-521 (NIST SP 800-57); Curve25519 is "slightly under the
standard 128-bit level" (RFC 7748). A large quantum computer breaks all four; long-lived secrecy needs a post-quantum
scheme such as [ML-KEM](mlkem.md).

- **The shared secret is not a key.** Run it through a KDF such as [HKDF](hkdf.md), with both public keys in the input
  (RFC 7748, sections 6.1 and 7).
- **Nothing is authenticated.** Unless the protocol binds keys to identities (signatures, certificates, a pre-shared
  secret), a man in the middle is possible. Prefer a fresh key pair per exchange.
- **Public keys are validated.** `PublicKey::from_bytes` rejects coordinates not below the prime, points off the curve,
  the point at infinity and compressed points (invalid-curve attacks), so a `PublicKey` is always valid. For X25519,
  `diffie_hellman` returns `Error::LowOrderPoint` when a small-order point forces an all-zero secret.
- **Randomness is the caller's.** `generate` is only as good as its reader.
- **Constant-time by construction, checked only by reading assembly.** No branch or memory address depends on a private
  key: full-table lookups, mask-based conditional swaps, complete formulas. Masks go through `core::hint::black_box`, a
  request, not a guarantee. In the `rustc` output for `aarch64` and `x86_64`, the other conditional jumps depend only on
  public values (limb, window and exponent-bit counts, lengths) or on two result checks (shared point at infinity,
  all-zero X25519 secret). Not timed on real hardware; no protection against power analysis or fault injection.
- **Zeroizing is best effort.** Private keys and shared secrets are zeroed on drop and hidden from `Debug`. Stack and
  register intermediates are not, nor are copies left by moves (e.g. into a `Box` or `Vec`).

## Testing

```sh
cargo test -- ecdh:: ec::   # known answers, Wycheproof, chained exchanges against OpenSSL, and the arithmetic against references
```

| Source | Coverage |
|--------|----------|
| Known answers | NIST CAVS vectors for the three NIST curves; RFC 7748 section 5.2 (including the 1,000-step chain) and the section 6.1 exchange |
| Project Wycheproof | `ecdh_secp256r1_ecpoint_test.json`, its 384 and 521 counterparts, and `x25519_test.json`: 2,324 cases, all passed once; 273 kept (every invalid or acceptable NIST case, the notable X25519 public-key cases, the zero-secret case per NIST curve, samples of the rest) |
| Chained exchanges | 16 rounds per curve of two derived keys exchanging, each seeded by the hash of the last; final values from OpenSSL, reproduced by `bench/ecdhcmp` |
| Differential tests | The X25519 five-limb field and full ladder against the generic NIST field (limbs at their bounds included); the generator table against generic multiplication; curve constants against their defining relations |
| API behaviour | `generate` redraws on zero, the order or too-large values and errors after 64 failed candidates; smallest/largest private keys and x = 0 are accepted; P-521 masks the seven unused top bits; reader failures are reported; `Debug` shows no secret; keys and secrets are wiped on drop |

Wycheproof covers off-curve and wrong-curve points, malformed and compressed encodings, small-order and twist points,
non-canonical encodings, edge-case keys and secrets, and the CVE-2017-8932 regression.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release ecdh:: -- --ignored --nocapture --test-threads=1
cd bench/ecdhcmp && go test -v                       # Go's crypto/ecdh as shipped, with its assembly
cd bench/ecdhcmp && go test -tags purego -v          # Go's portable code, with no assembly
```

Timed on the same keys: building a private key (derives the public key), building a public key (on-curve check), the
exchange, and all three ("handshake"). Each runs ~50 ms to size a ~100 ms batch; best of five batches. Key generation
is not timed. All runs print the same first 8 bytes of the shared secret.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| P-256 new private key | 31.8 | **11.1** | 26.2 |
| P-256 ecdh | 113.3 | **41.3** | 110.4 |
| P-256 handshake | 145.4 | **52.8** | 136.9 |
| P-384 new private key | 103.6 | **102.0** | 102.1 |
| P-384 ecdh | 392.0 | **332.4** | 332.4 |
| P-384 handshake | 496.7 | **434.9** | 435.1 |
| P-521 new private key | **261.6** | 269.8 | 269.8 |
| P-521 ecdh | 1012.6 | **945.1** | 945.2 |
| P-521 handshake | 1275.0 | **1216.2** | 1215.8 |
| X25519 new private key | **28.2** | 36.3 | 36.4 |
| X25519 ecdh | **28.1** | 36.3 | 36.3 |
| X25519 handshake | **56.5** | 72.6 | 72.6 |

- Building a public key takes 0.1 to 0.5 µs on the NIST curves, and nothing for X25519.
- Run-to-run spread was about 1% on a non-idle desktop (load average 2 to 4), so the last digit means little.
- The first NIST key in a process builds that curve's generator table (excluded above): about 0.5 ms for P-256, 1.7 ms
  for P-384, 4 ms for P-521, kept in 90, 200 and 420 KiB.
- The X25519 field (`src/ec/fe25519.rs`) is shared with Ed25519.
- Not done, possible NIST speedups: dedicated squaring, prime-specific reduction (P-521 needs no Montgomery step),
  signed windows (half the table), an x86-64 BMI2/ADX backend.

No x86 figures yet: Rosetta 2 timings say nothing about real x86 CPUs. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
