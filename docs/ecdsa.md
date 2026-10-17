# ECDSA

ECDSA signs a message with a private key; anyone with the public key can verify it. It signs most X.509 certificates,
TLS handshakes and JWTs (`ES256`, `ES384`, `ES512`). It is neither a `Digest` nor a `BlockCipher`: keys and signatures
are their own types, generic over the curve (one of four types implementing the sealed trait `Curve`), and the hash is
a type parameter of the sign and verify functions.

| Curve | Type | Private key | Public key | Signature `r \|\| s` | Signature in DER | Security |
|-------|------|-------------|------------|---------------------|------------------|----------|
| NIST P-224 | `P224` | 28 bytes | 57 bytes | 56 bytes | 8 to 64 bytes | 112 bits |
| NIST P-256 | `P256` | 32 bytes | 65 bytes | 64 bytes | 8 to 72 bytes | 128 bits |
| NIST P-384 | `P384` | 48 bytes | 97 bytes | 96 bytes | 8 to 104 bytes | 192 bits |
| NIST P-521 | `P521` | 66 bytes | 133 bytes | 132 bytes | 8 to 139 bytes | 256 bits |

Curves: [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final), [SEC 2](https://www.secg.org/sec2-v2.pdf).
Algorithm: [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final), section 6. Deterministic signatures:
[RFC 6979](https://www.rfc-editor.org/info/rfc6979). P-224, the weakest of the four, is included (unlike in ECDH)
because FIPS 186-5 includes it.

- **Public key**: an uncompressed point ([SEC 1](https://www.secg.org/sec1-v2.pdf), section 2.3.3), as in ECDH, validated
  when turned into a `PublicKey`.
- **Signature**: either `r || s`, each number as long as a private key (IEEE P1363, JWS, COSE), or DER
  `SEQUENCE { r INTEGER, s INTEGER }` ([RFC 3279](https://www.rfc-editor.org/info/rfc3279) section 2.2.3, SEC 1 annex
  C.5), as carried by X.509 and TLS. DER parsing is strict: only the one valid encoding is accepted.

Each signature needs a secret nonce `k`. Both ways to get it are provided, each over a message or a digest. As in ECDH,
key generation and randomized signing take a reader, since the standard library has no stable secure random source.

| Kind | Functions | Nonce | Output |
|------|-----------|-------|--------|
| Randomized | `sign`, `sign_prehash` | random bytes from any `std::io::Read`, mixed with the key and digest | different each time |
| Deterministic | `sign_deterministic`, `sign_prehash_deterministic` | from the key and digest alone (RFC 6979) | always the same |

## Usage

```rust
use cryptors::ecdsa::{Error, P256, PrivateKey, PublicKey, Signature};
use cryptors::sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// RFC 6979, appendix A.2.5: a P-256 key, and the deterministic signature of "sample" with SHA-256.
let key = PrivateKey::<P256>::from_bytes(&unhex(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
)).unwrap();
let signature = key.sign_deterministic::<Sha256>(b"sample");
assert_eq!(
    signature.as_bytes(),
    unhex(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ))
);

// The verifier parses the public key and signature (bad keys and encodings are refused here)...
let public = PublicKey::<P256>::from_bytes(key.public_key().as_bytes()).unwrap();
let received = Signature::<P256>::from_der(&signature.to_der()).unwrap();

// ...and checks the signature against the message.
assert_eq!(public.verify::<Sha256>(b"sample", &received), Ok(()));
assert_eq!(public.verify::<Sha256>(b"sampled", &received), Err(Error::VerificationFailed));
```

Real keys come from `PrivateKey::generate`. Randomized signing also takes a random source:

```rust
use cryptors::ecdsa::{P384, PrivateKey};
use cryptors::sha2::Sha384;
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do
let key = PrivateKey::<P384>::generate(&mut rng)?;
let signature = key.sign::<Sha384, _>(&mut rng, b"a message")?;
// Send key.public_key().as_bytes(), the message and signature.to_der() to the other side.
```

`examples/ecdsa.rs` runs a full round on all four curves (randomized and deterministic signatures, a changed message, a
changed signature):

```sh
cargo run --release --example ecdsa
```

## Security

None of the four curves is broken; the security levels in the table are NIST's (SP 800-57). A large quantum computer
would break all four (Shor's algorithm); signatures that must outlive one need a post-quantum scheme such as
[ML-DSA](mldsa.md).

- **Everything rests on `k`.** `d = (s * k - e) / r`: whoever learns `k` has the private key. Two signatures sharing a
  `k`, or many whose `k` share a few bits (lattice attack), leak it. Neither mode below protects against an attacker
  who can skip instructions.
  - Randomized signing mixes the random bytes, key and digest in an HMAC_DRBG (draft-irtf-cfrg-det-sigs-with-noise
    section 4) that always uses SHA-512, since a digest does not say which hash made it. A bad reader costs only the
    randomization, leaving a signature as strong as a deterministic one.
  - Deterministic signing needs no reader but loses fault protection: a faulted recomputation of the same signature
    yields two results sharing a `k`.
- **The randomness is the caller's.** `generate` is only as good as its reader; a predictable one makes keys guessable.
  For signing, the reader must be secret and from a CSPRNG, but need not be perfect.
- **Pick the hash on purpose.** FIPS 186-5 section 6.1.1 approves SHA-2 and SHA-3, and a hash weaker than the curve
  "shall not be used": SHA-256 for P-224 and P-256, SHA-384 for P-384, SHA-512 for P-521. The crate accepts any
  `Digest`, SHA-1 and MD5 included, and the signature is then only as strong as that hash. The verifier must use the
  signer's hash. SHA-3 is not a `Digest` yet; use the `_prehash` functions.
- **Signatures are malleable.** Anyone can turn a valid `(r, s)` into a valid `(r, n - s)`. This is not a forgery, but
  do not identify a signature by its bytes (transaction IDs, cache keys).
- **Use a key only for signing** (FIPS 186-5 sections 6 and 6.2). An ECDH key, a distinct type, cannot be passed here.
- **Constant-time by construction, checked only by inspection.** No branch or memory address depends on the private
  key or `k`: `k * G` uses a table lookup that reads every entry, `k^-1` is a fixed-exponent power, and formulas are
  complete with mask-based selection, as in ECDH. In `rustc`'s aarch64 and x86_64 assembly, signing branches only on:
  - loops over public counts (limbs, windows, bytes, bits of a fixed exponent) and checks of public lengths;
  - checks that infallible results did not fail;
  - redrawing a rejected `k` candidate (depends on the rejected candidates, not the accepted one);
  - the `r` or `s` = 0 test, true with probability about `1/n` (2^-224 to 2^-521).

  That is one compiler's output for two targets, not timed on real hardware. Nothing protects against power analysis
  or fault injection. Verification handles no secrets; its time depends on its inputs.
- **Key wiping is best effort.** Private keys are zeroed on drop and hidden from `Debug`. Stack and register
  intermediates are not wiped, nor are copies left by moves (into a `Box` or `Vec`, say).

## Testing

```sh
cargo test -- ecdsa:: ec::   # known answers, Wycheproof, CAVP, chained signatures against OpenSSL, and the arithmetic against references
```

| Source | Coverage |
|--------|----------|
| RFC 6979, appendix A.2 | 40 signatures (5 hashes, 2 messages, 4 curves), reproduced bit for bit, plus each nonce `k` from the HMAC_DRBG |
| Project Wycheproof | 21 files for these curves with SHA-2 and SHA-3, including `_p1363`: 9,767 cases, all passed once; 293 kept in the tests (every fault kind on every curve, all DER faults on P-256 and P-521) |
| NIST CAVP (CAVS 11.0) | 300 verification vectors, SHA-1 to SHA-512, all passed once; 40 kept (one pass and one fail per curve and hash) |
| [c2sp.org/det-keygen](https://c2sp.org/det-keygen) | 21 key-generation seeds, including the P-256 seed whose first candidate overflows the order and P-521 candidates cut to 521 bits |
| Chained signatures | 16 rounds per curve, each signing the previous state; final values from OpenSSL, recomputed in `bench/ecdsacmp`, all agree |
| Randomized signing | Matches Go's DER output for the same key, digest and random bytes, with digests shorter than, equal to and longer than the order, on all four curves |

Wycheproof covers arithmetic edge cases (`u1`/`u2` zero or maximal, doubling points, inverse edge cases, tiny and huge
`r`, `s`), special public-key coordinates, every invalid DER form (BER lengths, trailing bytes, padded or negative
integers, wrong tags), and special digests.

Mutation testing: of 67 mutants across signing, verifying, the DRBG, the DER parser and arithmetic modulo the order, 62
are caught and 1 does not compile. The 4 survivors are a control that changes nothing; two in the `r = 0` handling (sign
and verify), which no input can reach (no one knows a `k` giving `r = 0`, and such a signature is rejected anyway); and
one unobservable overwrite of a scratch buffer.

The tests also check that digests longer than the order are truncated to the leftmost bits (including P-521's seven
spare bits); empty or wrongly sized digests are refused; reader failures are reported and `generate` gives up on a
stuck reader; a zero `s` triggers a redraw of `k`; every malformed signature gets the same error, in DER or `r || s`;
`Debug` shows no secret, and a dropped private key leaves nothing behind.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release ecdsa:: -- --ignored --nocapture --test-threads=1
cd bench/ecdsacmp && go test -v -run TestThroughput               # Go's crypto/ecdsa as shipped, with its assembly
cd bench/ecdsacmp && go test -tags purego -v -run TestThroughput  # Go's portable code, with no assembly
```

Timed with the same key and digest on both sides: new private key from bytes (derives the public key, a generator
multiplication), new public key from bytes (on-curve check), randomized sign, deterministic sign, verify. Signatures
are DER, so encoding and parsing are included. Each runs about 50 ms to size a ~100 ms batch; best of five batches.
The message is hashed once, outside the timing: SHA-256 for P-224 and P-256, SHA-384 for P-384, SHA-512 for P-521.
Randomized signing reads from a cheap generator on both sides (`GODEBUG=cryptocustomrand=1` for Go), excluding system
RNG cost. Key generation is not timed. All three runs print the same first 8 bytes of the deterministic signature.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| P-224 new private key | **30.9** | 33.6 | 33.6 |
| P-224 sign | **44.1** | 61.3 | 67.6 |
| P-224 sign deterministic | **41.5** | 58.5 | 63.3 |
| P-224 verify | **148.8** | 156.0 | 155.8 |
| P-256 new private key | 32.7 | **11.8** | 27.5 |
| P-256 sign | 47.8 | **24.1** | 45.9 |
| P-256 sign deterministic | 44.6 | **21.3** | 42.2 |
| P-256 verify | 153.4 | **58.4** | 142.4 |
| P-384 new private key | 106.7 | **105.8** | 105.9 |
| P-384 sign | **138.5** | 167.9 | 174.0 |
| P-384 sign deterministic | **135.1** | 167.4 | 173.9 |
| P-384 verify | 506.9 | **487.6** | 495.0 |
| P-521 new private key | **270.2** | 279.5 | 280.8 |
| P-521 sign | **348.6** | 414.2 | 422.8 |
| P-521 sign deterministic | **347.6** | 413.1 | 421.0 |
| P-521 verify | 1346.9 | 1344.8 | **1342.8** |

- Building a public key takes 0.1 to 0.5 µs here and 0.2 to 1.0 µs in Go.
- Run-to-run spread was within about 5% on a non-idle machine (battery, load average 4 to 6, another benchmark running),
  so the last digit means little.
- Go has P-256 assembly (arm64, amd64, ppc64le, s390x), including generator multiplication; the `purego` column is the
  like-for-like comparison. Go has no assembly for the other three curves.
- Verify multiplies a non-generator point, rebuilding its 15-multiple table each call, besides the generator. Randomized
  signing costs extra because the key and the digest each fill their own SHA-512 HMAC_DRBG block.

Not done yet, would make it faster:

- Verify (no secrets, so not constant time): a joint `u * G + v * Q` sharing doublings, signed digits, and comparing `r`
  with the projective x-coordinate to skip an inversion.
- As for ECDH: a squaring that exploits symmetry, per-prime reductions, and a BMI2/ADX backend on x86-64.
- Shorter addition chains for the inverses modulo the order and the prime (fixed-exponent powers today).

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings say nothing about an x86 CPU. The
manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
