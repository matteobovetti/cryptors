# ML-DSA

ML-DSA, the Module-Lattice-Based Digital Signature Algorithm of [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
(CRYSTALS-Dilithium as NIST standardized it), is a post-quantum signature scheme: its lattice problems (module LWE and a
variant of module SIS) have no known quantum attack, while [ECDSA](ecdsa.md) and [Ed25519](ed25519.md) fall to Shor's
algorithm. [RFC 9881](https://www.rfc-editor.org/info/rfc9881) gives its X.509 identifiers. Keys and signatures are
their own types (not `Digest` or `BlockCipher`), generic over a parameter set: one of three types implementing the
sealed trait `Parameters`.

Types: `PrivateKey<P>`, `PublicKey<P>`, `Signature<P>`, the parameter sets `MlDsa44`, `MlDsa65` and `MlDsa87`,
`PreHash`, `Error`, `MAX_CONTEXT_LEN`, `SEED_LEN`.

| Parameter set | Type | NIST category | Private key | Public key | Signature |
|---------------|------|---------------|-------------|------------|-----------|
| ML-DSA-44 | `MlDsa44` | 2 (collision search on SHA-256) | 32 bytes | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | `MlDsa65` | 3 (key search on AES-192) | 32 bytes | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | `MlDsa87` | 5 (key search on AES-256) | 32 bytes | 2,592 bytes | 4,627 bytes |

- Keys and signatures of different parameter sets do not compile together.
- The private key is the 32-byte seed of `ML-DSA.KeyGen` (`PrivateKey::from_seed`, `PrivateKey::seed`). FIPS 204's
  expanded private key (2,560 to 4,896 bytes) is not accepted: it is larger, holds nothing to check against the seed,
  and RFC 9881 (section 8.1) recommends the seed for storage and exchange.
- `sign` is **hedged**: 32 bytes from any `std::io::Read` go into the mask, so two signatures of one message differ.
  `sign_deterministic` needs no reader; `verify` checks both. The standard library has no stable secure random source,
  so `generate` also takes a reader, as in ECDH, ECDSA and Ed25519.
- Every function takes a **context** of 0 to 255 bytes (`b""` for none) that the verifier must repeat; a longer one is
  `Error::ContextTooLong`.
- **HashML-DSA** (`sign_prehash`, `verify_prehash`) signs a digest plus its function's identifier, from the twelve
  functions of FIPS 204's registry (`PreHash`: SHA-2, SHA-3 and the two SHAKEs; `PreHash::digest` computes it). FIPS 204
  prefers the pure form; RFC 9881 does not allow HashML-DSA in X.509.
- **External μ** (`PublicKey::message_representative`, `sign_mu`, `verify_mu`, RFC 9881 appendix D): a client hashes a
  large message with the public key into 64 bytes, and the signer takes only those.

## Usage

```rust
use cryptors::mldsa::{Error, MlDsa44, PrivateKey, PublicKey, Signature};

// A key from a seed of 32 bytes of 0x2a, and the deterministic signature of "Hello world" with no context: a case of
// Project Wycheproof.
let key = PrivateKey::<MlDsa44>::from_seed(&[0x2a; 32]);
assert_eq!(key.public_key().as_bytes()[..8], [0xdb, 0x9a, 0xc6, 0x77, 0x08, 0xf2, 0xba, 0x0f]);
let signature = key.sign_deterministic(b"Hello world", b"")?;
assert_eq!(signature.as_bytes()[..8], [0x1a, 0xa6, 0x9c, 0xb5, 0xed, 0x35, 0x20, 0x45]);

// The verifier has the public key and the signature as bytes (this is where a key or a signature of the wrong length is
// refused)...
let public = PublicKey::<MlDsa44>::from_bytes(key.public_key().as_bytes())?;
let received = Signature::<MlDsa44>::from_bytes(signature.as_bytes())?;

// ...and checks the signature against the message and the context.
assert_eq!(public.verify(b"Hello world", b"", &received), Ok(()));
assert_eq!(public.verify(b"Hello world!", b"", &received), Err(Error::VerificationFailed));
assert_eq!(public.verify(b"Hello world", b"v2", &received), Err(Error::VerificationFailed));

// A hedged signature takes 32 random bytes from a reader, here a fixed string; it is another signature of the same
// message, and just as valid.
let mut noise: &[u8] = &[7; 32];
let hedged = key.sign(&mut noise, b"Hello world", b"")?;
assert_ne!(hedged, signature);
assert_eq!(public.verify(b"Hello world", b"", &hedged), Ok(()));
```

Real keys come from `PrivateKey::generate`; hedged signing also needs random bytes from your own source:

```rust
use cryptors::mldsa::{MlDsa65, PrivateKey};
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do
let key = PrivateKey::<MlDsa65>::generate(&mut rng)?;
let signature = key.sign(&mut rng, b"a message", b"")?;
// Store key.seed(); send key.public_key().as_bytes(), the message and signature.as_bytes() to the other side.
```

`examples/mldsa.rs` runs each parameter set through hedged and deterministic signing, a changed message, context and
signature, then HashML-DSA: `cargo run --release --example mldsa`.

## Security

The best known attacks are lattice reduction, classical or quantum, and the three parameter sets are chosen against them
(the categories are NIST's). FIPS 204 makes the scheme strongly unforgeable (section 3.1): nobody can turn a valid
signature into another valid one of the same message.

- **Hedged or deterministic.** The mask must never repeat or be guessable. Both forms derive it from the key and the
  message; hedging adds 32 random bytes, which protects against fault attacks (a fault in one of two computations of the
  same deterministic signature may leak the key) and costs nothing if the bytes are bad (FIPS 204, sections 3.4 and
  3.6.1). Deterministic signing time depends on the message, not the key (section 3.6.1, footnote 3): sign hedged to
  keep the message private.
- **The randomness is the caller's.** FIPS 204 asks the reader of `generate` for at least 128 (ideally 192) bits of
  strength for ML-DSA-44, 192 for ML-DSA-65 and 256 for ML-DSA-87 (section 3.6.1).
- **Signing is rejection sampling.** Attempts whose answer could leak the key are discarded: 4.25, 5.1 and 3.85 attempts
  on average per set (FIPS 204, table 1). Which check rejected, and how often, is public (Dilithium specification,
  section 5.5), so hedged signing time varies without revealing the key. Past `2^16 / l` attempts (at least 9,362)
  signing panics; the standard shows 814 are needed with a probability below `2^-256` (appendix C).
- **Pick the pre-hash on purpose.** FIPS 204 wants at least `2 * lambda` digest bits (section 5.4): 256, 384 and 512,
  excluding 224-bit functions for all sets and 256-bit ones for ML-DSA-65 and ML-DSA-87. This crate does not stop you
  from naming one. A signature of a digest binds the function, and is not a signature of the message.
- **Secret-independent arithmetic, checked one way only.** No branch or memory address derives from `s1`, `s2`, `t0`,
  `K` or the mask, except the `s1`/`s2` sampler's length (which candidates it discards) and the accept-or-reject
  decision, public by design. The transform, products, reductions, rounding and hint use only additions,
  multiplications, shifts and masks; the one table, the roots of unity, is read in loop order. In the assembly of
  `rustc` 1.95 for `aarch64-apple-darwin` and `x86_64-apple-darwin`, the only conditional jumps in signing and key
  generation are fixed-count loops, checks of public lengths and of an allocation, SHAKE buffer management, the
  rejection test (on the mask the norm check accumulates), packing an accepted signature's hint, and the sampler's
  discards. That is one compiler on two targets, not a proof; no timing was measured on real hardware, and nothing
  protects against power analysis or fault injection. Verifying handles no secret; its time depends on its inputs.
- **Lengths and encodings are checked.** Public keys and signatures of the wrong length are refused, as are hints not in
  FIPS 204's one encoding (section 3.6.2 and algorithm 21), so a signature has one encoding. Any string of the right
  length is a public key, all zeros included; that one verifies nothing.
- **Keys stay in memory for as long as they exist.** Dropping a key zeroes its seed and secret vectors; `Debug` shows no
  secret (a public key shows the start of its hash). Not wiped: arithmetic temporaries in stack and registers, and
  copies left by moves. A private key keeps its expanded form (28, 47 and 79 KiB of heap) so signing does not expand it
  again; a public key holds its bytes. Signing or verifying uses under 64 KiB of stack in release builds.

## Testing

```sh
cargo test -- mldsa:: sha3::xof   # known answers, vectors of NIST and Wycheproof, and each part against its definition
cargo test --release mldsa::keypair::tests::accumulated_10000 -- --ignored   # 10,000 keys and signatures for each set
MLDSA_VECTORS=/dir cargo test --release mldsa::conformance -- --ignored --nocapture   # every ACVP and Wycheproof vector
```

- **Accumulated known answers** ([C2SP's CCTV](https://github.com/C2SP/CCTV/tree/main/ML-DSA/accumulated)): seeds from
  one SHAKE128; each key and its deterministic signature of the empty message go into a second SHAKE128, of which 32
  bytes are compared. 100 rounds per set in the tests, 10,000 in the ignored one; both pass. Hashing 30,000 keys and
  signatures leaves no room for an error in key generation, signing or encoding.
- **NIST ACVP** (ACVP-Server `ML-DSA-keyGen`, `sigGen`, `sigVer` for FIPS 204): all 615 were run once with no failure;
  97 are in the tests (`src/mldsa/testdata/acvp.txt`). That is 75 key generation, 360 signing (external, pre-hash and
  internal interfaces, hedged and deterministic, with an external μ) and 180 verification (valid, or with a changed
  message, commitment, `z` or hint).
- **NIST rejection-loop known answers** (ACVP draft, tables 1 and 2): 27 cases, reaching each of the four rejections
  (`z`, the low bits, `c * t0`, the number of hints) and 64 to 100 rejections. Each case's name is its count of
  discarded attempts, which the tests check.
- **Project Wycheproof:** all 1,138 ML-DSA cases (287 signing from a seed, 220 from an expanded key, 631 verifying),
  including every wrong hint encoding, signatures at the norm bounds, all-zero keys and 256-byte contexts. The 1,129
  this API can express (nine have a wrong-length seed, which `from_seed` refuses to compile) were run once; 87 are in
  the tests (`src/mldsa/testdata/wycheproof.txt`).
- **OpenSSL 3.6.4** (once, outside the tests, all three sets): same public key from the same seed, same deterministic
  signature with empty and non-empty context, each verifies the other's signatures and this crate's hedged ones, and
  both reject a wrong context.
- **Go:** `bench/mldsacmp` reproduces the signature of the first Wycheproof case with Go's `crypto/mldsa`.
- **Each part against its definition:** the transform against a schoolbook polynomial product at the extremes of its
  bounds; `Decompose`, `Power2Round` and `UseHint` against the standard for every number modulo `q`, and `MakeHint` at
  every boundary signing reaches; the three samplers and `SampleInBall` against the written-out algorithms; packing at
  every width; the loop's four checks where they flip; streaming SHAKE against the one-shot functions at every input
  split.
- **API behaviour:** 255- and 256-byte contexts; the 12 pre-hash functions (identifiers not interchangeable, wrong
  digest length); the message `M'` written out; every byte class of a signature changed; wrong-length keys and
  signatures; hint encodings; a failing or short reader; `generate` reading exactly 32 bytes; `Debug` hiding secrets; a
  dropped key leaving neither the seed nor `K`; clones being independent.
- **Mutation testing:** of 106 small changes (a constant, an operand, a dropped check, a flipped comparison) to the
  transform, rounding, samplers, packing, key generation, signing, verifying, API and streaming SHAKE, each in a scratch
  copy, 98 fail a test, 1 does not compile and 7 survive. Three overwrite a local copy never read again (the seed and
  random bytes after use, a key-generation scratch vector), which cannot be observed; two change nothing (a harness
  control, and an addition to an always-zero position); one moves the threshold where `Decompose` brings a low part down
  by `q` to a value no low part takes; one compares the commitment hash a byte short, which no failing signature passes,
  since a changed byte changes all the others. The first run's three other survivors were gaps (a hint count past
  `omega` with indices in order, and the exact edges of the bounds on `z` and `c * t0`, which no vector hits); tests now
  pin them.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release mldsa:: -- --ignored --nocapture --test-threads=1
cd bench/mldsacmp && go test -v -run TestThroughput               # Go's crypto/mldsa as shipped, with its assembly Keccak
cd bench/mldsacmp && go test -tags purego -v -run TestThroughput  # Go with a portable Keccak
```

Each run uses the same key and a 64-byte message with no context, and times building a private key from its seed
(expanding the matrix and the secret vectors, and the public key), building a public key from its bytes (which hashes
it), hedged and deterministic signing, and verifying. Key generation is not timed. The attempt count depends on the
message, so signing cycles through 256 messages; a batch holds more than that, so the deterministic row does the same
work on both sides. Hedged signing reads its 32 bytes from a cheap generator here and from the system in Go (which
ignores the reader it is given). Each operation runs about 50 ms to size a batch of about 100 ms; the best of five
batches is reported. Both sides print the first 8 bytes of the deterministic signature of the benchmark key, and all
three runs print the same.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| ML-DSA-44 new private key | **35.7** | 101.3 | 121.2 |
| ML-DSA-44 new public key | **1.7** | 2.0 | 3.8 |
| ML-DSA-44 sign | **96.7** | 260.4 | 286.2 |
| ML-DSA-44 sign deterministic | **91.2** | 248.5 | 271.7 |
| ML-DSA-44 verify | **32.0** | 74.4 | 91.2 |
| ML-DSA-65 new private key | **61.9** | 168.4 | 205.8 |
| ML-DSA-65 new public key | **2.5** | 2.9 | 5.6 |
| ML-DSA-65 sign | **146.8** | 412.0 | 468.7 |
| ML-DSA-65 sign deterministic | **144.8** | 427.9 | 461.8 |
| ML-DSA-65 verify | **51.7** | 116.3 | 146.3 |
| ML-DSA-87 new private key | **96.5** | 236.0 | 296.0 |
| ML-DSA-87 new public key | **3.3** | 3.8 | 7.4 |
| ML-DSA-87 sign | **154.8** | 495.9 | 520.3 |
| ML-DSA-87 sign deterministic | **159.5** | 491.9 | 516.7 |
| ML-DSA-87 verify | **84.9** | 186.8 | 241.3 |

Run-to-run spread was within 8% in every cell (most in hedged signing, which draws new random bytes), on a desktop that
was not idle (load average about 5), so the last digit means little.

- **Signing takes 2.7 to 3.2 times less here than in Go, verifying 2.2 to 2.3 times, and building a private key 2.5 to
  2.8 times.** Building a public key, one SHAKE256 of the key in both, differs by 15 to 18%. Go's ML-DSA is also
  portable (only its Keccak is assembly), so this compares two implementations of one algorithm. This one keeps sums
  unreduced, adds a row's products in 64 bits before one reduction (Go reduces after each addition and subtraction), and
  keeps working vectors in fixed-size stack arrays.
- **A signature averages 3.85 to 5.1 loop passes**, most rejected before the expensive checks, so `sign` costs about
  that many passes: masks (SHAKE256), `A * y` (a transform and an inverse per polynomial), the hash and the answer.
  Hedged and deterministic rows are within each other's spread.
- **Verifying** makes the rows of `A` as it goes (a SHAKE128 stream for each of the `k * l` entries) and keeps none, so
  it costs a third to a half of a deterministic signature.
- The Keccak is this crate's, using `FEAT_SHA3` on this CPU. Go's uses it on Apple's Arm cores too, and assembly on
  x86-64, but not on other Arm cores, where it finds the instructions slower than its portable code.

Possible speedups, not done: explicit NEON and AVX2 for transforms and products (the compiler already uses NEON in
places); the two- and four-way Keccak of `sha3::shake128_many` for the matrix and masks, which are many independent
streams; caching `A` in a public key that verifies often (16 to 56 KiB); batch verification.

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 translates the instructions, so its timings
say nothing about an x86 CPU. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on
GitHub's x86-64 and Arm runners.
