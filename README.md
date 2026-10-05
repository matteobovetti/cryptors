# Cryptors

## Overview

Cryptors is all-in-one cryptographic crate written in pure Rust.

This library is heavily inspired by GoLang crypto library.

## Why everything in a single crate?

I decided to create a single crate rather than a collection of smaller crates to simplify usage and reduce dependencies.
Other implementations, require to add multiple crates to your project if you are using different algorithms. With Cryptors, you only need to add a single one.

## Rust Versions Compatibility

This library requires Rust version 1.95 or higher. Inside the CI pipeline, we run tests against multiple Rust versions to ensure compatibility.

## Algorithm

This library supports the following algorithms and packages:

| Algorithm | Description | Status |
|-----------|-------------|--------|
| AES | FIPS 197: Advanced Encryption Standard | In progress |
| Cipher modes | Standard block cipher modes (CBC, CFB, CTR, OFB, GCM) that wrap a block cipher such as AES | Planned |
| DES | FIPS 46-3 / TDEA: Data Encryption Standard and Triple DES | Planned |
| DSA | FIPS 186-3: Digital Signature Algorithm | Planned |
| ECDH | Elliptic Curve Diffie-Hellman over NIST curves and Curve25519 | Planned |
| ECDSA | FIPS 186-5: Elliptic Curve Digital Signature Algorithm | Planned |
| Ed25519 | Ed25519 signature algorithm | Planned |
| Elliptic Curves | NIST P-224, P-256, P-384, and P-521 elliptic curves | Planned |
| HKDF | RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function | Planned |
| HMAC | FIPS 198: Keyed-Hash Message Authentication Code | Planned |
| HPKE | RFC 9180: Hybrid Public Key Encryption | Planned |
| MD5 | [RFC 1321](https://www.rfc-editor.org/info/rfc1321): The MD5 Message-Digest Algorithm | Implemented |
| ML-DSA | FIPS 204: post-quantum ML-DSA signature scheme | Planned |
| ML-KEM | FIPS 203: quantum-resistant key encapsulation method | Planned |
| PBKDF2 | RFC 8018: Password-Based Key Derivation Function 2 | Planned |
| Rand | Cryptographically secure random number generator | Planned |
| RC4 | Rivest Cipher 4 stream cipher | Planned |
| RSA | PKCS #1 / RFC 8017: RSA encryption | Planned |
| SHA-1 | [RFC 3174](https://www.rfc-editor.org/info/rfc3174): US Secure Hash Algorithm 1 | Implemented |
| SHA-256 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-224 and SHA-256 | Implemented |
| SHA-3 | FIPS 202: SHA-3 and SHAKE extendable output functions | Implemented |
| SHA-512 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-384, SHA-512, SHA-512/224, and SHA-512/256 | Implemented |
| Subtle | Constant-time helpers that are useful in cryptographic code but need care to use correctly | Planned |
| TLS | RFC 5246 / RFC 8446: TLS 1.2 and TLS 1.3 | Planned |
| X.509 | A subset of the X.509 standard, with the shared ASN.1 structures for certificates, CRLs and OCSP (`pkix`) | Planned |

Status is one of Implemented, In progress or Planned.

## Hardware acceleration

Modern CPUs implement several of these primitives directly in silicon, and the difference is not marginal —
a single instruction can replace dozens of arithmetic operations. Cryptors targets **aarch64** and **x86** so
that, where the hardware offers a dedicated instruction, the crate uses it — and where it offers none, as for
MD5, the crate takes the parallelism that is actually there instead.

### Dedicated instructions

| Algorithm | Target | Feature | Instructions used |
|-----------|--------|---------|-------------------|
| SHA-1 | aarch64 | ARMv8 Cryptographic Extensions (`sha2` / `FEAT_SHA1`) | `SHA1C`, `SHA1P`, `SHA1M`, `SHA1H`, `SHA1SU0`, `SHA1SU1` |
| SHA-1 | x86_64 | SHA extensions (SHA-NI) | `SHA1RNDS4`, `SHA1NEXTE`, `SHA1MSG1`, `SHA1MSG2` |
| SHA-224, SHA-256 | aarch64 | ARMv8 Cryptographic Extensions (`sha2` / `FEAT_SHA256`) | `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` |
| SHA-224, SHA-256 | x86_64 | SHA extensions (SHA-NI) | `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` |
| SHA-384, SHA-512, SHA-512/224, SHA-512/256 | aarch64 | ARMv8.2 SHA-512 extension (`sha3` / `FEAT_SHA512`) | `SHA512H`, `SHA512H2`, `SHA512SU0`, `SHA512SU1` |
| SHA-3 | aarch64 | ARMv8.2 SHA-3 extension (`sha3` / `FEAT_SHA3`) | `EOR3`, `RAX1`, `XAR`, `BCAX` |

SHA-3 has no x86 row, and that is not an omission: **SHA-NI covers SHA-1 and SHA-256 only.** No shipping x86
CPU implements Keccak, so on x86 a single SHA-3 digest runs on the scalar backend. Where the CPU has BMI1 and
BMI2, that is a second build of the same code using their general-purpose `andn` and `rorx`, which cut a
round from 241 instructions to 181. The real parallelism has to come from somewhere else — see the next
section.

The 64-bit SHA-2 functions have no x86 row either, for a different reason. SHA-NI does not include SHA-512. The
SHA-512 instructions Intel has added since (`VSHA512RNDS2`, `VSHA512MSG1`, `VSHA512MSG2`) exist only in a few
recent CPUs, and none of the machines this project is tested on has them. A backend that nothing here can execute
is not worth shipping unverified, so on x86 SHA-384, SHA-512 and SHA-512/t run on the scalar backend, including
its BMI1/BMI2 build.

SHA-256 does have one x86 backend that is not SHA-NI. x86-64 CPUs with AVX2 but without SHA-NI, which means Intel's
cores from Haswell until Ice Lake, get the design from Intel's white paper *Fast SHA-256 Implementations on Intel
Architecture Processors*: AVX2 computes the message schedules of two blocks at once, one in each 128-bit half of a
register, with the round constants already added, while the rounds stay in general-purpose registers, using BMI2's
`rorx` and BMI1's `andn`.

The four ARMv8.2 instructions are an unusually good fit. Keccak's round is almost entirely XOR, rotate and
and-not, and each instruction collapses a whole pattern of them: `EOR3` is a three-way XOR, `RAX1` is
`a ^ rotl(b, 1)`, `XAR` fuses an XOR with a rotate, and `BCAX` is all three operations of the chi step at once.
Together they take a round from roughly 155 operations to 66.

### Multi-buffer SIMD, where no instruction exists

Not every algorithm has silicon behind it on every target. **No shipping CPU implements MD5**, and no x86 CPU
implements Keccak. The ARMv8 cryptographic extensions cover AES, PMULL, SHA-1, SHA-2, SHA-3, SM3 and SM4, and
x86 offers AES-NI and SHA-NI; MD5 appears in neither list.

Nor does ordinary SIMD help *within* one message, for either algorithm. MD5 has no message schedule to expand
in parallel, and its 64 steps form a single dependency chain in which every step needs the result of the one
before it. SHA-3's problem is shape rather than serialization: its 25-lane state and 5-wide rows map badly onto
4-lane registers, and the shuffling needed to line them up costs more than the parallelism returns — which is
why the Keccak team's own reference code ships no single-message AVX2 variant either. In both cases there is
nothing useful to do four at a time.

What is parallel is hashing several independent messages. Each SIMD lane holds the same state word — or, for
SHA-3, the same state lane — of a *different* message, and one ordinary pass advances every digest at once:

| Algorithm | Target | Feature | Lanes |
|-----------|--------|---------|-------|
| MD5 | aarch64 | NEON (baseline) | 16, 8, 4 |
| MD5 | x86_64 | AVX2 | 8 |
| MD5 | x86_64 | SSE2 (baseline) | 4 |
| SHA-3 | x86_64 | AVX2 | 4 |
| SHA-3 | x86_64 | SSE2 (baseline) | 2 |
| SHA-3 | aarch64 | `sha3` / FEAT_SHA3 | 2 |

That is a different shape of API, so it is a different function. `Md5::digest` and `sha3::sha3_256` hash one
message; `Md5::digest_many` and `sha3::sha3_256_many` take a slice of messages and return their digests. Each
fills the widest backend the CPU supports, then steps down through the narrower ones with whatever is left
over, so a batch of 15 messages is not thrown back onto the scalar path by a granularity cliff. Messages need
not be the same length: all lanes advance together for as long as every one of them still has a block left, and
each then leaves the batch at its own final block.

The aarch64 MD5 widths are not just register widths. Four lanes alone leave the vector units idle — MD5's
serial chain has nothing to issue while each multi-cycle instruction completes, worth only ~1.7x scalar. The 8-
and 16-lane versions interleave two and four independent lane groups instruction by instruction, each filling
the others' latency, for 3.2x and 4.8x at no extra arithmetic.

SHA-3 on aarch64 is the one case where both kinds of acceleration apply at once. The SHA-3 extension's
instructions are 128-bit, operating on two 64-bit lanes, and rho's rotation amount depends only on *which*
state lane is being rotated, never on the message — so both halves of every register always want the same
rotation. The same routine therefore serves two purposes: hashing one message, it broadcasts each state lane
into both halves and discards the second (the win is purely the fused instructions); hashing two, it gets the
fused instructions *and* twice the width out of identical code.

### Rules

Three rules govern how all of this is done, so that acceleration never costs correctness or portability:

1. **A portable scalar implementation always exists**, and it is the one the crate falls back to. It is not a
   second-class path: it is fully optimized (unrolled rounds, compile-time constants) and known-answer tested
   against the specification's own vectors in its own right.
2. **Backend selection is automatic, at runtime.** Nothing needs to be configured and no feature flag has to be
   enabled. The accelerated code is only ever entered after the relevant CPU feature has been confirmed present,
   so a binary built on one machine stays correct on another. Where a feature is part of the target baseline
   (`sha2` on `aarch64-apple-darwin`, for instance) the check folds away at compile time and costs nothing.
3. **Every backend is differential-tested against the scalar reference** — byte-for-byte, across input lengths
   that straddle every block and padding boundary, and for the multi-buffer backends across batches whose
   messages differ in length, so that lanes run out of blocks at different times. A backend that disagreed with
   the specification would fail the test suite, not silently produce wrong digests.

Because the vector instructions are intrinsics, these backends are where nearly all of the crate's `unsafe` lives.
Its scope is kept deliberately narrow:

- The single-message backends split the input into whole blocks (`chunks_exact`, `as_chunks`), so no length
  precondition can be violated by a caller.
- The multi-buffer backends receive fixed-size arrays, assembled by safe scalar code, so every vector load and store
  is in bounds by construction.

In both cases the only obligation left is the one the dispatcher has already discharged: that the CPU feature is
available.

The one other use is an empty block of inline assembly in SHA-256's two aarch64 backends, scalar and FEAT_SHA256.
It emits no instruction, touches no memory, and only stops the compiler from rearranging equivalent arithmetic into
a slower order (`src/sha2/sha256/scalar.rs` and `src/sha2/sha256/aarch64.rs`).

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Module layout

Each algorithm is one public module. The backends inside it (`scalar`, `aarch64`, `x86`, ...) are private, so what
you import is the same on every CPU, and the backend is chosen at runtime:

```text
cryptors
├── Digest                           the trait every fixed-output hash implements, re-exported at the root
├── md5
│   └── Md5
├── sha1
│   └── Sha1
├── sha2                             one module for the whole FIPS 180-4 family
│   ├── Sha224, Sha256               32-bit words
│   └── Sha384, Sha512,              64-bit words
│       Sha512_224, Sha512_256
└── sha3                             free functions: the XOFs do not fit the trait
    ├── sha3_224, sha3_256, sha3_384, sha3_512
    ├── shake128, shake256
    └── a `_hex` and a `_many` form of each
```

The SHA-2 functions are all imported from `sha2`, as in `cryptors::sha2::Sha256`. The two directories under
`src/sha2/` (`sha256/` and `sha512/`) are an implementation detail, and the [SHA-256](#sha-256) and
[SHA-512](#sha-512) sections below cover the 32-bit and the 64-bit functions respectively. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the layout of the source tree.

## Example

MD5, SHA-1 and the six SHA-2 functions (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256) are
zero-sized types that implement one trait, `cryptors::Digest`. Bring it into scope to call them, or take
`D: Digest` to be generic over the hash (HMAC, HKDF and PBKDF2 will do exactly that):

```rust
use cryptors::{Digest, md5::Md5, sha1::Sha1, sha2::{Sha256, Sha512}, sha3};

// A fixed-output hash is a type, and `digest` returns a `[u8; N]` of the right size for it.
let digest: [u8; 32] = Sha256::digest(b"abc");
assert_eq!(digest.len(), Sha256::OUTPUT_LEN);
assert_eq!(
    Sha256::hex_digest(b"abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);

// They share the `Digest` trait, so code can be generic over the hash.
fn hash_len<D: Digest>() -> usize {
    D::digest(b"abc").as_ref().len()
}
assert_eq!(hash_len::<Md5>(), 16);
assert_eq!(hash_len::<Sha1>(), 20);
assert_eq!(hash_len::<Sha512>(), 64);

// SHA-3 is a set of functions in its own module.
assert_eq!(sha3::sha3_256(b"abc").len(), 32);
```

Each hash provides `digest`, which returns a `[u8; N]`, plus the constants `BLOCK_LEN` and `OUTPUT_LEN`. `hex_digest`
and `digest_many` come with the trait; MD5 overrides `digest_many` with its SIMD multi-buffer implementation. The
dispatch is static, so a generic call compiles to the same code as a direct one. SHA-3 is not on the trait yet.

## MD5

MD5, specified in [RFC 1321](https://www.rfc-editor.org/info/rfc1321), is a cryptographic hash function that takes an
arbitrary-length message and produces a 128-bit (16-byte) digest.

### Usage

```rust
use cryptors::{Digest, md5::Md5};

let digest: [u8; 16] = Md5::digest(b"abc");
assert_eq!(Md5::hex_digest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
assert_eq!(digest[0], 0x90);

// Several independent messages, hashed side by side in SIMD lanes.
let digests: Vec<[u8; 16]> = Md5::digest_many(&[b"abc", b"", b"a longer message"]);
assert_eq!(digests[0], digest);
```

### Security

MD5 is cryptographically broken, for several reasons:

- **Collision attacks.** In 2004, researchers demonstrated practical collisions — two different inputs that produce
  the same MD5 digest. Modern hardware can now generate chosen-prefix collisions in seconds, meaning an attacker can
  craft two meaningfully different files (e.g. a benign and a malicious document) sharing the same hash.
- **Insufficient diffusion/strength.** The compression function's weaknesses let collisions be found far faster than
  the ~2^64 operations a 128-bit digest should require (the birthday bound), undermining the core guarantee of a
  hash function.
- **Chosen-prefix and length-extension weaknesses.** Attackers can prepend arbitrary chosen content and still
  produce colliding digests, which has been exploited to forge rogue CA certificates and sign malicious code.
- **No collision resistance means no integrity guarantee.** Any use case relying on MD5 to prove a file or message
  hasn't been tampered with can be defeated by an attacker able to produce a second input with the same hash.

As a result, MD5 **must not** be used for digital signatures, certificate signing, password hashing, or any other
context requiring collision resistance. It may still appear in non-security contexts such as checksums for
accidental corruption detection, but even there algorithms like SHA-256 are generally preferred.

### Testing

```sh
cargo test md5   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release md5 -- --ignored --nocapture --test-threads=1   # cryptors; names the backend selected on your machine
cd bench/md5cmp && go test -v                           # the Go stdlib counterpart
```

On an Apple M1 Pro, against Go's `crypto` package on the same machine:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| One 64 MiB message | **625 MiB/s** | — (no MD5 instruction exists) | 642 MiB/s |
| 1024 × 64 KiB messages | 625 MiB/s | **3022 MiB/s** (NEON, 16 lanes) | 641 MiB/s |

The batch row is the whole point of the multi-buffer backend: the same 64 MiB of input and the same number of
steps, at 4.8x the scalar throughput, purely from filling the lanes. `crypto/md5` has no batch API, so its
figure there is just its single-message one measured over 1024 sequential calls.

No absolute x86 figures are given. Under Rosetta 2 the SSE2 path measures 1.9x its own scalar baseline, but
emulation translates 256-bit AVX2 into pairs of 128-bit NEON operations, so such ratios say nothing useful
about real x86 hardware. The x86 backends are verified for *correctness* — differential-tested against the
scalar reference, with digests over 64 MiB matching the aarch64 ones byte for byte — but have not been
benchmarked on an x86 CPU.

## SHA-1

SHA-1, specified in [RFC 3174](https://www.rfc-editor.org/info/rfc3174), is a cryptographic hash function that
takes an arbitrary-length message (up to 2^64 - 1 bits) and produces a 160-bit (20-byte) digest.

### Usage

```rust
use cryptors::{Digest, sha1::Sha1};

let digest: [u8; 20] = Sha1::digest(b"abc");
assert_eq!(
    Sha1::hex_digest(b"abc"),
    "a9993e364706816aba3e25717850c26c9cd0d89d"
);
assert_eq!(digest[0], 0xa9);
```

### Security

SHA-1 is cryptographically broken, for several reasons:

- **Collision attacks.** In 2017, the SHAttered attack produced the first practical SHA-1 collision, and
  chosen-prefix collisions (letting an attacker pick the content of both colliding messages) followed in 2020.
- **Insufficient diffusion/strength.** Cryptanalysis has repeatedly reduced the cost of finding collisions far
  below the ~2^80 operations a 160-bit digest should require (the birthday bound), undermining the core guarantee
  of a hash function.
- **No collision resistance means no integrity guarantee.** Any use case relying on SHA-1 to prove a file or
  message hasn't been tampered with can be defeated by an attacker able to produce a second input with the same
  hash.

As a result, SHA-1 **must not** be used for digital signatures, certificate signing, password hashing, or any
other context requiring collision resistance. Major browsers and certificate authorities have deprecated it, and
algorithms like SHA-256 or SHA-3 should be used instead.

### Testing

```sh
cargo test sha1   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release sha1 -- --ignored --nocapture --test-threads=1   # cryptors; names the backend selected on your machine
cd bench/sha1cmp && go test -v                           # the Go stdlib counterpart
```

On an Apple M1 Pro, against Go's `crypto` package on the same machine:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| One 64 MiB message | ~790 MiB/s | **2143 MiB/s** (FEAT_SHA1) | 2365 MiB/s |

The x86 SHA-NI backend is verified for correctness only; it has not been benchmarked on an x86 CPU.

## SHA-256

SHA-224 and SHA-256, specified in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), are the two
32-bit members of the SHA-2 family, which NIST introduced in 2001 as the successor to SHA-1. They are built the
same way as SHA-1 and MD5 before them — a Merkle-Damgard construction, in which a fixed-size compression function
folds the padded message in one block at a time — but with a much larger and better-mixed compression function.
Decades of cryptanalysis have not produced a practical attack on either.

FIPS 180-4 defines six functions in the family. This crate implements all of them; the two that share the 32-bit
algorithm are described here:

| Function | Output | Block | Initial state |
|----------|--------|-------|---------------|
| SHA-224 | 224 bits (28 bytes) | 512 bits (64 bytes) | second 32 bits of the fractional parts of the square roots of the 9th–16th primes |
| SHA-256 | 256 bits (32 bytes) | 512 bits (64 bytes) | first 32 bits of the fractional parts of the square roots of the first eight primes |

SHA-224 is not a truncated SHA-256: it starts from a different initial state, so the two give unrelated digests
for the same input. The 64-bit members of the family (SHA-384, SHA-512, SHA-512/224, SHA-512/256) use a different
word size and are described under [SHA-512](#sha-512).

### Usage

```rust
use cryptors::{Digest, sha2::{Sha224, Sha256}};

let digest: [u8; 32] = Sha256::digest(b"abc");
assert_eq!(
    Sha256::hex_digest(b"abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);
assert_eq!(digest[0], 0xba);

// SHA-224 is a separate algorithm with its own initial state, not a truncated SHA-256.
let short: [u8; 28] = Sha224::digest(b"abc");
assert_eq!(
    Sha224::hex_digest(b"abc"),
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
);
assert_eq!(short[0], 0x23);
```

### Security

SHA-224 and SHA-256 are not broken. There is no known collision or preimage attack better than brute force on
either, and both are suitable for digital signatures, certificate signing and integrity checks.

Two things to know when using them. First, as a Merkle-Damgard hash, SHA-256 allows **length extension**: anyone
holding `sha256(m)` and the length of `m` can compute `sha256(m || padding || x)` without knowing `m`, because the
digest *is* the final state. So `sha256(key || message)` is not a safe MAC — use HMAC. SHA-224 withholds the last of
the eight state words, so an attacker has to guess that one (32 bits) first, which makes extension harder but
does not remove it. SHA-3 does not have the problem. Second, SHA-256 is fast by design, which is the wrong
property for storing passwords; use a password-hashing construction such as PBKDF2 instead.

### Testing

```sh
cargo test sha2::sha256     # known-answer vectors and differential tests against the scalar reference
```

The known-answer tests include NIST's published example messages, and digests of inputs whose lengths straddle the
block and padding boundaries (55, 56 and 57 bytes, 63, 64 and 65, and so on), computed by an independent
implementation (OpenSSL).

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public functions use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release sha2::sha256 -- --ignored --nocapture --test-threads=1
cd bench/sha256cmp && go test -v                        # Go's crypto/sha256 as shipped
cd bench/sha256cmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
cd bench/sha256cmp && GODEBUG=cpu.sha=off go test -v    # x86-64 only: Go's AVX2 path, the counterpart of x86_avx2
```

On an Apple M1 Pro, against Go's `crypto` package on the same machine (medians of three runs):

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA-224, one 64 MiB message | 409 MiB/s | 304 MiB/s | **2365 MiB/s** (FEAT_SHA256) | 2324 MiB/s |
| SHA-256, one 64 MiB message | 409 MiB/s | 305 MiB/s | **2365 MiB/s** (FEAT_SHA256) | 2324 MiB/s |

SHA-224 and SHA-256 run the same 64 rounds and differ only in their initial state and in how many words they
output, so their speeds are the same to within measurement noise.

Each cryptors column has a Go counterpart:

- **Accelerated vs Go stdlib.** Go's assembly runs the same four instructions, and cryptors is 1.8% faster. It used to
  be 10% slower, and the whole gap came down to one register copy per group of four rounds:
  - `SHA256H` overwrites its `a`-`d` input, while `SHA256H2` still needs the old value, so one of the two has to
    work on a copy.
  - The compiler gave `SHA256H` the copy, which put the copy on the chain every group waits on.
  - Go copies the value for `SHA256H2` instead, off that chain.

  Go's loop, transliterated verbatim into Rust inline assembly, ran at Go's speed, which ruled out every other
  cause. An empty inline-assembly barrier that makes the compiler place the copy Go's way closed the gap. Keeping all
  64 round constants in registers, as Go does, makes no difference, because the compiler already does it.
- **Scalar vs Go portable.** Go's portable code is what it runs on every platform without assembly. Our scalar
  backend is 1.34x faster.

The instructions buy 5.8x over scalar.

No x86 figures are given yet: none of the three x86 backends has been timed on real hardware. Rosetta 2 does not
expose SHA-NI at all, and its timings of the other two say nothing about a real CPU. The SHA-NI backend has not
been run on real SHA-NI hardware. The AVX2 and BMI backends are correctness-tested on x86-64 under Docker
(`--platform linux/amd64`, which exposes AVX2, BMI1 and BMI2). On any CPU, `cargo test` runs every backend that CPU
supports against the scalar one (the `matches_scalar_backend` test), and `--nocapture` names each backend it checked.
The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
Since the throughput test times every backend the runner supports, one run on a SHA-NI machine also measures the paths
that a CPU without it would take.

## SHA-3

SHA-3, specified in [FIPS 202](https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions), is
NIST's answer to the Keccak permutation, chosen in 2012 to stand alongside SHA-2 after years of successful
attacks on MD5 and SHA-1. It is built differently from every hash earlier in this README: instead of a
Merkle-Damgard compression function, it uses a single permutation, Keccak-f[1600], applied through a "sponge"
construction. That structural distance from SHA-1/SHA-2 is deliberate — a weakness that breaks one family is
far less likely to break both.

FIPS 202 defines six functions built on the same sponge:

| Function | Output | Rate (absorbed per permutation) | Capacity |
|----------|--------|----------------------------------|----------|
| SHA3-224 | 224 bits (fixed) | 1152 bits (144 bytes) | 448 bits |
| SHA3-256 | 256 bits (fixed) | 1088 bits (136 bytes) | 512 bits |
| SHA3-384 | 384 bits (fixed) | 832 bits (104 bytes) | 768 bits |
| SHA3-512 | 512 bits (fixed) | 576 bits (72 bytes) | 1024 bits |
| SHAKE128 | any length (XOF) | 1344 bits (168 bytes) | 256 bits |
| SHAKE256 | any length (XOF) | 1088 bits (136 bytes) | 512 bits |

The last two are extendable-output functions (XOFs): instead of a fixed-size digest, the caller asks for as
many output bytes as they need — useful as a building block for key derivation and other constructions that
want a pseudorandom stream rather than a single fixed-width digest.

### Usage

```rust
use cryptors::sha3;

let digest: [u8; 32] = sha3::sha3_256(b"abc");
assert_eq!(
    sha3::sha3_256_hex(b"abc"),
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
);
assert_eq!(digest[0], 0x3a);

// The other fixed-size variants are sha3_224, sha3_384 and sha3_512, each with a `_hex` form.
// SHAKE writes as many bytes as the output buffer holds.
let mut xof = [0u8; 32];
sha3::shake128(b"", &mut xof);
assert_eq!(
    sha3::shake128_hex(b"", 32),
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
);
assert_eq!(xof[0], 0x7f);
```

Hashing many messages at once is a separate set of functions, because it is a different shape of API. Each `_many`
function takes a slice of messages and hashes them side by side, one per vector lane:

```rust
use cryptors::sha3;

let digests: Vec<[u8; 32]> = sha3::sha3_256_many(&[b"many", b"messages"]);
assert_eq!(digests[0], sha3::sha3_256(b"many"));
assert_eq!(digests[1], sha3::sha3_256(b"messages"));

// For SHAKE the output length is shared by the whole batch.
let xofs: Vec<Vec<u8>> = sha3::shake128_many(&[b"a", b"b"], 64);
assert_eq!(xofs[0].len(), 64);
```

They hash in groups of 4 (AVX2) or 2 (SSE2, or aarch64 with FEAT_SHA3), so a whole group costs little more than a
single digest, and the messages do not have to be the same length. See
[Hardware acceleration](#hardware-acceleration).

### Security

SHA-3 is not broken. It has no known collision, preimage, or length-extension attacks, and its sponge
construction is immune to the length-extension issues that affect SHA-2's Merkle-Damgard design (feeding a
SHA-3 digest back in as a prefix does not let an attacker extend it undetected). It is suitable for the same
uses as SHA-256/SHA-512 — digital signatures, certificate signing, integrity checks — and the SHAKE XOFs are
commonly used wherever a construction needs variable-length pseudorandom output instead of a fixed digest.

### Testing

```sh
cargo test sha3   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
# cryptors: the backend selected on your machine and, if that isn't scalar, the scalar one too. One test
# thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release sha3 -- --ignored --nocapture --test-threads=1
cd bench/sha3cmp && go test -v                 # Go's crypto/sha3 as shipped
cd bench/sha3cmp && go test -tags purego -v    # Go's portable code, the counterpart of our scalar backend
```

On an Apple M1 Pro, against Go's `crypto` package on the same machine (medians of three runs):

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA3-224, one 64 MiB message | 657 MiB/s | 414 MiB/s | **881 MiB/s** (FEAT_SHA3) | 882 MiB/s |
| SHA3-256, one 64 MiB message | 619 MiB/s | 391 MiB/s | **834 MiB/s** (FEAT_SHA3) | 829 MiB/s |
| SHA3-384, one 64 MiB message | 473 MiB/s | 299 MiB/s | **634 MiB/s** (FEAT_SHA3) | 645 MiB/s |
| SHA3-512, one 64 MiB message | 329 MiB/s | 208 MiB/s | **443 MiB/s** (FEAT_SHA3) | 447 MiB/s |
| SHAKE128, one 64 MiB message | 765 MiB/s | 480 MiB/s | **1026 MiB/s** (FEAT_SHA3) | 1021 MiB/s |
| SHAKE256, one 64 MiB message | 619 MiB/s | 390 MiB/s | **834 MiB/s** (FEAT_SHA3) | 831 MiB/s |
| SHA3-256, 1024 × 64 KiB messages | 622 MiB/s | 391 MiB/s | **1596 MiB/s** (FEAT_SHA3, 2 lanes) | 831 MiB/s |

The four SHA-3 digests differ from each other by more than 2x because their rates differ: SHA3-512 absorbs only
72 bytes per permutation against SHA3-224's 144, so it runs the same permutation twice as often per byte.

Each cryptors column has a Go counterpart:

- **Accelerated vs Go stdlib.** On macOS, Go's `crypto/sha3` uses the same four ARMv8.2 instructions, and the
  two land within 2% of each other either way.
- **Scalar vs Go portable.** Go's portable code is what it runs on every other platform without assembly, and
  on non-Apple aarch64 by choice. Our scalar backend is 1.58–1.59x faster. Both use the same in-place round
  structure, so the gap comes from code generation, not from the algorithm.

FEAT_SHA3 buys 1.35x over scalar here. That is well short of the halved instruction count (74 instructions per
round against 150), and why has not been established; Go's FEAT_SHA3 assembly is no faster. What is certain is
that a single message leaves half of every 128-bit register idle. The batch row fills it, for 1.9x the
single-message FEAT_SHA3 throughput and 2.6x scalar. `crypto/sha3` has no batch API, so its figure there is
its single-message one over 1024 sequential calls.

No x86 figures are given yet. Under Rosetta 2 the x86 code runs, but its speed says nothing about real x86
hardware: 256-bit AVX2, for instance, is emulated as pairs of 128-bit NEON operations. The x86 backends,
including the BMI1/BMI2 scalar build, are therefore verified for *correctness* only. The manual `Benchmarks`
workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## SHA-512

SHA-384, SHA-512, SHA-512/224 and SHA-512/256, specified in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final),
are the four 64-bit members of the SHA-2 family. They are built exactly like [SHA-256](#sha-256) — a Merkle-Damgard
construction around a compression function of rounds — but on 64-bit words: eight of them in the state, a 128-byte
block and 80 rounds. Each operation handles twice as many bits, so on a 64-bit CPU without dedicated instructions
SHA-512 usually hashes a long message faster than SHA-256 does (1.3x in the scalar backends here, see Benchmarking
below).

| Function | Output | Block | Initial state |
|----------|--------|-------|---------------|
| SHA-384 | 384 bits (48 bytes) | 1024 bits (128 bytes) | first 64 bits of the fractional parts of the square roots of the 9th–16th primes |
| SHA-512 | 512 bits (64 bytes) | 1024 bits (128 bytes) | first 64 bits of the fractional parts of the square roots of the first eight primes |
| SHA-512/224 | 224 bits (28 bytes) | 1024 bits (128 bytes) | generated by the SHA-512/t procedure, from the string `SHA-512/224` |
| SHA-512/256 | 256 bits (32 bytes) | 1024 bits (128 bytes) | generated by the SHA-512/t procedure, from the string `SHA-512/256` |

None of the shorter functions is a truncated SHA-512: each starts from its own initial state, so the digests are
unrelated to SHA-512's for the same input. SHA-512/t is a family of functions whose initial state FIPS 180-4
derives, so that `t` does not need a constant of its own: it is what SHA-512 outputs for the string `SHA-512/t`,
when started from SHA-512's initial state XOR `0xa5a5a5a5a5a5a5a5`. A test runs that procedure for `t` = 224 and
256 and checks it against the constants in the code. The crate implements the two values of `t`, 224 and 256, that
the standard approves; SHA-512/t for other values of `t` is not provided.

### Usage

```rust
use cryptors::{Digest, sha2::{Sha384, Sha512, Sha512_224, Sha512_256}};

let digest: [u8; 64] = Sha512::digest(b"abc");
assert_eq!(
    Sha512::hex_digest(b"abc"),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);
assert_eq!(digest[0], 0xdd);

// The others are separate algorithms with their own initial states, not truncated SHA-512 digests.
let short: [u8; 48] = Sha384::digest(b"abc");
assert_eq!(short[0], 0xcb);
assert_eq!(
    Sha512_224::hex_digest(b"abc"),
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
);
assert_eq!(
    Sha512_256::hex_digest(b"abc"),
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
);
```

### Security

SHA-384, SHA-512, SHA-512/224 and SHA-512/256 are not broken. There is no known collision or preimage attack better
than brute force on any of them, and all four are suitable for digital signatures, certificate signing and
integrity checks.

They share the one weakness of the Merkle-Damgard construction that SHA-256 has, **length extension**, but SHA-384,
SHA-512/224 and SHA-512/256 are protected from it by their truncated output. Whoever holds `sha512(m)` and the length
of `m` can compute `sha512(m || padding || x)` without knowing `m`, because the digest *is* the final state, so
`sha512(key || message)` is not a safe MAC — use HMAC. SHA-384 withholds 128 bits of the state, SHA-512/256 withholds
256 and SHA-512/224 withholds 288, and an attacker has to guess the withheld bits before extending, which is far
beyond reach. That is why SHA-512/256 is sometimes chosen over SHA-256 where length extension is a concern; HMAC is
still the right way to build a MAC from any of them. SHA-3 does not have the problem at all. And, like SHA-256,
SHA-512 is fast by design, which is the wrong property for storing passwords; use a password-hashing construction
such as PBKDF2 instead.

### Testing

```sh
cargo test sha2::sha512     # known-answer vectors and differential tests against the scalar reference, for all four functions
```

The known-answer tests include NIST's published example messages, and digests of inputs whose lengths straddle the
block and padding boundaries (111, 112 and 113 bytes, 127, 128 and 129, and so on). The expected digests of all four
functions come from two independent implementations, OpenSSL and Go's standard library, which agree with each
other. On any CPU, `cargo test` runs every backend that CPU supports against the scalar one (the
`matches_scalar_backend` test), and `--nocapture` names each backend it checked. The x86-64 build, including the
BMI1/BMI2 one, passes the same tests under Docker (`--platform linux/amd64`).

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public functions use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release sha2::sha512 -- --ignored --nocapture --test-threads=1
cd bench/sha512cmp && go test -v                        # Go's crypto/sha512 as shipped
cd bench/sha512cmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
```

On an Apple M1 Pro, against Go's `crypto` package on the same machine (medians of three runs):

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA-384, one 64 MiB message | 541 MiB/s | 437 MiB/s | **1371 MiB/s** (FEAT_SHA512) | 1366 MiB/s |
| SHA-512, one 64 MiB message | 540 MiB/s | 438 MiB/s | **1386 MiB/s** (FEAT_SHA512) | 1364 MiB/s |
| SHA-512/224, one 64 MiB message | 541 MiB/s | 437 MiB/s | **1374 MiB/s** (FEAT_SHA512) | 1363 MiB/s |
| SHA-512/256, one 64 MiB message | 540 MiB/s | 438 MiB/s | **1392 MiB/s** (FEAT_SHA512) | 1361 MiB/s |

The four functions run the same 80 rounds and differ only in their initial state and in how many words they
output, so their speeds are the same to within measurement noise.

Each cryptors column has a Go counterpart:

- **Accelerated vs Go stdlib.** Go's assembly runs the same four instructions, and the two land within about 2% of
  each other, which is as far apart as two runs of the same program. Unlike SHA-256, no gap needed closing here.
- **Scalar vs Go portable.** Go's portable code is what it runs on every platform without assembly. Our scalar
  backend is 1.23–1.24x faster.

The instructions buy 2.6x over scalar. Compared across the two algorithms on this machine, SHA-512's scalar backend
is 1.32x faster than SHA-256's (540 against 409 MiB/s), but SHA-256 has instructions here too, and they are faster:
2365 MiB/s against SHA-512's 1386.

No x86 figures are given yet, for the same reason as SHA-256: nothing here can time real x86 hardware. The x86-64
scalar backend, with and without BMI1/BMI2, is correctness-tested under Docker. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding
conventions, and how to submit a pull request.
