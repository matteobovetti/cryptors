# Cryptors

## Overview

Cryptors is all-in-one cryptographic crate written in pure Rust.

This library is heavily inspired by GoLang crypto library.

## Why everything in a single crate?

I decided to create a single crate rather than a collection of smaller crates to simplify usage and reduce dependencies.
Other implementations, require to add multiple crates to your project if you are using different algorithms. With Cryptors, you only need to add a single one.

## Algorithm

This library supports the following algorithms:

| Algorithm | Description | Status |
|-----------|-------------|--------|
| AES | FIPS 197: Advanced Encryption Standard | :white_large_square: |
| DES | FIPS 46-3 / TDEA: Data Encryption Standard and Triple DES | :white_large_square: |
| DSA | FIPS 186-3: Digital Signature Algorithm | :white_large_square: |
| ECDH | Elliptic Curve Diffie-Hellman over NIST curves and Curve25519 | :white_large_square: |
| ECDSA | FIPS 186-5: Elliptic Curve Digital Signature Algorithm | :white_large_square: |
| Ed25519 | Ed25519 signature algorithm | :white_large_square: |
| Elliptic Curves | NIST P-224, P-256, P-384, and P-521 elliptic curves | :white_large_square: |
| HKDF | RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function | :white_large_square: |
| HMAC | FIPS 198: Keyed-Hash Message Authentication Code | :white_large_square: |
| HPKE | RFC 9180: Hybrid Public Key Encryption | :white_large_square: |
| MD5 | [RFC 1321](https://www.rfc-editor.org/info/rfc1321): The MD5 Message-Digest Algorithm | :white_check_mark: |
| ML-DSA | FIPS 204: post-quantum ML-DSA signature scheme | :white_large_square: |
| ML-KEM | FIPS 203: quantum-resistant key encapsulation method | :white_large_square: |
| PBKDF2 | RFC 8018: Password-Based Key Derivation Function 2 | :white_large_square: |
| RC4 | Rivest Cipher 4 stream cipher | :white_large_square: |
| RSA | PKCS #1 / RFC 8017: RSA encryption | :white_large_square: |
| SHA-1 | [RFC 3174](https://www.rfc-editor.org/info/rfc3174): US Secure Hash Algorithm 1 | :white_check_mark: |
| SHA-256 | FIPS 180-4: SHA-224 and SHA-256 | :white_large_square: |
| SHA-3 | FIPS 202: SHA-3 and SHAKE extendable output functions | :white_large_square: |
| SHA-512 | FIPS 180-4: SHA-384, SHA-512, SHA-512/224, and SHA-512/256 | :white_large_square: |

:white_check_mark: implemented — :construction: in progress — :white_large_square: not implemented

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

### Multi-buffer SIMD, where no instruction exists

Not every algorithm has silicon behind it. **No shipping CPU implements MD5.** The ARMv8 cryptographic
extensions cover AES, PMULL, SHA-1, SHA-2, SHA-3, SM3 and SM4, and x86 offers AES-NI and SHA-NI; MD5 appears in
neither list. Nor does ordinary SIMD help *within* one message: MD5 has no message schedule to expand in
parallel, and its 64 steps form a single dependency chain in which every step needs the result of the one
before it. There is nothing to do four at a time.

What is parallel is hashing several independent messages. Each SIMD lane holds the same state word of a
*different* message, and one pass of the ordinary MD5 step advances every digest at once:

| Target | Feature | Lanes |
|--------|---------|-------|
| aarch64 | NEON (baseline) | 16, 8, 4 |
| x86_64 | AVX2 | 8 |
| x86_64 | SSE2 (baseline) | 4 |

That is a different shape of API, so it is a different function. `md5::digest` hashes one message and is always
scalar; `md5::digest_many` takes a slice of messages and returns their digests. It fills the widest backend the
CPU supports, then steps down through the narrower ones with whatever is left over, so a batch of 15 messages is
not thrown back onto the scalar path by a granularity cliff.

The aarch64 widths are not just register widths. Four lanes alone leave the vector units idle — MD5's serial
chain has nothing to issue while each multi-cycle instruction completes, worth only ~1.7x scalar. The 8- and
16-lane versions interleave two and four independent lane groups instruction by instruction, each filling the
others' latency, for 3.2x and 4.8x at no extra arithmetic.

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

Because the vector instructions are intrinsics, these backends are the crate's only meaningful use of `unsafe`.
Its scope is kept deliberately narrow. The single-message backends iterate the input with `chunks_exact`, so no
length precondition can be violated by a caller; the multi-buffer backends receive fixed-size arrays, assembled
by safe scalar code, so every vector load and store is in bounds by construction. In both cases the only
obligation left is the one the dispatcher has already discharged — that the CPU feature is available. See
[CONTRIBUTING.md](CONTRIBUTING.md).

### Measured

On an Apple M1 Pro, against Go's `crypto` package on the same machine:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| SHA-1, one 64 MiB message | ~790 MiB/s | **2143 MiB/s** (FEAT_SHA1) | 2365 MiB/s |
| MD5, one 64 MiB message | **625 MiB/s** | — (no MD5 instruction exists) | 642 MiB/s |
| MD5, 1024 × 64 KiB messages | 625 MiB/s | **3022 MiB/s** (NEON, 16 lanes) | 641 MiB/s |

The last row is the whole point of the multi-buffer backend: the same 64 MiB of input and the same number of
scalar steps, at 4.8x the throughput, purely from filling the lanes. Go's `crypto/md5` has no batch API, so its
third figure is just its second one measured over 1024 sequential calls.

No absolute x86 figures are given. The SSE2 path measures 1.9x its own scalar baseline under Rosetta 2
emulation, which says nothing useful about real x86 hardware, and AVX2 cannot be emulated there at all.

Reproduce both halves yourself with:

```sh
make bench-throughput   # cryptors; names the backend selected on your machine
make bench-go           # the Go stdlib counterparts, in bench/sha1cmp and bench/md5cmp
```

## MD5

MD5, specified in [RFC 1321](https://www.rfc-editor.org/info/rfc1321), is a cryptographic hash function that takes an
arbitrary-length message and produces a 128-bit (16-byte) digest.

### How it works

1. **Padding.** The message is padded so its length is congruent to 448 mod 512 bits: a single `1` bit is appended,
   followed by `0` bits, followed by a 64-bit little-endian integer encoding the original message length in bits.
   The padded message is now a multiple of 512 bits (16 32-bit words).
2. **Initialization.** Four 32-bit state words (`A`, `B`, `C`, `D`) are set to fixed initial values.
3. **Block processing.** The message is processed in 512-bit chunks. Each chunk goes through 4 rounds of 16
   operations each (64 operations total), where every operation:
   - applies one of four nonlinear functions (`F`, `G`, `H`, `I`) to three of the state words,
   - adds a chunk-of-message word and a round-specific constant (derived from the sine function),
   - rotates the result left by a round-specific amount,
   - adds it to one of the state words, then rotates the four state words.
4. **Output.** After all chunks are processed, `A`, `B`, `C`, `D` are concatenated to form the 128-bit digest.

Step 3 is where all the time goes, and unlike SHA-1 no CPU has an instruction for it — the 64 operations are
strictly sequential, so there is no parallelism to exploit inside a single message. The 64 operations of
*different* messages, however, are completely independent, which is what `md5::digest_many` exploits. See
[Hardware acceleration](#hardware-acceleration).

### Why it is cryptographically broken

MD5 is considered broken for security purposes for several reasons:

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

## SHA-1

SHA-1, specified in [RFC 3174](https://www.rfc-editor.org/info/rfc3174), is a cryptographic hash function that
takes an arbitrary-length message (up to 2^64 - 1 bits) and produces a 160-bit (20-byte) digest.

### How it works

1. **Padding.** The message is padded so its length is congruent to 448 mod 512 bits: a single `1` bit is appended,
   followed by `0` bits, followed by a 64-bit big-endian integer encoding the original message length in bits.
   The padded message is now a multiple of 512 bits (16 32-bit words).
2. **Initialization.** Five 32-bit state words (`H0`..`H4`) are set to fixed initial values.
3. **Block processing.** The message is processed in 512-bit chunks. Each chunk's 16 32-bit words are expanded into
   an 80-word schedule, where each new word is the XOR of four earlier words rotated left by one bit. The chunk then
   goes through 80 operations split into 4 rounds of 20, where every operation:
   - applies one of three nonlinear functions to three of the state words (a fourth, parity, function is reused for
     two of the rounds),
   - adds a schedule word and a round-specific constant,
   - rotates and recombines the five state words.
4. **Output.** After all chunks are processed, `H0`..`H4` are concatenated to form the 160-bit digest.

Step 3 is where almost all the time goes, and it is what both aarch64 and x86 provide dedicated instructions
for: a single instruction computes four of the 80 operations, and another expands four schedule words at once.
See [Hardware acceleration](#hardware-acceleration).

### Why it is cryptographically broken

SHA-1 is considered broken for security purposes for several reasons:

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding
conventions, and how to submit a pull request.
