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
| SHA-256 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-224 and SHA-256 | :white_check_mark: |
| SHA-3 | FIPS 202: SHA-3 and SHAKE extendable output functions | :white_check_mark: |
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
| SHA-224, SHA-256 | aarch64 | ARMv8 Cryptographic Extensions (`sha2` / `FEAT_SHA256`) | `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` |
| SHA-224, SHA-256 | x86_64 | SHA extensions (SHA-NI) | `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` |
| SHA-3 | aarch64 | ARMv8.2 SHA-3 extension (`sha3` / `FEAT_SHA3`) | `EOR3`, `RAX1`, `XAR`, `BCAX` |

SHA-3 has no x86 row, and that is not an omission: **SHA-NI covers SHA-1 and SHA-256 only.** No shipping x86
CPU implements Keccak, so on x86 a single SHA-3 digest runs on the scalar backend. Where the CPU has BMI1 and
BMI2, that is a second build of the same code using their general-purpose `andn` and `rorx`, which cut a
round from 241 instructions to 181. The real parallelism has to come from somewhere else — see the next
section.

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

That is a different shape of API, so it is a different function. `md5::digest` and `sha3::sha3_256` hash one
message; `md5::digest_many` and `sha3::sha3_256_many` take a slice of messages and return their digests. Each
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
a slower order (see [SHA-256](#accelerating-it)).

See [CONTRIBUTING.md](CONTRIBUTING.md).

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

### Testing

```sh
cargo test md5   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release md5 -- --ignored --nocapture   # cryptors; names the backend selected on your machine
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

### Testing

```sh
cargo test sha1   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release sha1 -- --ignored --nocapture   # cryptors; names the backend selected on your machine
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

FIPS 180-4 defines six functions in the family. This crate implements the two that share one algorithm:

| Function | Output | Block | Initial state |
|----------|--------|-------|---------------|
| SHA-224 | 224 bits (28 bytes) | 512 bits (64 bytes) | second 32 bits of the fractional parts of the square roots of the 9th–16th primes |
| SHA-256 | 256 bits (32 bytes) | 512 bits (64 bytes) | first 32 bits of the fractional parts of the square roots of the first eight primes |

SHA-224 is not a truncated SHA-256: it starts from a different initial state, so the two give unrelated digests
for the same input. The 64-bit members of the family (SHA-384, SHA-512, SHA-512/224, SHA-512/256) use a different
word size and are listed separately in the table above.

### How it works

1. **Padding.** The message is padded so its length is congruent to 448 mod 512 bits: a single `1` bit is appended,
   followed by `0` bits, followed by a 64-bit big-endian integer encoding the original message length in bits.
   The padded message is now a multiple of 512 bits (16 32-bit words).
2. **Initialization.** Eight 32-bit state words (`H0`..`H7`) are set to the initial state of the function being
   computed.
3. **Message schedule.** The 16 words of each 512-bit chunk are expanded into 64. Every new word is the sum of four
   earlier ones, two of which are first mixed through a pair of rotate-and-shift functions (`σ0` and `σ1`).
4. **Compression.** The chunk then goes through 64 rounds. Each round keeps eight working variables (`a`..`h`) and:
   - computes `Ch(e, f, g)` (a bitwise choice) and `Maj(a, b, c)` (a bitwise majority),
   - rotates `e` and `a` by three different amounts each and XORs the results (`Σ1` and `Σ0`),
   - adds a schedule word and a round constant (the cube roots of the first 64 primes),
   - shifts the eight variables down by one place, with two of them receiving new values.

   The eight variables are added back into the state at the end of the chunk.
5. **Output.** After all chunks are processed, the state words are concatenated big-endian: all eight make the
   256-bit SHA-256 digest, and the first seven make the 224-bit SHA-224 digest.

Step 4 is where all the time goes, and unlike MD5 it is what both aarch64 and x86 provide dedicated instructions
for. See [Hardware acceleration](#hardware-acceleration).

### Accelerating it

Hashing one message is serial — chunk `n + 1` cannot start until chunk `n` has finished — so the only thing worth
accelerating is the compression function itself, and both common CPU families have instructions for exactly that.
On aarch64 that is `SHA256H` and `SHA256H2`, which each advance half of the state by four rounds, with `SHA256SU0`
and `SHA256SU1` producing four schedule words at a time. On x86 it is SHA-NI's `SHA256RNDS2`, two rounds per
instruction, with `SHA256MSG1` and `SHA256MSG2` for the schedule. Both are described under
[hardware acceleration](#hardware-acceleration) above, and both are selected automatically at runtime. Unlike MD5
and SHA-3 there is no multi-message API: the instructions already cover what a batch would have been for.

x86-64 CPUs with AVX2 but without SHA-NI, which means Intel's cores from Haswell until Ice Lake, get the design from
Intel's white paper *Fast SHA-256 Implementations on Intel Architecture Processors*. AVX2 computes the message
schedules of two blocks at once, one in each 128-bit half of a register, with the round constants already added.
The rounds stay in general-purpose registers, using BMI2's `rorx` and BMI1's `andn`. The first block's rounds
overlap with the vector work, and the second block's need no schedule work at all.

Everything else runs on the scalar backend, which does as much as plain integer code can. It is fully unrolled, so
every schedule index and round constant is known at compile time, and it computes each schedule word in the middle
of the rounds, right before the round that needs it, instead of expanding 16 words at a time between groups of
rounds. The rounds then overlap with the schedule instead of waiting for it, which measured 1.6x faster on the
Apple M1 Pro used for the benchmarks below.

Within a block the rounds form one dependency chain, so what sets the speed is how many instructions sit between
one round's `e` and the next, not how many there are in total, and the compiler optimizes for the total. On aarch64
two of its choices cost the most:

- It folds rotates into the XORs that use them (`eor w0, w1, w2, ror #n`). On the M1 that form takes two cycles,
  where a plain rotate or XOR takes one, so each `Σ` costs five cycles instead of three.
- It adds the values it has loaded, the round constant and the schedule word, last. That leaves five additions
  between `Ch` and the new `e`.

So the aarch64 build keeps the rotates separate and adds up `h + K[t] + W[t]` and `d` first, off the chain. Both are
pinned in place with empty inline-assembly barriers, which emit no instruction. Two smaller changes go with them:
`Maj` reuses the previous round's `a ^ b`, and the round constants are loaded from a table instead of being built
from immediates. Together these make the backend 1.2x faster on the M1 Pro. On x86-64, with 16 registers instead of
31, the regrouping costs more in spills than it saves, so it is not applied there. Instead, CPUs with BMI1 and BMI2
get a second build of the same code, using `rorx` and `andn`, with about 17% fewer instructions per block.

```rust
use cryptors::sha256;

let digest = sha256::sha256(b"one message");     // [u8; 32]
let short = sha256::sha224(b"one message");      // [u8; 28]
let hex = sha256::sha256_hex(b"abc");            // "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

### Security status

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
cargo test sha256   # known-answer vectors and differential tests against the scalar reference
```

The known-answer tests include NIST's published example messages, and digests of inputs whose lengths straddle the
block and padding boundaries (55, 56 and 57 bytes, 63, 64 and 65, and so on), computed by an independent
implementation (OpenSSL).

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public functions use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release sha256 -- --ignored --nocapture --test-threads=1
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
  backend is 1.34x faster (see [Accelerating it](#accelerating-it)).

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

### How it works

1. **State.** The permutation operates on a 1600-bit state, viewed as a 5x5 array of 64-bit lanes. `rate` and
   `capacity` always add up to 1600 bits; a smaller rate (as used by the larger digests) means more of the
   state is kept secret between permutations, which is what buys the extra security margin.
2. **Absorbing.** The message is padded with `pad10*1`: a domain-separation suffix (`01` for SHA3-*, `1111`
   for SHAKE*) followed by a `1` bit, zero bits, and a final `1` bit, so the padded length is a multiple of the
   rate. Each rate-sized block is XORed into the state, with the Keccak-f[1600] permutation run in between.
3. **Permuting.** Keccak-f[1600] runs 24 rounds, each applying five step mappings to the whole state: theta
   (XOR each lane with the parity of two neighboring columns), rho (rotate each lane by a fixed, lane-specific
   amount), pi (permute the lanes' positions), chi (XOR each lane with a nonlinear function of its row), and
   iota (XOR a round-specific constant into one lane to break symmetry between rounds).
4. **Squeezing.** Once the whole message has been absorbed, output bytes are read directly off the state,
   rate-sized block at a time, permuting again between blocks if more output is needed than one block holds.
   The fixed-size digests simply stop after their digest length; the XOFs keep going for as long as the caller
   asked.

### Accelerating it

All six functions are built on the same permutation, so there is only one thing worth accelerating. On aarch64
that is ARMv8.2's `EOR3`/`RAX1`/`XAR`/`BCAX`. On x86, where no Keccak instruction exists, it is hashing several
messages at once with one per vector lane. Both are described under
[hardware acceleration](#hardware-acceleration) above, and both are selected automatically at runtime.

Everything else runs on the scalar backend, which does as much as plain integer code can. It processes the
state one row at a time and writes each row back over the slots it was read from, the "in-place" technique of
the Keccak team's reference code, so about a dozen values are live at once instead of thirty. On x86-64 it
also has a BMI1/BMI2 build, picked at runtime.

The batch form is a separate set of functions, because it is a different shape of API:

```rust
use cryptors::sha3;

let digest = sha3::sha3_256(b"one message");                  // [u8; 32]
let digests = sha3::sha3_256_many(&[b"many", b"messages"]);   // Vec<[u8; 32]>
let xof = sha3::shake128_many(&[b"a", b"b"], 64);             // Vec<Vec<u8>>, 64 bytes each
```

`sha3_256_many` and its siblings hash in groups of 4 (AVX2) or 2 (SSE2, or aarch64 with FEAT_SHA3), so a whole
group costs little more than a single digest. The messages do not have to be the same length.

### Security status

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding
conventions, and how to submit a pull request.
