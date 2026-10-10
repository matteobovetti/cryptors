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
| AES | [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final): Advanced Encryption Standard (AES-128, AES-192 and AES-256) | Implemented |
| DES | [FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final): Data Encryption Standard and Triple DES (TDEA), withdrawn in 2005 and kept for legacy data | Implemented |
| ECDH | [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final) and [RFC 7748](https://www.rfc-editor.org/info/rfc7748): Elliptic Curve Diffie-Hellman over P-256, P-384, P-521 and Curve25519 (X25519) | Implemented |
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
| AES | aarch64 | ARMv8 Cryptographic Extensions (`aes` / `FEAT_AES`, which Rust reports together with `FEAT_PMULL`) | `AESE`, `AESMC`, `AESD`, `AESIMC` |
| AES | x86_64 | AES-NI | `AESENC`, `AESENCLAST`, `AESDEC`, `AESDECLAST`, `AESIMC` |
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

AES is the opposite case from SHA-3: both architectures have instructions for it, and each one does most or all of
a round of the cipher. On x86, `AESENC` is SubBytes, ShiftRows, MixColumns and AddRoundKey in a single instruction.
On Arm, `AESE` is all of them but MixColumns, which is `AESMC`. A block takes 10, 12 or 14 rounds, so that many
instructions on x86 and about twice as many on Arm, against the sixteen table lookups per round of the scalar
backend. The key expansion uses the instructions too, for its S-box, so that on these backends no byte that depends
on the key or the data is ever used as a table index. The scalar backend cannot say the same, see
the Security part of [AES](#aes). The wider forms of the x86 instruction (VAES), which run two or four blocks at once, are
not used: they only help code that has many blocks in hand at once, which a cipher called one block at a time does
not.

DES is the case with nothing to accelerate. No instruction in the x86 or Arm cryptographic extensions implements it, and
SIMD does not help with a block either: the sixteen rounds of a block are one chain, each round waiting on the one
before it. What does run well on a vector unit is DES in "bitslice" form, which encrypts as many blocks side by side as
a register has bits; it needs an interface that takes many blocks at once, and `BlockCipher` takes one. So DES and TDEA
have no row in the tables above and run on their one scalar implementation everywhere. It folds `E` and `P` into the
rounds (two rotations and eight lookups in tables of 64 words), does `IP` and its inverse as five exchanges of bit pairs
with no table, and does TDEA's three stages with a single `IP` and a single inverse. See the Benchmarking part of
[DES](#des) for what is left on the table.

ECDH is the case where the hardware offers nothing and no clever layout of the work changes that. No x86 or Arm
extension has an instruction for elliptic curve arithmetic, and the work is a long chain of multiplications of numbers
of 256 to 521 bits, each waiting on the one before it. What the CPU does offer is a multiplier with a 128-bit result,
which Rust reaches through `u128`, so ECDH has one portable implementation and no row in the tables above. The x86-64
build uses plain `mulq`: the `mulx` and `adcx`/`adox` instructions of BMI2 and ADX, which the fastest x86 big-number code
uses, are not in the x86-64 baseline, and a backend that used them behind a run-time check is not written. See the
Benchmarking part of [ECDH](#ecdh) for what that costs where it can be measured.

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
   that straddle every block and padding boundary, for the multi-buffer backends across batches whose
   messages differ in length, so that lanes run out of blocks at different times, and for AES across keys of
   all three sizes, comparing the round keys as well as the blocks. A backend that disagreed with
   the specification would fail the test suite, not silently produce wrong digests.

Because the vector instructions are intrinsics, these backends are where nearly all of the crate's `unsafe` lives.
Its scope is kept deliberately narrow:

- The single-message backends split the input into whole blocks (`chunks_exact`, `as_chunks`), so no length
  precondition can be violated by a caller.
- The multi-buffer backends receive fixed-size arrays, assembled by safe scalar code, so every vector load and store
  is in bounds by construction.
- The AES backends take their block and their round keys as fixed-size arrays, so each 16-byte load and store is in
  bounds by construction.

In every case the only obligation left is the one the dispatcher has already discharged: that the CPU feature is
available.

There are two other uses. One is an empty block of inline assembly in SHA-256's two aarch64 backends, scalar and
FEAT_SHA256. It emits no instruction, touches no memory, and only stops the compiler from rearranging equivalent
arithmetic into a slower order (`src/sha2/sha256/scalar.rs` and `src/sha2/sha256/aarch64.rs`). The other is the
volatile write that overwrites an AES or DES cipher's round keys, or an ECDH private key or shared secret, with zeros when
it is dropped, which the compiler would otherwise delete as a store nobody reads (`src/aes/schedule.rs`,
`src/des/schedule.rs` and, for ECDH, `src/wipe.rs`). Outside its tests, ECDH has no intrinsics and nothing else that is
`unsafe`.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Module layout

Each algorithm is one public module. The backends inside it (`scalar`, `aarch64`, `x86`, ...) are private, so what
you import is the same on every CPU, and the backend is chosen at runtime:

```text
cryptors
├── BlockCipher                      the trait every block cipher implements, re-exported at the root
├── Digest                           the trait every fixed-output hash implements, re-exported at the root
├── aes
│   └── Aes128, Aes192, Aes256
├── des
│   └── Des, TripleDes
├── ecdh                             key agreement: neither a hash nor a cipher, so it has its own types
│   ├── PrivateKey, PublicKey,       generic over the curve, so keys of two curves cannot be mixed
│   │   SharedSecret
│   ├── P256, P384, P521, X25519     the curves, which implement the sealed trait `Curve`
│   └── Error
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

The AES and DES ciphers are not hashes and do not implement `Digest`. They implement `BlockCipher`, a trait of the same
shape for keyed permutations of fixed-size blocks: a cipher is built from a key with `new`, which runs the key schedule
once, and then transforms blocks with `encrypt_block` and `decrypt_block`. The block and the key are types of the
cipher, so the 16-byte blocks of AES and the 8-byte blocks of DES fit the same code. See [AES](#aes) and [DES](#des).

Key agreement is neither of those. ECDH has no digest and no block, so its keys are types of their own: a
`PrivateKey<C>` and a `PublicKey<C>`, generic over the curve `C` (`P256`, `P384`, `P521` or `X25519`, which implement
the sealed trait `Curve`), and a `SharedSecret<C>` as the result of an exchange. Because the curve is a type, a private
key of one curve and a public key of another do not compile together. See [ECDH](#ecdh).

## AES

AES, specified in [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), is a block cipher: a permutation of 128-bit
blocks chosen by a key, together with the permutation that undoes it under the same key. NIST standardised it in 2001
as the successor to DES, from the Rijndael design of Joan Daemen and Vincent Rijmen, and it is the cipher behind most
encryption in use today: TLS, disk and file encryption, Wi-Fi. It is built from rounds of a substitution, a row
shuffle, a column mix and a key addition, and it is not a hash, so it does not implement `Digest`. It implements
`BlockCipher`, which has the same shape (associated lengths and array types, static dispatch) but holds a key. The
cipher modes on the list above will be generic over it, just as HMAC will be over `Digest`.

FIPS 197 defines three variants:

| Cipher | Key | Block | Rounds |
|--------|-----|-------|--------|
| AES-128 | 128 bits (16 bytes) | 128 bits (16 bytes) | 10 |
| AES-192 | 192 bits (24 bytes) | 128 bits (16 bytes) | 12 |
| AES-256 | 256 bits (32 bytes) | 128 bits (16 bytes) | 14 |

The block is always 128 bits; the key size only changes the number of rounds and the key expansion. A longer key is
not a longer version of a shorter one: it is a different permutation. What the crate provides is the cipher of FIPS
197 itself, one block at a time. A mode of operation (CBC, CTR, GCM, ...) is what turns it into encryption of a
message, and that is a separate item on the list above.

### Usage

```rust
use cryptors::{BlockCipher, aes::{Aes128, Aes256}};

// FIPS 197, Appendix B.
let key = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
let plaintext = [
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
];

// Building the cipher runs the key schedule once; every block then reuses it.
let cipher = Aes128::new(&key);
let ciphertext: [u8; 16] = cipher.encrypt_block(&plaintext);
assert_eq!(
    ciphertext,
    [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    ]
);
assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);

// The key sizes are separate types with the same interface, so code can be generic over the cipher.
fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
    C::new(key).encrypt_block(&C::Block::default())
}
assert_eq!(encrypt_zeros::<Aes256>(&[0; 32]).len(), Aes256::BLOCK_LEN);
```

### Security

AES is not broken. The best known attack on the full cipher, a biclique attack from 2011, finds the key only about 3 to
5 times faster than trying every key, which changes nothing in practice. Related-key attacks on AES-192 and AES-256 are
faster than that, but need encryptions under keys that differ in ways the attacker chooses; do not derive one key by
changing a few bits of another.

Three things to know when using it:

- **It is a block cipher, not an encryption scheme.** `encrypt_block` encrypts 16 bytes. Calling it on every block of a
  message independently (ECB) is not safe, because equal plaintext blocks give equal ciphertext blocks and the structure
  of the message shows through. Nor is anything authenticated: a ciphertext that has been altered decrypts to something
  else, without any error. Use a mode of operation, and an authenticated one for anything that crosses a network;
  this crate does not have them yet.
- **The hardware backends do not index memory by secrets. The scalar backend does.** With AES-NI or the Arm crypto
  extensions, neither the key nor the data is ever used as a memory address or a branch condition, even during the key
  expansion, and the instructions themselves are built to take the same time for every input; no CPU is known to do
  otherwise, though Arm documents that guarantee only while its data-independent-timing mode (DIT) is on, and this
  crate does not turn it on. The scalar backend looks up table entries at positions given by the state, and how long
  a lookup takes depends on whether the CPU has that part of the table cached. That has recovered AES keys in
  practice, both from a program on the same core (Osvik, Shamir and Tromer 2006) and, with many more samples, from the
  response times of a server across a network (Bernstein 2005). It is a real difference from the SHA-2 functions, whose
  work and memory accesses never depend on the message. The scalar backend is what runs on any CPU without AES
  instructions (on Arm, that includes one with the AES instructions but without PMULL, since Rust reports `aes` only
  with both), and on any target other than aarch64 and x86-64.
- **Keys stay in memory for as long as the cipher does.** The round keys are overwritten with zeros when the cipher is
  dropped, and `Debug` does not print them. That is best effort: copies the compiler made on the stack while a key was
  expanded or a block processed are not reachable from here, and neither is the copy that moving a cipher (into a
  `Box` or a `Vec`, say) can leave behind where it was. Where that matters, build the cipher where it will stay.

### Testing

```sh
cargo test aes     # known-answer vectors and differential tests against the scalar reference
```

The known-answer tests include the examples of FIPS 197 (Appendix B, and the one NIST publishes for each key size,
which the 2001 edition printed as Appendix C) and the ECB examples of NIST SP 800-38A, for all three key sizes and in
both directions. Those have only a handful of keys, so two further sets come from OpenSSL and Go's standard library,
which agree with each other: a thousand encryptions in a row, each on the previous ciphertext, for each key size, so
that one wrong table entry cannot go unnoticed; and a thousand different keys for each size, which is what exercises
the key expansion. Every test that uses a vector is run twice, through the public types and through the scalar backend
alone, which on a machine with AES instructions the public types do not use. On any CPU, `cargo test` also runs every
backend that CPU supports against the scalar one (the `matches_scalar_backend` test), comparing the round keys of both
directions and the blocks, and `--nocapture` names each backend it checked.

Unlike SHA-NI, AES-NI can be executed on a Mac: both Rosetta 2 and Docker's `linux/amd64` emulation support it. The
x86-64 backend therefore passes these tests as it is, with the emulator supplying the instructions, where the SHA-NI
backend could only be checked against a model of them written for the purpose. It has still not run on an x86 CPU.

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public types use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release aes -- --ignored --nocapture --test-threads=1
cd bench/aescmp && go test -v                        # Go's crypto/aes as shipped, and its CTR mode for reference
cd bench/aescmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
```

Both sides encrypt (or decrypt) 64 MiB in place, as independent 16-byte blocks with one call per block: ECB with no mode
on top. Each takes the best of five passes after a warm-up pass. They start from the same bytes and print the first block
after the passes; all four implementations print the same, which is a cross-check of its own.

On an Apple M1 Pro, against Go's `crypto` package on the same machine (medians of five interleaved runs, in MiB/s):

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| AES-128 encrypt | 444 | 327 | **11648** (FEAT_AES) | 2095 |
| AES-128 decrypt | 441 | 322 | **11931** (FEAT_AES) | 2091 |
| AES-192 encrypt | 361 | 273 | **8799** (FEAT_AES) | 1954 |
| AES-192 decrypt | 362 | 271 | **9585** (FEAT_AES) | 1955 |
| AES-256 encrypt | 306 | 235 | **8053** (FEAT_AES) | 1845 |
| AES-256 decrypt | 306 | 234 | **7378** (FEAT_AES) | 1833 |

The ciphers differ in rounds (10, 12 and 14), and the speed falls with them. Decrypting runs at about the speed of
encrypting, as the equivalent inverse cipher gives their rounds the same shape: identical to within 2% in the scalar
columns, and within 9%, in either direction, in the accelerated one.

Each cryptors column has a Go counterpart, and the two accelerated columns need more care than the others:

- **Scalar vs Go portable.** Go's portable code is what it runs on every platform without assembly. Both use lookup
  tables, and our scalar backend is 1.30–1.37x faster. The first version of ours, with one table and a rotate after each
  lookup, to save memory, was no faster than Go's (323 against 327 MiB/s for AES-128). Go keeps four tables, one per
  row, and so does ours now. That takes twelve rotates out of every round, and the rotates sit on the path each round
  waits on; it measured 37% faster, for 6 KiB more tables (8 KiB in all, for both directions).
- **Accelerated vs Go stdlib.** Both run the same instructions, so the 4.0–5.7x between them is not AES. `cipher.Block`
  takes one block per call, through an interface, and at 16 bytes a call the call is most of Go's time. Go's own bulk
  path is CTR mode, which hands the whole buffer to the assembly; it reaches 6917, 6225 and 5724 MiB/s for the three key
  sizes, even though it also builds the counters and XORs the keystream into the data (`TestThroughputBulk`, with no
  Rust counterpart). Against that, cryptors encrypts 1.4–1.7x faster, on an ECB loop that does less work per block.
  The loop gets there because the aarch64 backend is compiled into the caller's loop on this target (the instructions
  are in its baseline), which keeps the round keys in registers and lets the CPU overlap independent blocks. A mode in
  which each block waits for the one before it, like CBC encryption, cannot overlap them and will be slower; that is
  not measured here.

The instructions buy 24–27x over scalar.

No x86 figures are given yet, for the same reason as the SHA functions: nothing here can time real x86 hardware, and
Rosetta 2 translates AES-NI to Arm instructions, so its timings say nothing about an x86 CPU. The manual `Benchmarks`
workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners, and the throughput test
times the scalar backend there as well.

## DES

DES, specified in [FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final), is a block cipher: a permutation of 64-bit
blocks chosen by a 56-bit key, together with the permutation that undoes it under the same key. It became the US federal
standard in July 1977 and stayed it until NIST withdrew it in favour of AES. It is a Feistel network of 16 rounds whose only nonlinear
step is eight small substitution tables, and, like AES, it is not a hash, so it implements `BlockCipher`. FIPS 46-3
also defines TDEA, the Triple Data Encryption Algorithm, or Triple DES: three DES operations in a row under three keys.

**DES is broken and TDEA is obsolete.** They are here for reading data that already exists and for talking to systems
that have not moved on, not for protecting anything new. Use [AES](#aes).

| Cipher | Type | Key | Block | Rounds |
|--------|------|-----|-------|--------|
| DES | `Des` | 64 bits (8 bytes), of which 56 are used | 64 bits (8 bytes) | 16 |
| TDEA | `TripleDes` | 3 x 64 bits (24 bytes) | 64 bits (8 bytes) | 3 x 16 |

TDEA **encrypts** under `K1`, **decrypts** under `K2` and **encrypts** under `K3`. Decrypting in the middle is what
keeps it compatible with DES: if the three keys are equal, the first two steps cancel. FIPS 46-3 allows three keying
options for the bundle `(K1, K2, K3)`, and `TripleDes` takes the bundle as one 24-byte key, so each option is a kind of
key:

| Keying option | Bundle | Remarks |
|---------------|--------|---------|
| 1 | `K1`, `K2` and `K3` independent | the intended use |
| 2 | `K1` and `K2` independent, `K3 = K1` | "two-key" TDEA |
| 3 | `K1 = K2 = K3` | single DES, with a longer key |

What the crate provides is the cipher of FIPS 46-3 itself, one block at a time. A mode of operation (CBC, CTR, ...) is
what turns it into encryption of a message, and that is a separate item on the list above.

### Usage

```rust
use cryptors::{BlockCipher, des::{Des, TripleDes}};

// FIPS 81, the ECB example: the key 0123456789abcdef and the text "Now is t".
let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
let plaintext = *b"Now is t";

// Building the cipher runs the key schedule once; every block then reuses it.
let cipher = Des::new(&key);
let ciphertext: [u8; 8] = cipher.encrypt_block(&plaintext);
assert_eq!(ciphertext, [0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15]);
assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);

// TDEA takes the key bundle K1 || K2 || K3. With three equal keys (keying option 3) it is single DES.
let bundle: [u8; 24] = [key, key, key].concat().try_into().unwrap();
let triple = TripleDes::new(&bundle);
assert_eq!(triple.encrypt_block(&plaintext), ciphertext);

// The block is 8 bytes here, not 16, and code generic over the cipher does not mind.
fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
    C::new(key).encrypt_block(&C::Block::default())
}
assert_eq!(encrypt_zeros::<TripleDes>(&[0; 24]).len(), TripleDes::BLOCK_LEN);
```

### Security

**DES has a 56-bit key, and trying every one is within reach.** In 1998 the Electronic Frontier Foundation's DES
Cracker, built for under US$250,000, found a key in 56 hours, and in January 1999 it did so in 22 hours and 15 minutes
with the help of distributed.net. A machine of 120 FPGAs that cost under US$10,000 (COPACOBANA, 2006) was shown to
take under nine days on average, and the service crack.sh advertises the whole key space in about 26 hours. The attacks
on the 16 rounds themselves, differential (Biham and Shamir, 2^47 chosen plaintexts) and linear (Matsui, 2^43 known
plaintexts), beat exhaustive search on paper but need more data than anyone has; the short key is what matters.

**TDEA has a larger key and still falls short.** A meet-in-the-middle attack brings three-key TDEA down to about 112
bits, and NIST rates two-key TDEA at no more than 80. The bigger problem is the 64-bit block: two ciphertext blocks are
equal by chance after about 2^32 blocks (32 GiB) under one key, and in the usual modes that tells an attacker the XOR of
the two plaintexts. The Sweet32 attack (2016, CVE-2016-2183) used this against 3DES in TLS and recovered a secret cookie
from 610 GB of captured traffic. NIST withdrew FIPS 46-3 on 19 May 2005. Its TDEA specification, SP 800-67, capped a key
bundle at 2^20 blocks (8 MiB) in 2017 and was withdrawn on 1 January 2024, which "signifies that TDEA is no longer an
approved block cipher"; decrypting data that was protected earlier is still allowed. SP 800-131A (Revision 2, 2019) had
already disallowed two-key TDEA encryption and, after 2023, three-key TDEA encryption.

Four things to know when using it:

- **It is a block cipher, not an encryption scheme.** `encrypt_block` encrypts 8 bytes. Calling it on every block of a
  message independently (ECB) is not safe, because equal plaintext blocks give equal ciphertext blocks and the structure
  of the message shows through. Nor is anything authenticated: a ciphertext that has been altered decrypts to something
  else, without any error. With a block this short, the mode and the amount of data under one key matter more than they
  do for AES. This crate does not have modes yet.
- **The table lookups are indexed by secrets.** No CPU this crate targets has a DES instruction, so there is no backend
  without them: the rounds look up table entries at positions given by the state, and how long a lookup takes depends on
  whether the CPU has that part of the table cached. That is the same kind of leak as the AES scalar backend, see the
  Security part of [AES](#aes), though the tables here are small (2 KiB in all), which makes the signal coarser, not
  absent. The key schedule only shifts and masks. It is a real difference from the SHA-2 functions, whose work and memory
  accesses never depend on the message.
- **Keys stay in memory for as long as the cipher does.** The round keys are overwritten with zeros when the cipher is
  dropped, and `Debug` does not print them. That is best effort: copies the compiler made on the stack while a key was
  expanded or a block processed are not reachable from here, and neither is the copy that moving a cipher (into a `Box`
  or a `Vec`, say) can leave behind where it was. Where that matters, build the cipher where it will stay.
- **The last bit of every key byte is ignored, and every key is accepted.** The standard sets those eight bits to give
  each byte an odd number of ones and the algorithm does not use them, so two keys that differ only in them are the same
  key; nothing checks the parity. DES also has four weak keys, which are their own inverse, and twelve semi-weak ones, in
  pairs that undo each other. They are accepted like any other, and a random key is one of them with a probability near
  2^-52. Keying option 3 of TDEA is single DES with a longer key, and `TripleDes` builds it if it is given such a bundle.

### Testing

```sh
cargo test des::   # known-answer vectors, and a comparison with a literal implementation of the standard
```

The known-answer tests include the ECB example of FIPS 81 (the text "Now is the time for all " under the key
`0123456789abcdef`), the first entries of NIST's variable-plaintext and variable-key tests (the `TECBvartext` and
`TECBvarkey` files of its validation program), and vectors for the three TDEA keying options. Those have only a
handful of keys, so two further sets come from OpenSSL and Go's standard library, which agree with each other, for DES
and for TDEA: a thousand encryptions in a row, each on the previous ciphertext, and a thousand different keys, which is
what exercises the key schedule.

DES has one implementation, so there is no backend to compare against. In its place, `matches_reference` checks the
round keys and the blocks, in both directions, against a second DES written for the tests alone (`src/des/reference.rs`).
That one is as slow and as literal as the text of FIPS 46-3: blocks are vectors of bits, every permutation is the
standard's own table, and none of the shortcuts of the real one is taken. The real one never forms `IP`, `IP^-1` or `E`: they
are folded into rotations, five exchanges of bit pairs and the lookup tables, which is why it needs a check that known
answers alone do not give.
`triple_des_is_three_des` checks the single-block TDEA path, which skips the permutations between its stages, against
three DES operations in a row, for each keying option.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release des:: -- --ignored --nocapture --test-threads=1
cd bench/descmp && go test -v                        # Go's crypto/des, which has no assembly and so no purego run
```

Both sides encrypt (or decrypt) 32 MiB in place, as independent 8-byte blocks with one call per block: ECB with no mode
on top. Each takes the best of five passes after a warm-up pass. They start from the same bytes and print the first
block after the passes; the two implementations print the same, which is a cross-check of its own.

On an Apple M1 Pro, against Go's `crypto` package on the same machine (medians of five interleaved runs, in MiB/s):

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| DES encrypt | **110.3** | 96.6 |
| DES decrypt | **110.3** | 96.3 |
| TDEA encrypt | **36.6** | 33.8 |
| TDEA decrypt | **36.5** | 33.9 |

Decrypting runs at the speed of encrypting, as the same rounds are used with the keys in the opposite order, and TDEA
at a third of DES, as it is 48 rounds against 16. Skipping the four permutations between the stages of TDEA is worth
1.22x: three separate DES operations in a row, on the same keys, run at 30.2 MiB/s against 36.9 (one run of three).

The two are close because they are built the same way. Go's `crypto/des` also merges the S-boxes and `P` into tables of
64 words, takes the six-bit groups out of two rotations of the half-block, and does its TDEA with one initial and one
final permutation. Ours is 1.14x faster for DES and 1.08x for TDEA. Building a cipher is faster too, though not
measured with the same care (one run of three, with one block encrypted): about 0.5 µs for DES and 1.7 µs for TDEA,
against 0.9 and 2.3 µs.

What limits both is the chain of rounds. Each round waits on the one before it, so a call that encrypts a single block
leaves most of the CPU idle. An experiment that is not in the crate, running 2, 3, 4 and 8 independent blocks side by
side through the same code, reached 181, 236, 278 and 332 MiB/s for DES (one run), 1.6x to 3.0x the figure above, with
the same output. Getting there needs an interface that takes many blocks at once, which `BlockCipher` does not have, and
modes in which the blocks are independent (ECB, CTR, decrypting CBC); CBC encryption, where each block waits for the one
before it, would not gain.

No x86 figures are given yet, for the same reason as the others: nothing here can time real x86 hardware. The manual
`Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## ECDH

ECDH, Elliptic Curve Diffie-Hellman, lets two parties who share no secret agree on one over a channel that anyone can
read. Each makes a key pair, sends the public half to the other, and combines its own private half with the one it
received; both arrive at the same bytes, and someone who saw only the public keys cannot. It is how TLS 1.3, among
others, establishes the keys that the rest of a session is encrypted with. It is neither a hash nor a cipher, so it
implements neither `Digest` nor `BlockCipher`: a key pair is a type of its own, generic over the curve, and the curve
is one of four types that implement the sealed trait `Curve`.

| Curve | Type | Private key | Public key | Shared secret | Defined in |
|-------|------|-------------|------------|---------------|------------|
| NIST P-256 | `P256` | 32 bytes | 65 bytes | 32 bytes | [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final), [SEC 1](https://www.secg.org/sec1-v2.pdf) |
| NIST P-384 | `P384` | 48 bytes | 97 bytes | 48 bytes | the same |
| NIST P-521 | `P521` | 66 bytes | 133 bytes | 66 bytes | the same |
| Curve25519 | `X25519` | 32 bytes | 32 bytes | 32 bytes | [RFC 7748](https://www.rfc-editor.org/info/rfc7748) |

On the NIST curves a public key is an uncompressed point, the byte `0x04` and the two coordinates (SEC 1, section 2.3.3),
and the shared secret is the x-coordinate of the shared point (SEC 1, section 3.3.1; NIST SP 800-56A Rev. 3, section
5.7.1.2). A key from the network is validated when it is turned into a `PublicKey`: coordinates below the prime, point
on the curve, no point at infinity, no compressed form. X25519 takes any 32 bytes as a public key, as RFC 7748 asks, and
the one thing it refuses is the all-zero secret that a peer's point of small order would force. P-224 is not here: the
curves a Go program can use with `crypto/ecdh` are these four, and the general-purpose curve package on the list above is
a separate item.

The keys are generic over the curve, so a private key of one curve takes only a public key of the same curve and mixing
them is a compile error, where a library that picks the curve at run time can only return an error. Key generation takes
any `std::io::Read` as its source of randomness, because the standard library has no secure random source that is stable
and the `Rand` item above is still planned.

### Usage

```rust
use cryptors::ecdh::{P256, PrivateKey, PublicKey, X25519};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// RFC 7748, section 6.1: Alice and Bob each make a key from 32 bytes...
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

// ...send each other the public half, as bytes (this is where a bad key is refused)...
let bobs_public = PublicKey::<X25519>::from_bytes(bob.public_key().as_bytes()).unwrap();

// ...and both arrive at the same secret.
let from_alice = alice.diffie_hellman(&bobs_public).unwrap();
let from_bob = bob.diffie_hellman(alice.public_key()).unwrap();
assert_eq!(from_alice, from_bob);
assert_eq!(
    from_alice.as_bytes(),
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
);

// The NIST curves work the same way. A vector from NIST's CAVS for P-256: a private key, the other side's
// public key as it arrives on the wire (an uncompressed point), and the secret both get.
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

// A point that is not on the curve is refused when the key is built.
let mut off_the_curve = peer.as_bytes().to_vec();
off_the_curve[64] ^= 1;
assert!(PublicKey::<P256>::from_bytes(&off_the_curve).is_err());
```

Real keys come from `PrivateKey::generate`, given a source of secure random bytes of your own:

```rust
use cryptors::ecdh::{P384, PrivateKey};
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do
let key = PrivateKey::<P384>::generate(&mut rng)?;
// Send key.public_key().as_bytes() to the other side.
```

`examples/ecdh.rs` runs a complete exchange on each of the four curves, between two parties that each generate a key:
`cargo run --release --example ecdh`.

### Security

None of the four curves is broken. The best known attacks on the NIST curves take about the square root of the size of
the group, which NIST rates (SP 800-57) at 128, 192 and 256 bits of security for P-256, P-384 and P-521. RFC 7748 puts
Curve25519 "slightly under the standard 128-bit level". A large quantum computer would break all four, by Shor's
algorithm, and a key exchange that has to outlast one needs a post-quantum scheme such as ML-KEM, which is also on the
list above, alongside or instead.

Six things to know when using it:

- **The shared secret is not a key.** It is one coordinate of a point, and both sides, and anyone who gets it from either
  of them, see exactly the same bytes. Run it through a key derivation function, and include both public keys in what
  that hashes, as RFC 7748 (section 6.1) describes and its section 7 explains the need for, before using any of it as a
  key. HKDF is on the list above and not yet here.
- **Nothing is authenticated.** ECDH gives two parties a secret in common; it does not say who they are. Someone between
  them can play each against the other and end up with a secret shared with both, so a protocol has to bind the keys to
  an identity (signatures, certificates, a pre-shared secret). Use a fresh key pair for each exchange where you can: a key
  that is reused makes every exchange with it a target for an attack on that one key.
- **A public key is validated, and that is the point.** On the NIST curves, a point that is not on the curve lets an
  attacker who chooses it learn the private key a little at a time, one exchange after another (an invalid-curve attack).
  `PublicKey::from_bytes` is where that is refused, so a `PublicKey` is always a valid one, and `diffie_hellman` needs no
  further check. X25519 has no such attack on its `u` coordinate, but a few points have small order and force the secret
  to all zeros; `diffie_hellman` returns `Error::LowOrderPoint` for them, which RFC 7748 allows.
- **The randomness is the caller's.** `generate` is only as good as the reader it is given. A predictable one makes every
  key it produced guessable.
- **The arithmetic is written not to depend on secrets, and that is checked in one way only.** No branch condition or
  memory address is derived from a private key: the scalar goes through a table lookup that reads every entry, a
  conditional swap done with masks, and formulas that are complete, so they have no special cases to branch on. The
  masks go through `core::hint::black_box`, because a compiler may turn a mask back into a jump, and `black_box` is a
  request, not a guarantee. What backs the claim is the assembly `rustc` produced for `aarch64` and `x86_64`, which was
  inspected: the conditional jumps in the code that handles a secret are loops over a public number of limbs, windows or
  bits of the exponent that inverts a number, checks of public lengths, and two checks of a result (whether the shared
  point is the point at infinity, which for a valid key it never is, and whether an X25519 secret is all zeros, which
  the peer's point decides whatever our key is). That is one compiler's output for two targets, with no timing
  measurement on real hardware behind it, and nothing protects against attacks that read power consumption or inject
  faults.
- **Keys stay in memory for as long as they exist.** A private key and a shared secret are overwritten with zeros when
  dropped, and `Debug` does not print them. That is best effort: the working values of the arithmetic (numbers that depend
  on a key, on the stack and in registers while it is in use) are not overwritten, and neither is the copy that moving a
  key (into a `Box` or a `Vec`, say) can leave
  behind where it was.

### Testing

```sh
cargo test ecdh::   # known answers, Wycheproof, chained exchanges against OpenSSL, and the arithmetic against references
```

The known-answer tests include the vectors of NIST's CAVS for the three curves (the ones Go's tests use) and those of
RFC 7748: the function itself (section 5.2), including the thousand-step chain, and the exchange of section 6.1. The
rest of the confidence comes from three other kinds of test:

- **Project Wycheproof.** The four of its ECDH files that take points as raw bytes (`ecdh_secp256r1_ecpoint_test.json`,
  the same for 384 and 521, and `x25519_test.json`) hold 2,324 cases for these curves: points that are not on the curve (the
  invalid-curve attack), points of other curves, compressed and malformed encodings, the points of small order of
  X25519, non-canonical encodings and points on its twist, private keys with unusual bit patterns, public keys that hit
  an edge case such as a zero coordinate when doubled, shared secrets that are special cases, and a regression for a bug
  that Go's own P-256 once had on amd64 (CVE-2017-8932). All of them were run once and passed. 273 are in the tests:
  every NIST case that is invalid or only acceptable, every X25519 case whose public key is of small order, not reduced,
  of a special form or small, the one with a zero secret on each NIST curve, and samples of the rest.
- **Chained exchanges.** Rounds of two derived keys exchanging with each other, each round seeded by the hash of the
  last, for 16 rounds on each curve: some hundreds of thousands of field multiplications per curve, so a wrong carry in
  one of them changes everything after it. The final values come from OpenSSL, and `bench/ecdhcmp` recomputes them with Go's
  `crypto/ecdh`; the three agree.
- **Differential tests.** The five-limb field of X25519 is compared with the generic field of the NIST curves on
  pseudo-random inputs and on limbs at the largest values its bounds allow, and a whole ladder is compared with the same
  ladder on the generic field. The table of multiples of the generator is compared with the generic multiplication, and
  the curve constants with the relations that define them (the generator is on the curve; the order times the generator
  is the point at infinity).

The tests also cover the other behaviour of the API: what `generate` does with a reader that gives a zero, the order or a
too-big number (it draws again, and after 64 candidates in a row that are not keys it reports an error), that the
smallest and largest private keys and the point with x = 0 are accepted, that P-521 masks the seven unused bits of its first byte, that a failing reader is
reported, that `Debug` shows no secret, and that a key and a shared secret leave nothing behind after they are dropped.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release ecdh:: -- --ignored --nocapture --test-threads=1
cd bench/ecdhcmp && go test -v                       # Go's crypto/ecdh as shipped, with its assembly
cd bench/ecdhcmp && go test -tags purego -v          # Go's portable code, with no assembly
```

Both sides time the four operations of one side of a handshake, on the same keys: building a private key from its bytes
(which derives the public key: a multiplication of the generator), building a public key from its bytes (which checks
that the point is on the curve), the exchange itself (a multiplication of the peer's point), and the three in a row.
Each runs for about 50 ms to size a batch of about 100 ms, and the best of five batches is reported. Key generation
itself is not timed, so the cost of the random source is on neither side. Both print the first 8 bytes of the shared
secret, and all three runs print the same.

On an Apple M1 Pro, against Go 1.27.1's `crypto/ecdh` on the same machine (medians of five interleaved runs, in
microseconds per operation, lower is better):

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
| X25519 new private key | **30.5** | 35.5 | 35.6 |
| X25519 ecdh | **30.6** | 35.5 | 35.5 |
| X25519 handshake | **61.1** | 71.1 | 71.1 |

Building a public key takes 0.1 to 0.5 µs for the NIST curves here and 0.2 to 0.9 µs in Go, and nothing for X25519, which
has nothing to check. Run-to-run spread was within about 1% in every cell, but the machine was not idle (load average
2 to 4, a desktop), so the last digit means little.

Per curve:

- **X25519 is 16% faster than Go's.** Go's X25519 has assembly for amd64 only, so on this machine the two are portable
  code against portable code, and both use five limbs of 51 bits. The first version of ours used the field of the
  NIST curves, which does not know about the shape of `2^255 - 19`, and took 79.6 µs for an exchange, about 2.2x Go's at the time; the
  field of its own took that to 30.6.
- **P-256: level with Go's portable code on the exchange, 21% behind on building a key, and 2.7x behind its assembly.**
  Go has assembly for P-256 on arm64 (and on amd64, ppc64le and s390x). Nothing in this crate competes with that, and the
  `purego` column is the fair one: 113.3 against 110.4 µs for the exchange, 31.8 against 26.2 for building a key.
- **P-384 and P-521: 18% and 7% behind Go on the exchange, level or ahead on building a key.** Go has no assembly for
  them. Both are the same kind of code, Montgomery multiplication on 64-bit limbs, so the difference is in the
  details. Two things that were measured and are not the cause: the `black_box` on the masks (removing it changes the NIST
  curves by 1% or less, and by 6% in the generic field that X25519 started with), and loops that LLVM does not unroll in
  the 6- and 9-limb multiplications (raising its unroll threshold so that it does makes P-384 and P-521 4–5% faster, and
  P-256 not at all).
  The first key of a curve in a process also builds the table of multiples of the generator, once: in a fresh process,
  about 0.5 ms more for P-256, 1.7 ms for P-384 and 4 ms for P-521 (medians of seven; a busy machine took up to twice
  that), kept afterwards (90, 200 and 420 KiB). The figures above leave that out.

What would make the NIST curves faster, none of it done: a squaring that uses the symmetry of a product (about a fifth
of the multiplications of a squaring), a reduction written for the shape of each prime (P-521's `2^521 - 1` reduces by
shifts and additions, with no Montgomery step at all), signed windows (half the table), and, on x86-64, a backend for
BMI2 and ADX behind a run-time check, which is what the fastest x86 big-number code relies on. Nothing here can run that
one to see what it would gain.

No x86 figures are given yet, for the same reason as the others: nothing here can time real x86 hardware, and Rosetta 2
translates the instructions, so its timings say nothing about an x86 CPU. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

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
