# Cryptors

## Index

**General**

- [Overview](#overview)
- [Why everything in a single crate?](#why-everything-in-a-single-crate)
- [Rust Versions Compatibility](#rust-versions-compatibility)
- [Algorithm](#algorithm)
- [Hardware acceleration](#hardware-acceleration)
- [Module layout](#module-layout)
- [Example](#example)

**Algorithms**

- [AES](#aes)
- [DES](#des)
- [ECDH](#ecdh)
- [ECDSA](#ecdsa)
- [Ed25519](#ed25519)
- [HKDF](#hkdf)
- [HMAC](#hmac)
- [HPKE](#hpke)
- [MD5](#md5)
- [ML-DSA](#ml-dsa)
- [ML-KEM](#ml-kem)
- [PBKDF2](#pbkdf2)
- [Rand](#rand)
- [RC4](#rc4)
- [RSA](#rsa)
- [SHA-1](#sha-1)
- [SHA-256](#sha-256)
- [SHA-3](#sha-3)
- [SHA-512](#sha-512)

**Project**

- [Contributing](#contributing)

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
| ECDSA | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) and [RFC 6979](https://www.rfc-editor.org/info/rfc6979): Elliptic Curve Digital Signature Algorithm over P-224, P-256, P-384 and P-521, randomized and deterministic | Implemented |
| Ed25519 | [RFC 8032](https://www.rfc-editor.org/info/rfc8032): Edwards-curve Digital Signature Algorithm over edwards25519 (Ed25519, Ed25519ctx and Ed25519ph) | Implemented |
| HKDF | [RFC 5869](https://www.rfc-editor.org/info/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function, over any hash of the crate that implements `Digest` | Implemented |
| HMAC | [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final) and [RFC 2104](https://www.rfc-editor.org/info/rfc2104): Keyed-Hash Message Authentication Code, over MD5, SHA-1 and the six SHA-2 functions | Implemented |
| HPKE | [RFC 9180](https://www.rfc-editor.org/info/rfc9180): Hybrid Public Key Encryption over DHKEM(P-256, P-384, P-521, X25519), HKDF and AES-GCM | Implemented |
| MD5 | [RFC 1321](https://www.rfc-editor.org/info/rfc1321): The MD5 Message-Digest Algorithm | Implemented |
| ML-DSA | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): Module-Lattice-Based Digital Signature Algorithm (ML-DSA-44, ML-DSA-65 and ML-DSA-87), hedged and deterministic, with contexts, pre-hash and external μ | Implemented |
| ML-KEM | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final): Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-512, ML-KEM-768 and ML-KEM-1024), with implicit rejection | Implemented |
| PBKDF2 | [RFC 8018](https://www.rfc-editor.org/info/rfc8018): Password-Based Key Derivation Function 2 (PKCS #5 v2.1), with HMAC over any hash of the crate that implements `Digest` | Implemented |
| Rand | Cryptographically secure random number generator: the operating system's (`getrandom(2)`, `arc4random_buf(3)` or `/dev/urandom`), as an `io::Read`, with random bytes, random text and uniform numbers below a bound | Implemented |
| RC4 | Rivest Cipher 4, the stream cipher of Schneier's *Applied Cryptography* (ARC4, ARCFOUR), with the vectors of [RFC 6229](https://www.rfc-editor.org/info/rfc6229); broken, kept for legacy data | Implemented |
| RSA | [RFC 8017](https://www.rfc-editor.org/info/rfc8017): PKCS #1 v2.2, RSA encryption (OAEP and PKCS #1 v1.5) and signatures (PSS and PKCS #1 v1.5), with keys of 1,024 to 16,384 bits that are generated or built from their numbers | Implemented |
| SHA-1 | [RFC 3174](https://www.rfc-editor.org/info/rfc3174): US Secure Hash Algorithm 1 | Implemented |
| SHA-256 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-224 and SHA-256 | Implemented |
| SHA-3 | FIPS 202: SHA-3 and SHAKE extendable output functions | Implemented |
| SHA-512 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-384, SHA-512, SHA-512/224, and SHA-512/256 | Implemented |
| TLS | RFC 5246 / RFC 8446: TLS 1.2 and TLS 1.3 | Planned |
| X.509 | A subset of the X.509 standard, with the shared ASN.1 structures for certificates, CRLs and OCSP (`pkix`) | Planned |

Status is one of Implemented, In progress or Planned.

## Hardware acceleration

Cryptors targets **aarch64** and **x86_64**. Where the CPU has a dedicated instruction for a primitive, the crate uses
it. Where it has none, the crate falls back to a portable scalar implementation, or to hashing several messages at once.
Backends are picked at runtime; nothing needs to be configured.

### Dedicated instructions

| Algorithm | Target | Feature | Instructions |
|-----------|--------|---------|--------------|
| AES | aarch64 | ARMv8 Cryptographic Extensions (`FEAT_AES`) | `AESE`, `AESMC`, `AESD`, `AESIMC` |
| AES | x86_64 | AES-NI | `AESENC`, `AESENCLAST`, `AESDEC`, `AESDECLAST`, `AESIMC` |
| AES-GCM's GHASH (HPKE) | aarch64 | ARMv8 Cryptographic Extensions (`FEAT_PMULL`) | `PMULL`, `PMULL2` |
| AES-GCM's GHASH (HPKE) | x86_64 | PCLMULQDQ, with SSSE3 | `PCLMULQDQ`, `PSHUFB` |
| SHA-1 | aarch64 | ARMv8 Cryptographic Extensions (`FEAT_SHA1`) | `SHA1C`, `SHA1P`, `SHA1M`, `SHA1H`, `SHA1SU0`, `SHA1SU1` |
| SHA-1 | x86_64 | SHA-NI | `SHA1RNDS4`, `SHA1NEXTE`, `SHA1MSG1`, `SHA1MSG2` |
| SHA-224, SHA-256 | aarch64 | ARMv8 Cryptographic Extensions (`FEAT_SHA256`) | `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` |
| SHA-224, SHA-256 | x86_64 | SHA-NI | `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` |
| SHA-3 | aarch64 | ARMv8.2 SHA-3 extension (`FEAT_SHA3`) | `EOR3`, `RAX1`, `XAR`, `BCAX` |
| SHA-384, SHA-512, SHA-512/224, SHA-512/256 | aarch64 | ARMv8.2 SHA-512 extension (`FEAT_SHA512`) | `SHA512H`, `SHA512H2`, `SHA512SU0`, `SHA512SU1` |

Notes per algorithm:

- **AES**: each instruction does most or all of a cipher round, and the key expansion uses them too, so no secret byte
  is ever a table index. The scalar backend cannot say that, see [AES](#aes). The wider VAES forms are not used, because
  a cipher called one block at a time cannot fill them.
- **DES, TDEA**: no instruction exists, and the sixteen rounds of a block form a single dependency chain, so there is
  one scalar implementation everywhere. See [DES](#des).
- **RC4**: no instruction exists, and each step of the generator reads two positions that the step before it may have
  swapped, so the steps are one dependency chain and there is one scalar implementation everywhere. See [RC4](#rc4).
- **ECDH, ECDSA, Ed25519**: no instruction exists for elliptic curve arithmetic either. They share one portable
  implementation built on `u128` multiplications; x86_64 uses plain `mulq`, not BMI2/ADX. They still benefit from
  hardware through their hash: ECDSA runs HMAC_DRBG on the SHA-256 and SHA-512 backends above, and Ed25519 hashes with
  SHA-512. See [ECDH](#ecdh), [ECDSA](#ecdsa) and [Ed25519](#ed25519).
- **ML-DSA**: no instruction exists for lattice arithmetic either, so the transform and the products are one portable
  implementation in safe Rust, which the compiler turns into NEON instructions in places on aarch64. Much of the time goes
  into SHAKE, which runs on the SHA-3 backends above (`FEAT_SHA3` on aarch64). See [ML-DSA](#ml-dsa).
- **ML-KEM**: no instruction exists for lattice arithmetic either, so the transform and the products are one portable
  implementation in safe Rust on `i16` coefficients, which the compiler turns into NEON instructions in places on
  aarch64. A good part of the time goes into SHAKE and SHA-3, which run on the SHA-3 backends above (`FEAT_SHA3` on
  aarch64). See [ML-KEM](#ml-kem).
- **HKDF, HMAC, PBKDF2**: no instruction exists for them either; they run on the hash's own backend, whichever the
  CPU has from the table above, through the hash's incremental form. See [HKDF](#hkdf), [HMAC](#hmac) and
  [PBKDF2](#pbkdf2).
- **Rand**: no instruction is used, not even `RDRAND` or `RNDR`: the operating system's generator already mixes the
  hardware's source with others, and a generator of the crate's own on top of it would share its state across a fork.
  Nothing is selected at run time; the platform is chosen at compile time. See [Rand](#rand).
- **HPKE**: gets its curves, KDF and cipher from the algorithms above, and adds hardware GHASH. Carry-less multiply
  replaces the many integer multiplications of the software version, which makes GHASH 23 times faster here. See
  [HPKE](#hpke).
- **SHA-256**: x86_64 CPUs with AVX2 but without SHA-NI (Intel Haswell to Ice Lake) use a backend based on Intel's
  *Fast SHA-256 Implementations on Intel Architecture Processors*, which computes the message schedule of two blocks at
  once.
- **SHA-3**: no x86 CPU implements Keccak, so one digest runs on the scalar backend (with a BMI1/BMI2 build where
  available). On aarch64 the SHA-3 instructions each replace a whole pattern of XOR, rotate and and-not, taking a round
  from about 155 operations to 66. Real x86 parallelism comes from the next section.
- **SHA-384, SHA-512, SHA-512/t**: x86_64 uses the scalar backend. SHA-NI does not include SHA-512, and the newer
  Intel SHA-512 instructions are in too few CPUs to test here, so no unverified backend is shipped.

### Multi-buffer SIMD, where no instruction exists

No shipping CPU implements MD5, and no x86 CPU implements Keccak. Ordinary SIMD does not help within one message
either: MD5 is a single dependency chain, and SHA-3's 25-lane state maps badly onto 4-lane registers. What is parallel
is hashing several independent messages, with each SIMD lane holding the same state word of a different message:

| Algorithm | Target | Feature | Lanes |
|-----------|--------|---------|-------|
| MD5 | aarch64 | NEON (baseline) | 16, 8, 4 |
| MD5 | x86_64 | AVX2 | 8 |
| MD5 | x86_64 | SSE2 (baseline) | 4 |
| SHA-3 | x86_64 | AVX2 | 4 |
| SHA-3 | x86_64 | SSE2 (baseline) | 2 |
| SHA-3 | aarch64 | `FEAT_SHA3` | 2 |

This has its own API: `Md5::digest_many` and `sha3::sha3_256_many` take a slice of messages. They use the widest
backend available, then narrower ones for the remainder, and the messages may differ in length.

On aarch64, 4 MD5 lanes leave the vector units idle (about 1.7x scalar), so the 8- and 16-lane versions interleave two
and four lane groups to reach 3.2x and 4.8x. SHA-3 on aarch64 gets both kinds of acceleration: one message uses the
fused instructions on half a register, two messages use the whole register.

### Rules

1. **A portable scalar implementation always exists.** It is optimized and tested against the specification's vectors
   in its own right.
2. **Backend selection is automatic, at runtime.** Accelerated code is only entered after the CPU feature is confirmed,
   so a binary built on one machine stays correct on another. Features in the target baseline are checked at compile
   time at no cost.
3. **Every backend is differential-tested against the scalar one**, byte for byte, across lengths around every block
   and padding boundary. Multi-buffer backends are also tested on batches of different lengths, AES on all three key
   sizes (round keys included), and GHASH on lengths around its groups of sixteen blocks.

Most of the crate's `unsafe` lives in the intrinsics backends, and is kept narrow: every backend takes whole blocks or
fixed-size arrays assembled by safe code, so each load and store is in bounds by construction. The only obligation left
is the one the dispatcher has already met, that the CPU feature is present.

Three other uses exist:

- An empty inline `asm!` block in SHA-256's aarch64 scalar and `FEAT_SHA256` backends. It emits no instruction and only
  stops the compiler from reordering the arithmetic into a slower order (`src/sha2/sha256/scalar.rs`,
  `src/sha2/sha256/aarch64.rs`).
- A volatile write that zeroes secrets on drop (AES and DES round keys, the RC4 state, ECDH/ECDSA/Ed25519/RSA private keys, ECDH shared
  secrets, HMAC key states, HPKE and AES-GCM secrets), which the compiler would otherwise delete as a dead store
  (`src/aes/schedule.rs`, `src/des/schedule.rs`, `src/wipe.rs`). `src/wipe.rs` wipes aligned buffers in 16-byte words.

- The declaration of the system's random generator (`getrandom` or `arc4random_buf`, from the C library the standard
  library already links) and one call to it, with the buffer's pointer and length (`src/rand/sys.rs`).

ECDH, ECDSA, Ed25519, HMAC and RSA have no other `unsafe` outside their tests, and neither does HPKE outside its GHASH
backends.

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
├── ecdsa                            signatures: neither a hash nor a cipher either, so it has its own types
│   ├── PrivateKey, PublicKey,       generic over the curve, so a key and a signature of two curves cannot be mixed
│   │   Signature
│   ├── P224, P256, P384, P521       the curves, which implement the sealed trait `Curve` (ecdh has three of these types)
│   └── Error
├── ed25519                          signatures on one curve with its hash built in, so nothing is generic
│   ├── SigningKey, VerifyingKey,    a method for each of the three schemes: Ed25519, Ed25519ctx, Ed25519ph
│   │   Signature
│   └── Error, MAX_CONTEXT_LEN
├── hkdf                             key derivation: generic over the hash, as in Hkdf<Sha256>
│   ├── Hkdf                         a pseudorandom key, extracted or given, ready to expand into keys
│   └── Error
├── hmac                             message authentication: built on a hash, so generic over any `Digest`
│   ├── Hmac<D>                      keyed once, with the hash's states after the padded key
│   ├── hmac                         the one-call form
│   └── VerifyError
├── hpke                             encryption to a public key: a protocol over ecdh, HKDF and AES-GCM
│   ├── Suite, Kem, Kdf, Aead        the suite and its three parts, values chosen at run time from their identifiers
│   ├── PrivateKey, PublicKey        keys that belong to one KEM each
│   ├── Sender, Recipient            the two sides of a context
│   ├── Mode, SenderMode,            the mode, and its inputs on each side
│   │   RecipientMode
│   └── Error
├── md5
│   └── Md5
├── mldsa                            post-quantum signatures: generic over the parameter set, as ecdsa is over the curve
│   ├── PrivateKey, PublicKey,       a key and a signature of two parameter sets cannot be mixed
│   │   Signature
│   ├── MlDsa44, MlDsa65, MlDsa87    the parameter sets, which implement the sealed trait `Parameters`
│   ├── PreHash                      the hash functions that HashML-DSA can sign a digest of
│   └── Error, MAX_CONTEXT_LEN, SEED_LEN
├── mlkem                            post-quantum key encapsulation: generic over the parameter set, as mldsa is
│   ├── DecapsulationKey,            keys, a ciphertext and a secret of two parameter sets cannot be mixed
│   │   EncapsulationKey,
│   │   Ciphertext, SharedSecret
│   ├── MlKem512, MlKem768,          the parameter sets, which implement the sealed trait `Parameters`
│   │   MlKem1024
│   └── Error, SEED_LEN, SHARED_SECRET_LEN
├── pbkdf2                           password-based key derivation: one function, generic over the hash
│   ├── derive                       fills a buffer with the key for a password, a salt and an iteration count
│   └── Error
├── rand                             the operating system's random number generator
│   ├── Reader                       as an `io::Read`: what the keys of the other modules take as their randomness
│   ├── fill, text                   random bytes into a buffer, and a random string for a token
│   └── below                        a uniform number below a bound, from any reader
├── rc4                              a stream cipher: neither a hash nor a block cipher, so it has its own type
│   ├── Rc4                          built from a key, then XORs data with the keystream, however it is cut into calls
│   └── Error
├── rsa                              public-key encryption and signatures: neither a hash nor a cipher, so it has its own types
│   ├── PublicKey, PrivateKey        built from numbers or generated; a method for each scheme, the hash a type parameter
│   ├── SaltLength                   the salt of a PSS signature
│   ├── Pkcs1Hash                    the sealed trait of the eight hashes that a PKCS #1 v1.5 signature can name
│   └── Error
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

Runnable examples for every algorithm are in the `examples/` directory: `cargo run --release --example <name>`.

## AES

AES ([FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)) is a block cipher: a keyed permutation of 128-bit blocks.
The crate provides the FIPS 197 cipher only, one block at a time; modes of operation (CBC, CTR, GCM, ...) are not
included yet. It implements `BlockCipher` rather than `Digest`: the same shape (associated lengths and array types,
static dispatch), but it holds a key. Future cipher modes will be generic over it, as [HMAC](#hmac) is over `Digest`.

| Cipher | Key | Block | Rounds |
|--------|-----|-------|--------|
| AES-128 | 16 bytes | 16 bytes | 10 |
| AES-192 | 24 bytes | 16 bytes | 12 |
| AES-256 | 32 bytes | 16 bytes | 14 |

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

// `new` runs the key schedule once; every block reuses it.
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

// Each key size is its own type with the same interface.
fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
    C::new(key).encrypt_block(&C::Block::default())
}
assert_eq!(encrypt_zeros::<Aes256>(&[0; 32]).len(), Aes256::BLOCK_LEN);
```

### Security

AES is not broken: the best attack on the full cipher (biclique, 2011) is only 3-5x faster than brute force.
Related-key attacks on AES-192/256 exist, so never derive one key by flipping bits of another.

- **Block cipher, not an encryption scheme.** ECB (each block encrypted on its own) leaks equal blocks and
  authenticates nothing. Use an (authenticated) mode of operation (none here yet).
- **Hardware backends are constant-time; the scalar backend is not.**
  - AES-NI and Arm crypto extensions: no key or data byte is ever a memory address or branch condition, key expansion
    included. Arm guarantees data-independent timing only with DIT enabled, which this crate does not set.
  - Scalar: state-indexed table lookups leak through cache timing. Such attacks have recovered AES keys from the same
    core (Osvik, Shamir and Tromer 2006) and over a network (Bernstein 2005).
  - Scalar runs on CPUs without AES instructions, on Arm CPUs with AES but without PMULL (Rust reports `aes` only with
    both), and on every target other than aarch64 and x86-64.
- **Key wiping is best effort.** Round keys are zeroed on drop and hidden from `Debug`, but compiler stack copies and
  the copy a move leaves behind (e.g. into a `Box` or `Vec`) are not wiped. Build the cipher where it will stay.

### Testing

```sh
cargo test aes     # known-answer vectors and differential tests against the scalar reference
```

Covered for all three key sizes, in both directions:

- FIPS 197 examples (Appendix B, plus NIST's per-key-size example, Appendix C in the 2001 edition).
- NIST SP 800-38A ECB examples.
- OpenSSL and Go (which agree): per key size, 1,000 chained encryptions and 1,000 different keys (key expansion).

Every vector runs twice: through the public types and through the scalar backend alone. `matches_scalar_backend`
compares every backend the CPU supports against scalar (round keys for both directions, and blocks); `--nocapture`
lists the backends checked. The x86-64 AES-NI backend passes under Rosetta 2 and Docker `linux/amd64` emulation, but
has not run on a real x86 CPU.

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public types use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release aes -- --ignored --nocapture --test-threads=1
cd bench/aescmp && go test -v                        # Go's crypto/aes as shipped, and its CTR mode for reference
cd bench/aescmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
```

Workload: 64 MiB in place as independent 16-byte blocks, one call per block (ECB, no mode); best of five passes after
a warm-up. All implementations print the same first block as a cross-check.

Apple M1 Pro, MiB/s (medians of five interleaved runs):

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| AES-128 encrypt | 444 | 327 | **11648** (FEAT_AES) | 2095 |
| AES-128 decrypt | 441 | 322 | **11931** (FEAT_AES) | 2091 |
| AES-192 encrypt | 361 | 273 | **8799** (FEAT_AES) | 1954 |
| AES-192 decrypt | 362 | 271 | **9585** (FEAT_AES) | 1955 |
| AES-256 encrypt | 306 | 235 | **8053** (FEAT_AES) | 1845 |
| AES-256 decrypt | 306 | 234 | **7378** (FEAT_AES) | 1833 |

- Speed falls with the round count (10, 12, 14).
- The ECB loop lets independent blocks overlap. Chained modes such as CBC encryption cannot, and will be slower (not
  measured).
- No x86 figures yet: Rosetta 2 timings say nothing about x86 hardware. The manual `Benchmarks` workflow
  (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners, scalar backend included.

## DES

DES ([FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final)) is a 64-bit block cipher: a 16-round Feistel network with
a 56-bit key. FIPS 46-3 also defines TDEA (Triple DES): three DES operations under three keys. Both implement
`BlockCipher`, one block at a time; modes of operation (CBC, CTR, ...) are not provided yet.

**DES is broken and TDEA is obsolete.** Use them only to read existing data or talk to legacy systems. For anything new,
use [AES](#aes).

| Cipher | Type | Key | Block | Rounds |
|--------|------|-----|-------|--------|
| DES | `Des` | 64 bits (8 bytes), of which 56 are used | 64 bits (8 bytes) | 16 |
| TDEA | `TripleDes` | 3 x 64 bits (24 bytes) | 64 bits (8 bytes) | 3 x 16 |

TDEA encrypts under `K1`, decrypts under `K2`, encrypts under `K3`. `TripleDes` takes `K1 || K2 || K3` as one 24-byte
key, so the FIPS 46-3 keying options are just kinds of key:

| Keying option | Bundle | Remarks |
|---------------|--------|---------|
| 1 | `K1`, `K2` and `K3` independent | the intended use |
| 2 | `K1` and `K2` independent, `K3 = K1` | "two-key" TDEA |
| 3 | `K1 = K2 = K3` | single DES, with a longer key |

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

// Generic code works with the 8-byte block too.
fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
    C::new(key).encrypt_block(&C::Block::default())
}
assert_eq!(encrypt_zeros::<TripleDes>(&[0; 24]).len(), TripleDes::BLOCK_LEN);
```

### Security

- **DES: the 56-bit key can be brute-forced.** The EFF DES Cracker took 56 hours (1998), and 22 hours with
  distributed.net (1999); crack.sh advertises the whole key space in about 26 hours.
- **TDEA is weaker than its key size.** Meet-in-the-middle brings three-key TDEA to about 112 bits; NIST rates two-key
  TDEA at no more than 80.
- **TDEA's 64-bit block is too short.** Collisions appear after about 2^32 blocks (32 GiB) under one key and leak
  plaintext XORs (Sweet32, CVE-2016-2183).
- **Status.** NIST withdrew FIPS 46-3 in 2005 and SP 800-67 (TDEA) on 1 January 2024. TDEA is no longer approved for
  encryption; decrypting old data is still allowed.
- **Block cipher, not an encryption scheme.** ECB (each block encrypted on its own) leaks message structure and
  authenticates nothing. With an 8-byte block, the mode and the data volume per key matter even more than for AES.
- **Not constant-time.** No targeted CPU has a DES instruction, so the only backend indexes lookup tables by secret
  state, which can leak through cache timing as in AES's scalar backend (see [AES](#aes)). The 2 KiB tables give a
  coarser signal, but still one. The key schedule only shifts and masks.
- **Key wiping is best effort.** Round keys are zeroed on drop and hidden from `Debug`. Stack copies and copies left
  behind by moves are not reachable; build the cipher where it will stay.
- **Every key is accepted.** The low (parity) bit of each key byte is unused and not checked. The 4 weak and 12
  semi-weak keys are accepted (a random key hits one with probability near 2^-52).

### Testing

```sh
cargo test des::   # known-answer vectors, and a comparison with a literal implementation of the standard
```

- **Known answers:** the FIPS 81 ECB example, the first entries of NIST's `TECBvartext` and `TECBvarkey` tests, and
  vectors for all three TDEA keying options.
- **OpenSSL / Go sets** (they agree), for DES and TDEA: 1,000 chained encryptions, and 1,000 different keys to exercise
  the key schedule.
- **`matches_reference`:** with one implementation there is no backend to diff against, so round keys and blocks in
  both directions are checked against a slow bit-by-bit DES that follows FIPS 46-3 literally (`src/des/reference.rs`).
  The real code folds `IP`, `IP^-1` and `E` into rotations and tables, which known answers alone would not fully cover.
- **`triple_des_is_three_des`:** the fused TDEA path (no permutations between stages) matches three DES calls, for each
  keying option.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release des:: -- --ignored --nocapture --test-threads=1
cd bench/descmp && go test -v                        # Go's crypto/des, which has no assembly and so no purego run
```

Both sides encrypt (or decrypt) 32 MiB in place as independent 8-byte blocks, one call per block (ECB, no mode); best
of five passes after a warm-up. Both print the same first block as a cross-check.

Apple M1 Pro, MiB/s (medians of five interleaved runs):

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| DES encrypt | **110.3** | 96.6 |
| DES decrypt | **110.3** | 96.3 |
| TDEA encrypt | **36.6** | 33.8 |
| TDEA decrypt | **36.5** | 33.9 |

- Decryption is as fast as encryption. TDEA runs at a third of DES speed (48 rounds against 16).
- Fused TDEA (no permutations between stages) reaches 36.9 MiB/s, against 30.2 MiB/s for three separate DES calls (one
  run of three).
- Key setup: about 0.5 µs for DES and 1.7 µs for TDEA (one run of three).
- Rounds form one dependency chain, so a single block leaves the CPU mostly idle. An out-of-crate experiment running 2,
  3, 4 and 8 independent blocks side by side reached 181, 236, 278 and 332 MiB/s for DES (one run). That needs a
  multi-block API (`BlockCipher` has none) and a mode with independent blocks (ECB, CTR, CBC decryption).
- No x86 figures yet: nothing here can time real x86 hardware. The manual `Benchmarks` workflow
  (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## ECDH

Elliptic Curve Diffie-Hellman: two parties exchange public keys over an open channel and each derives the same shared
secret. It is neither a `Digest` nor a `BlockCipher`. Keys are generic over the curve, one of four types implementing
the sealed trait `Curve`, so mixing keys of two curves is a compile error. P-224 is only in [ECDSA](#ecdsa).

| Curve | Type | Private key | Public key | Shared secret | Defined in |
|-------|------|-------------|------------|---------------|------------|
| NIST P-256 | `P256` | 32 bytes | 65 bytes | 32 bytes | [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final), [SEC 1](https://www.secg.org/sec1-v2.pdf) |
| NIST P-384 | `P384` | 48 bytes | 97 bytes | 48 bytes | the same |
| NIST P-521 | `P521` | 66 bytes | 133 bytes | 66 bytes | the same |
| Curve25519 | `X25519` | 32 bytes | 32 bytes | 32 bytes | [RFC 7748](https://www.rfc-editor.org/info/rfc7748) |

- **NIST curves**: a public key is an uncompressed point, `0x04` and both coordinates (SEC 1, 2.3.3). The shared secret
  is the x-coordinate of the shared point (SEC 1, 3.3.1; NIST SP 800-56A Rev. 3, 5.7.1.2).
- **X25519**: any 32 bytes are a public key (RFC 7748).

### Usage

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

### Security

Security levels: 128, 192 and 256 bits for P-256, P-384 and P-521 (NIST SP 800-57); Curve25519 is "slightly under the
standard 128-bit level" (RFC 7748). A large quantum computer breaks all four; long-lived secrecy needs a post-quantum
scheme such as [ML-KEM](#ml-kem).

- **The shared secret is not a key.** Run it through a KDF such as [HKDF](#hkdf), with both public keys in the input
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

### Testing

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

### Benchmarking

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

## ECDSA

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

### Usage

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

### Security

None of the four curves is broken; the security levels in the table are NIST's (SP 800-57). A large quantum computer
would break all four (Shor's algorithm); signatures that must outlive one need a post-quantum scheme such as
[ML-DSA](#ml-dsa).

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

### Testing

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

### Benchmarking

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

## Ed25519

EdDSA on edwards25519 (the curve of X25519) with SHA-512, as in [RFC 8032](https://www.rfc-editor.org/info/rfc8032).
Used by SSH (RFC 8709), TLS 1.3 (RFC 8446), X.509 (RFC 8410) and DNSSEC (RFC 8080), and the default `ssh-keygen` key.
One curve, hash built in: nothing is generic, and neither `Digest` nor `BlockCipher` applies. Ed448 is not implemented.
Types: `SigningKey`, `VerifyingKey`, a 64-byte `Signature`, `Error`, `MAX_CONTEXT_LEN`.

| Scheme | Signs | Context | Seed | Public key | Signature | Methods |
|--------|-------|---------|------|------------|-----------|---------|
| [Ed25519](https://www.rfc-editor.org/rfc/rfc8032#section-5.1) | the message | none | 32 bytes | 32 bytes | 64 bytes | `sign`, `verify` |
| [Ed25519ctx](https://www.rfc-editor.org/rfc/rfc8032#section-5.1) | the message | 1 to 255 bytes | 32 bytes | 32 bytes | 64 bytes | `sign_ctx`, `verify_ctx` |
| [Ed25519ph](https://www.rfc-editor.org/rfc/rfc8032#section-5.1) | the SHA-512 digest of the message | 0 to 255 bytes | 32 bytes | 32 bytes | 64 bytes | `sign_prehashed`, `verify_prehashed` |

- The three schemes share keys, but a signature from one never verifies under another (`dom2` prefix, section 2).
- Use plain Ed25519: it is what other software means by the name. RFC 8032 says Ed25519ph SHOULD NOT be used (section
  8.5), because it relies on SHA-512 collision resistance and Ed25519 does not.
- The private key is a 32-byte seed. `to_keypair_bytes` / `from_keypair_bytes` use Go's 64-byte `ed25519.PrivateKey`
  format (seed, then public key); reading checks that the halves match.
- Signing is deterministic. Only `SigningKey::generate` needs randomness; like ECDH and ECDSA, it takes any
  `std::io::Read` (std has no stable secure RNG yet).

### Usage

```rust
use cryptors::{Digest, ed25519::{Error, Signature, SigningKey, VerifyingKey}, sha2::Sha512};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// RFC 8032, section 7.1, test 1.
let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap();
let key = SigningKey::from_seed(&seed);
assert_eq!(
    key.verifying_key().as_bytes()[..],
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
);
let signature = key.sign(b"");
assert_eq!(
    signature.to_bytes()[..],
    unhex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ))
);

// Parsing the public key is where a bad key is refused.
let public = VerifyingKey::try_from(&key.verifying_key().to_bytes()[..]).unwrap();
let received = Signature::try_from(&signature.to_bytes()[..]).unwrap();
assert_eq!(public.verify(b"", &received), Ok(()));
assert_eq!(public.verify(b"x", &received), Err(Error::InvalidSignature));

// The other two schemes; none accepts another's signatures.
let with_context = key.sign_ctx(b"message", b"my protocol, v1").unwrap();
assert_eq!(public.verify_ctx(b"message", b"my protocol, v1", &with_context), Ok(()));
assert_eq!(public.verify(b"message", &with_context), Err(Error::InvalidSignature));
let digest = Sha512::digest(b"message");
let prehashed = key.sign_prehashed(&digest, b"").unwrap();
assert_eq!(public.verify_prehashed(&digest, b"", &prehashed), Ok(()));

// The identity is a small-order point and is refused as a key.
let mut identity = [0u8; 32];
identity[0] = 1;
assert_eq!(VerifyingKey::from_bytes(&identity), Err(Error::InvalidPublicKey));
```

Generating a key with your own source of secure random bytes:

```rust
use cryptors::ed25519::SigningKey;
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do
let key = SigningKey::generate(&mut rng)?;
let signature = key.sign(b"a message");
// Send key.verifying_key().to_bytes(), the message and signature.to_bytes() to the other side.
```

`examples/ed25519.rs` checks RFC 8032's first example, then runs all three schemes on a fresh key, including a changed
message, a changed signature and a wrong context: `cargo run --release --example ed25519`.

### Security

128-bit security (RFC 8032, section 8.5), like P-256 and AES-128. Not broken classically, but a large quantum computer
would break it (Shor). For long-lived signatures, use a post-quantum scheme such as [ML-DSA](#ml-dsa) alongside or instead.

- **Randomness.** Only `generate` is random, and it is only as good as its reader. The per-message secret is a hash of
  key and message (section 8.2), so ECDSA-style nonce reuse cannot happen; the cost is no protection against fault
  attacks (Romailler and Pelissier, 2017).
- **Verification rules** (implementations differ). Together they make signatures unique: nobody can turn a valid
  signature into a second valid one of the same message and key.
  - S must be below ℓ (no malleability by adding ℓ, section 8.4).
  - R is compared byte for byte with the encoding of `[S]B - [k]A`, so a non-canonical R never matches.
  - The equation is cofactorless, `[S]B = R + [k]A`, which the RFC allows.
  - `VerifyingKey::from_bytes` accepts only canonical encodings (y below p, no sign bit when x = 0) of points not of
    small order. Small-order keys allow forgeries: under the identity, `R = [S]B` verifies for every message.
  - The R, S and equation rules match Go's `crypto/ed25519`. Go also accepts non-canonical and small-order keys, which
    no key generation produces, so Go accepts everything this crate accepts but not the reverse.
- **Contexts and prehashing.** A context should be a protocol constant, not derived from the message (section 8.3). An
  empty Ed25519ctx context is refused, as in OpenSSL. Ed25519ph takes a `[u8; 64]` SHA-512 digest, so another length
  does not compile.
- **Constant time, checked one way only.** No branch or memory address depends on the seed, secret scalar, prefix or
  per-message secret:
  - `[s]B` reads all eight entries of a table row and selects with masks.
  - The formulas are complete, and point encoding inverts with a fixed-exponent power.
  - Masks go through `core::hint::black_box` (a request, not a guarantee; about 2.5% of a signature).
  - We inspected the release assembly from `rustc` 1.95 for `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`.
    Key derivation and signing branch only on public loop counts, whether the B table is built, public lengths, an
    allocation, and the public-key comparison in `from_keypair_bytes`. Point arithmetic and encoding have no
    branches. SHA-512 depends only on input length (see [SHA-512](#sha-512)).
  - Not timed on real hardware; no protection against power analysis or fault injection.
  - Verifying handles no secret; its time depends on its inputs.
- **Zeroizing is best effort.** The seed, secret scalar, prefix and the crate's copies of them are zeroed on drop;
  `Debug` shows only the public key. Not wiped: arithmetic temporaries on stack and in registers, SHA-512's stack
  copies, and copies left behind by moving a key.

### Testing

```sh
cargo test -- ed25519 ec::fe25519   # RFC 8032, Go's vectors, 768 signatures from Go and OpenSSL, every verification rule, and the arithmetic against references
```

- **RFC 8032:** every example of the three schemes: section 7.1 (five, incl. the 1023-byte message and SHA(abc)), 7.2
  (four) and 7.3 (one).
- **Go's vectors:** the 128 lines of `crypto/ed25519/testdata/sign.input.gz`, stored decompressed and unchanged in
  `src/ed25519/testdata/sign.input`.
- **768 signatures from Go and OpenSSL:** 256 keys, messages of 0 to 255 bytes, all three schemes, context lengths 0 to
  255 (crossing SHA-512 block boundaries). The output hash comes from Go's `crypto/ed25519`; `bench/ed25519cmp`
  recomputes it. OpenSSL 3.6 matches all but the three empty-message signatures, which its CLI cannot make.
- **Every verification rule:** every bit of signature, key and message flipped; S + ℓ, ℓ and 2^256 - 1 as S; Go's
  malleated signature; the identity as R (canonical accepted, two non-canonical refused); all 40 non-canonical key
  encodings and the eight small-order points; a key with an order-8 component to pin the cofactorless equation. Go
  gives the same verdicts on the R and cofactor cases.
- **Go's edge cases (run once, outside the tests):** of the 768 cases of Filippo Valsorda's `ed25519vectors`, 656 get
  the same verdict as Go; the other 112 all have small-order keys, which this crate refuses and Go accepts.
- **Differential tests:** the field shared with X25519 (`src/ec/fe25519.rs`) against the generic Montgomery field
  (`src/ec/field.rs`) at maximal limb values, plus Ed25519-only parts (negation, square root, sign); scalar reduction
  and multiplication against a bit-at-a-time reference at Barrett edge values; verification's double multiplication
  against double-and-add at scalars like 0 and ℓ - 1.
- **Mutation testing:** 30 of 31 code mutations make a test fail; the survivor, zeroing the seed digest, is
  unobservable. Every test in `src/ed25519/` except the published vectors is the only one catching some mutation.
- **API behaviour:** longest context and one byte more, empty Ed25519ctx context, wrong slice lengths, mismatched key
  pair halves, `generate` with exactly 32 bytes and with a reader that runs out, `Debug` shows no secret, and a dropped
  key leaves nothing behind.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release ed25519 -- --ignored --nocapture --test-threads=1
cd bench/ed25519cmp && go test -v -run TestThroughput               # Go's crypto/ed25519 as shipped
cd bench/ed25519cmp && go test -tags purego -v -run TestThroughput  # Go with no assembly
```

What is timed, with the same seed and 128-byte message on both sides (key generation is not timed):

- **new signing key:** from its seed (SHA-512 plus a multiplication of B).
- **new verifying key:** decoding a point. Go has no decode-only call, so it times `VerifyWithOptions` with an empty
  signature; in Go 1.27.1 that decodes the key and stops at the length check (the test checks that it still does).
- **sign**, and **verify** with the key decoded each time, as `ed25519.Verify` does (cryptors also times it with the
  key decoded once).

Each runs ~50 ms to size a ~100 ms batch; the best of five is reported. All three runs print the same first 8 bytes of
public key and signature.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| new signing key | **9.76** | 16.03 | 16.22 |
| new verifying key | **2.82** | 3.50 | 3.49 |
| sign | **10.13** | 19.86 | 20.64 |
| verify | **31.12** | 41.55 | 41.85 |
| verify, key decoded once | 28.23 | — | — |

Spread was within ~5% except one `purego` verify run (62 µs). The machine was loaded (load average 4 to 7.5), so the
last digit means little.

- Go has no arm64 edwards25519 assembly, so `purego` only removes SHA-512 assembly here. On x86-64, Go's field
  multiplication and squaring are assembly, and `purego` is the like-for-like build.
- Signing and key building each cost one multiplication of B (~6.9 µs) plus one inversion (~2.5 µs). Verifying is
  ~253 shared doublings for `[S]B` and `[k]A` (~25 µs) plus one inversion. Decoding a key costs ~2.9 µs.

Not done yet: Bernstein-Yang inversion; caching the eight multiples of A in `VerifyingKey` (~0.6 µs per verification,
1.3 KiB per key, by operation count); a wider window for B; batch verification; incremental SHA-512 input to avoid
copying long messages; a BMI2/ADX x86-64 backend, as for [ECDH](#ecdh).

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings are meaningless. The manual
`Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## HKDF

HKDF ([RFC 5869](https://www.rfc-editor.org/info/rfc5869)) turns a secret that is not yet fit to be a key, such as an
[ECDH](#ecdh) shared secret, into as many keys as a protocol needs, each bound to its purpose. TLS 1.3, QUIC, HPKE and
Signal use it. `Hkdf<D>` is built on the crate's [HMAC](#hmac) and is generic over any `D: Digest`; it implements
neither `Digest` nor `BlockCipher`.

Two steps, Extract once per secret and Expand once per key (HashLen is the hash's output length):

- **Extract**: `PRK = HMAC(salt, IKM)`, HashLen bytes. The salt is optional and not secret; no salt means HashLen zero
  bytes, the same as an empty salt.
- **Expand**: `T(i) = HMAC(PRK, T(i - 1) | info | i)` from an empty `T(0)`, cut to the requested length. `info` names
  the output's purpose. `i` is one byte, so output is at most 255 blocks.

| Hash | `D` | HashLen | Block | Longest output (255 × HashLen) |
|------|-----|---------|-------|--------------------------------|
| MD5 | `Md5` | 16 bytes | 64 bytes | 4080 bytes |
| SHA-1 | `Sha1` | 20 bytes | 64 bytes | 5100 bytes |
| SHA-224 | `Sha224` | 28 bytes | 64 bytes | 7140 bytes |
| SHA-256 | `Sha256` | 32 bytes | 64 bytes | 8160 bytes |
| SHA-384 | `Sha384` | 48 bytes | 128 bytes | 12240 bytes |
| SHA-512 | `Sha512` | 64 bytes | 128 bytes | 16320 bytes |
| SHA-512/224 | `Sha512_224` | 28 bytes | 128 bytes | 7140 bytes |
| SHA-512/256 | `Sha512_256` | 32 bytes | 128 bytes | 8160 bytes |

No HKDF-SHA3: SHA-3 is not on `Digest` yet (see [SHA-3](#sha-3)).

### Usage

```rust
use cryptors::hkdf::{Error, Hkdf};
use cryptors::sha2::Sha256;

// RFC 5869, Appendix A.1.
let ikm = [0x0b; 22];
let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

// One call: Extract, then Expand into the buffer.
let mut okm = [0; 42];
Hkdf::<Sha256>::derive(&salt, &ikm, &info, &mut okm).unwrap();
assert_eq!(okm[..8], [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a]);

// Or extract once, then expand one key per purpose.
let hkdf = Hkdf::<Sha256>::extract(&salt, &ikm);
let mut client = [0; 16];
let mut server = [0; 16];
hkdf.expand(b"client write key", &mut client).unwrap();
hkdf.expand(b"server write key", &mut server).unwrap();
assert_ne!(client, server);

// An already uniformly random key of at least HashLen bytes can skip Extract.
let next = Hkdf::<Sha256>::from_prk(&okm[..32]).unwrap();
assert!(matches!(Hkdf::<Sha256>::from_prk(&okm[..31]), Err(Error::InvalidPrkLength)));

// More than 255 blocks is an error, not a panic; the buffer is left untouched.
let mut too_long = vec![0; Hkdf::<Sha256>::MAX_OUTPUT_LEN + 1];
assert_eq!(next.expand(b"", &mut too_long), Err(Error::InvalidLength));
```

`examples/hkdf.rs` checks the vector above, then derives one key per direction from an X25519 exchange, with both public
keys in `info`: `cargo run --release --example hkdf`.

### Security

HKDF is not broken: it relies on HMAC being a PRF and has its own analysis (Krawczyk, CRYPTO 2010). MD5 and SHA-1 are
for older protocols only; their collisions do not break HMAC, but do not pick them for new designs. Grover's algorithm at
most halves a key's security (128 of SHA-256's 256 bits).

- **Use a salt if you have one.** It is not secret and can be reused, but must not be attacker-chosen or depend on the
  IKM (section 3.4); HashLen random bytes is ideal. No salt is still sound, with weaker guarantees (section 3.1).
- **Extract secrets, expand keys.** Non-uniform secrets (Diffie-Hellman outputs above all) must go through `extract`.
  Skip it only for a key that is already uniformly random (section 3.3); `from_prk` rejects one shorter than HashLen
  (`Error::InvalidPrkLength`).
- **Bind each key with `info`.** Different `info` gives independent keys. After a key exchange, put both public keys in
  `info` (or the salt), per RFC 7748, section 6.1. `info` must not depend on the IKM (section 3.2).
- **Length does not separate keys.** With the same PRK and `info`, a shorter output is a prefix of a longer one. The
  maximum is 255 × HashLen bytes; more returns `Error::InvalidLength` and writes nothing. Empty output is allowed.
- **Not for passwords.** HKDF adds no work factor; use a password-based KDF such as [PBKDF2](#pbkdf2).
- **Zeroization is best effort.** The PRK (held as an HMAC key) and HMAC's padded-key copies are zeroed on drop, and
  `Debug` does not print them. Not wiped: the hash functions' stack values, the returned digests (including output
  blocks), copies left by moving an `Hkdf`, and the caller's output buffer.
- **Constant time, unverified.** Control flow and memory addresses depend only on input and output lengths, never on a
  secret. Unlike ECDH, the compiled code has not been inspected and no timing measurement backs this.

### Testing

```sh
cargo test hkdf::   # RFC 5869, and vectors from Go and OpenSSL for all eight hashes
```

- **RFC 5869 Appendix A**: all seven cases (SHA-256 and SHA-1), run through `extract`, `expand`, `derive` and `from_prk`.
- **Go `crypto/hkdf` and OpenSSL 3.6**, agreeing, for all eight hashes:
  - salts and `from_prk` keys around one block (HashLen, one block, one block + 1);
  - the 255-block limit: longest output, one byte over (refused, nothing written), and prefixes ending at the first and
    last block edges, down to empty;
  - 1000-byte IKM and `info` for SHA-256 and SHA-512.
- **API**: empty salt gives a PRK of HashLen zeros, `from_prk` length bounds, drop zeroes the whole `Hkdf`, `Debug`
  shows no secret.
- **Mutation check**: 11 deliberate breaks of `src/hkdf/kdf.rs` are each caught by at least one test.

HMAC is tested in its own module; see [HMAC](#hmac).

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release hkdf:: -- --ignored --nocapture --test-threads=1
cd bench/hkdfcmp && go test -v                  # Go's crypto/hkdf, on its crypto/sha256 and crypto/sha512 as shipped
```

Two workloads each for SHA-256 and SHA-512, same inputs on both sides:

- **Long Expand**: RFC 5869 A.1's PRK to the longest output (8160 or 16320 bytes), 4096 times per pass.
- **Short key**: Extract and Expand from a 32-byte secret to a 32-byte key, 200,000 times per pass, each key seeding the
  next.

One warm-up pass, then the best of five timed passes; both sides print the same check bytes. HKDF has no backend of
its own and uses its hash's (FEAT_SHA256 and FEAT_SHA512 here). `-tags purego` is not run; see [SHA-256](#sha-256) and
[SHA-512](#sha-512) for the hashes.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, higher is better:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| HKDF-SHA256, Expand to 8160 bytes | **356 MiB/s** | 247 MiB/s |
| HKDF-SHA256, Extract and Expand to a 32-byte key | **3.10 M/s** | 1.45 M/s |
| HKDF-SHA512, Expand to 16320 bytes | **274 MiB/s** | 221 MiB/s |
| HKDF-SHA512, Extract and Expand to a 32-byte key | **1.28 M/s** | 660 k/s |

Run-to-run spread was within 2%, but the machine was not idle (load average 3 to 5), so the last digit means little.

No x86 figures yet: Rosetta 2 timings say nothing about real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## HMAC

HMAC turns a hash into a message authentication code: a short tag, computed from a secret key and a message, that
proves the message came from a key holder and was not changed. TLS, IPsec, SSH, JWT (HS256), [HKDF](#hkdf) and the
HMAC_DRBG of [ECDSA](#ecdsa) use it. `Hmac<D>` works with any `D: Digest`, holds its key, and implements neither
`Digest` nor `BlockCipher`.

| HMAC with | `D` | Block | Tag | Shortest truncated tag | Hash defined in | Test vectors |
|-----------|-----|-------|-----|------------------------|-----------------|--------------|
| MD5 | `Md5` | 64 bytes | 16 bytes | 10 bytes | [RFC 1321](https://www.rfc-editor.org/info/rfc1321) | [RFC 2202](https://www.rfc-editor.org/info/rfc2202) |
| SHA-1 | `Sha1` | 64 bytes | 20 bytes | 10 bytes | [RFC 3174](https://www.rfc-editor.org/info/rfc3174) | [RFC 2202](https://www.rfc-editor.org/info/rfc2202) |
| SHA-224 | `Sha224` | 64 bytes | 28 bytes | 14 bytes | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | [RFC 4231](https://www.rfc-editor.org/info/rfc4231) |
| SHA-256 | `Sha256` | 64 bytes | 32 bytes | 16 bytes | the same | the same |
| SHA-384 | `Sha384` | 128 bytes | 48 bytes | 24 bytes | the same | the same |
| SHA-512 | `Sha512` | 128 bytes | 64 bytes | 32 bytes | the same | the same |
| SHA-512/224 | `Sha512_224` | 128 bytes | 28 bytes | 14 bytes | the same | none published; Go and OpenSSL, which agree |
| SHA-512/256 | `Sha512_256` | 128 bytes | 32 bytes | 16 bytes | the same | the same |

- Standard: [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final), which adopts
  [RFC 2104](https://www.rfc-editor.org/info/rfc2104): `HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))`.
- No HMAC-SHA3 yet: SHA-3 does not implement `Digest`.
- Keys may have any length, including zero; one longer than a block is hashed first.
- `Hmac::new` hashes both padded keys once and keeps the two states (FIPS 198-1, section 6); each tag then hashes only
  the message and the inner digest.
- `verify` takes only the full tag, `verify_truncated` its leftmost bytes down to the last column above; neither
  accepts an empty tag.

### Usage

```rust
use cryptors::{hmac::{self, Hmac, VerifyError}, sha2::{Sha256, Sha512}};

// RFC 4231, test case 2.
let mac = Hmac::<Sha256>::new(b"Jefe");
let tag: [u8; 32] = mac.mac(b"what do ya want for nothing?");
assert_eq!(tag[..4], [0x5b, 0xdc, 0xc1, 0x46]);

// Constant-time check; never compare tags with `==`.
assert_eq!(mac.verify(b"what do ya want for nothing?", &tag), Ok(()));
assert_eq!(
    mac.verify(b"what do ya want for everything?", &tag),
    Err(VerifyError::Mismatch)
);

// Truncated tags, e.g. IPsec's HMAC-SHA-256-128.
assert_eq!(mac.verify_truncated(b"what do ya want for nothing?", &tag[..16]), Ok(()));

// A message in pieces, never copied into one buffer.
assert_eq!(mac.mac_parts(&[b"what do ya ", b"want for nothing?"]), tag);

// One call, for one message under a key.
let tag: [u8; 64] = hmac::hmac::<Sha512>(b"Jefe", b"what do ya want for nothing?");
assert_eq!(tag[..4], [0x16, 0x4b, 0x7a, 0x7b]);
```

A real key is random bytes from your own source (the standard library has no stable secure one):

```rust
use cryptors::{hmac::Hmac, sha2::Sha256};
use std::{fs::File, io::Read};

let mut key = [0u8; 32];
File::open("/dev/urandom")?.read_exact(&mut key)?;      // on Unix; any io::Read of random bytes will do
let mac = Hmac::<Sha256>::new(&key);
```

`examples/hmac.rs` runs a sender and receiver over all eight hashes and shows a forged tag and a changed message being
refused: `cargo run --release --example hmac`.

### Security

HMAC is not broken with any of these hashes: it needs the compression function to act as a keyed random function, not
collision resistance, so the MD5 and SHA-1 collision attacks do not carry over. Avoid both in new designs anyway: RFC
6151 advises against HMAC-MD5, MD5 was never NIST-approved, and NIST retires SHA-1 by the end of 2030. Use HMAC-SHA-256
or a 64-bit SHA-2. Against a quantum computer (Grover), a 256-bit key keeps about 128 bits.

- **Compare tags with `verify`, never `==`.** `verify` checks every byte; `==` stops at the first difference, letting
  an attacker forge a tag byte by byte.
- **The protocol fixes the tag length.** `verify_truncated` accepts `Hmac::<D>::MIN_TAG_LEN` (half the output, rounded
  up, at least 10 bytes; RFC 2104 section 5) up to the full tag. That clears NIST's 32-bit floor (SP 800-107 Rev. 1,
  section 5.3.3) and covers HMAC-SHA-256-128 (IPsec, RFC 4868) and HMAC-SHA1-80 (SRTP). The length is not
  authenticated: enforce the protocol's, or a forger sends the shortest one accepted.
- **Use a random key at least as long as the tag, not a password.** HMAC is too fast for passwords; derive the key with
  a password hash such as [PBKDF2](#pbkdf2).
- **Timing depends only on lengths; checked in assembly, never timed on real hardware.** The hashes have no
  data-indexed tables or data branches, the pads are XORs, and the comparison ORs all byte differences and branches
  once on the result (through `core::hint::black_box`, a request, not a guarantee). In `rustc`'s `aarch64` and `x86_64`
  assembly, its only conditional jumps are the loop over the public tag length and the length check before it. No
  protection against power analysis or fault injection. Not hidden (none secret): the key, message and received-tag
  lengths, and whether a tag was refused for its length or its contents.
- **The key lives as long as the `Hmac`.** Both saved states (either lets a forger tag any message), the per-tag states
  and `new`'s padded-key block are zeroed on drop and hidden from `Debug`. Best effort only: the compression functions'
  working values (stack, registers), the digest of a key longer than a block, and copies left by moving an `Hmac` (into
  a `Box` or `Vec`, say) are not wiped, so build it where it will stay if that matters.

### Testing

```sh
cargo test -- hmac:: incremental::   # the RFC vectors, vectors from Go and OpenSSL, verification, and the hashes in pieces
```

- **Known answers:** RFC 4231's seven cases for HMAC-SHA-224/256/384/512 (with long keys and 128-bit truncation) and
  RFC 2202's seven for HMAC-MD5 and HMAC-SHA-1 (with 96-bit truncations), each through `hmac`, `Hmac::mac`, `mac_parts`
  and `verify`, on the streaming path and on the one-shot path used by hashes from outside the crate. ECDSA's RFC 6979
  tests exercise HMAC through HMAC_DRBG.
- **Go and OpenSSL vectors** for all eight hashes (the only source for SHA-512/224 and SHA-512/256), on which Go's
  `crypto/hmac` and OpenSSL 3.6 agree: RFC 4231 inputs, empty key and message, keys of block length -1, 0 and +1, and
  messages on both sides of the inner hash's padding boundary.
- **Hashes in pieces:** each hash's crate-internal incremental form matches the one-shot digest around every block and
  padding boundary up to two blocks (split at every byte, and byte by byte) and for a 100,000-byte message in uneven
  pieces; a copied state continues like the original.
- **Verification:** every tag bit flipped and every length from empty to one byte too long, on `verify` and
  `verify_truncated`; each hash's shortest truncated tag against the policy.
- **Multi-part messages:** split in two at every byte, in three at every pair, one byte per part, and none, on both paths.
- **Wiping:** dropping an `Hmac` or a hash state leaves zeros; `Debug` shows nothing of the key.

Each test was checked by breaking the code it guards in a scratch copy and seeing it fail.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release hmac:: -- --ignored --nocapture --test-threads=1
cd bench/hmaccmp && go test -v                       # Go's crypto/hmac, on Go's hashes as shipped
```

Per hash, same 32-byte key and bytes on both sides, best of five passes after a warm-up: one 64 MiB message and
1,000,000 messages of 64 bytes under one key, each next to the bare hash; then the same messages keyed afresh for each
(`hmac::hmac` here, `hmac.New` in Go), as HKDF does on every call. Both sides print the same tags; the Go side first
checks a known answer per hash.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs. MiB/s for the long message, millions of tags per second for
short ones; higher is better. "One-shot hash" is the earlier design, which copied the padded key and message into one
buffer and called `digest`; hashes from outside the crate still take that path.

| Workload | cryptors | Go stdlib | cryptors, one-shot hash | cryptors, hash alone | Go, hash alone |
|----------|----------|-----------|-------------------------|----------------------|----------------|
| HMAC-SHA-256, one 64 MiB message | **2341** | 2313 | 2100 | 2355 | 2324 |
| HMAC-SHA-512, one 64 MiB message | **1396** | 1377 | 1283 | 1397 | 1377 |
| HMAC-SHA-1, one 64 MiB message | 2202 | **2359** | 1986 | 2195 | 2365 |
| HMAC-MD5, one 64 MiB message | 619 | **637** | 607 | 623 | 637 |
| HMAC-SHA-256, 64-byte messages, keyed once | **9.99** | 7.47 | 7.47 | 20.6 | 12.1 |
| HMAC-SHA-512, 64-byte messages, keyed once | **4.51** | 3.70 | 2.57 | 13.9 | 6.99 |
| HMAC-SHA-1, 64-byte messages, keyed once | **10.22** | 7.46 | 7.04 | 18.7 | 12.7 |
| HMAC-MD5, 64-byte messages, keyed once | **3.38** | 3.01 | 2.05 | 5.22 | 4.69 |
| HMAC-SHA-256, 64-byte messages, keyed for each | **6.08** | 3.25 | 6.26 | | |
| HMAC-SHA-512, 64-byte messages, keyed for each | **2.50** | 1.45 | 2.49 | | |
| HMAC-SHA-1, 64-byte messages, keyed for each | **6.20** | 3.10 | 6.23 | | |
| HMAC-MD5, 64-byte messages, keyed for each | **1.98** | 1.56 | 1.97 | | |

Spread was within about 5% per cell (7% in a few Go cells, 19% for Go's bare SHA-256 on short messages) on a shared,
non-idle desktop, so 2-3% differences are noise. Adding the incremental form left each hash's one-shot speed within
0.4% of before.

- **Long message:** the message is hashed in place, so HMAC runs at hash speed. The one-shot hash lost 9% (SHA-256),
  8% (SHA-1), 6% (SHA-512) and 3% (MD5) to copying and wiping.
- **Short messages, keyed once:** from the two saved states, a 64-byte tag takes three compression calls (two with
  SHA-512's 128-byte block); the one-shot hash re-hashed both padded keys each time (five, or four), so it is
  1.34-1.76x slower.
- **Short messages, keyed for each:** both designs run five compression calls (four with SHA-512), so they are level.
  Building the two states costs at most 3% (SHA-256); `hmac::hmac` consumes its states rather than copying them.
- **Wiping:** one volatile store per byte took 36% of an HMAC-SHA-256 tag (6.53 vs 10.23 M tags/s, medians of three
  interleaved runs); `wipe_bytes`, 16 bytes per store, is within 1.5% of not wiping at all.

Possible speedups, none done:

- **Faster hashes:** faster SHA-1 or MD5 backends speed HMAC up directly.
- **A smaller state:** each holds a 144-byte block (the longest an outside `Digest` may have), though the crate's
  hashes need 64 or 128, and each tag copies and wipes two.
- **A stateless one-call form** for single-use keys, skipping the two states (the 3% in the SHA-256 keyed-for-each row).
- **Batched HMAC-MD5** with the up-to-16-lane `Md5::digest_many` on NEON.

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings say nothing about an x86 CPU. The
manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## HPKE

HPKE (Hybrid Public Key Encryption) encrypts messages to a public key with no prior exchange: a KEM gives both sides a
shared secret, a KDF turns it into AEAD keys, and the AEAD encrypts. TLS Encrypted Client Hello, MLS and Oblivious
HTTP build on it. A protocol rather than a primitive, it implements neither `Digest` nor `BlockCipher`. A `Suite` is a
`Kem`, a `Kdf` and an `Aead`; keys belong to one KEM; a context is a `Sender` or a `Recipient`.

| KEM | Type | Identifier | Private key | Public and encapsulated key | Shared secret | Built on |
|-----|------|------------|-------------|-----------------------------|---------------|----------|
| DHKEM(P-256, HKDF-SHA256) | `Kem::P256HkdfSha256` | `0x0010` | 32 bytes | 65 bytes | 32 bytes | `ecdh::P256` |
| DHKEM(P-384, HKDF-SHA384) | `Kem::P384HkdfSha384` | `0x0011` | 48 bytes | 97 bytes | 48 bytes | `ecdh::P384` |
| DHKEM(P-521, HKDF-SHA512) | `Kem::P521HkdfSha512` | `0x0012` | 66 bytes | 133 bytes | 64 bytes | `ecdh::P521` |
| DHKEM(X25519, HKDF-SHA256) | `Kem::X25519HkdfSha256` | `0x0020` | 32 bytes | 32 bytes | 32 bytes | `ecdh::X25519` |

| KDF or AEAD | Type | Identifier | Sizes | Built on |
|-------------|------|------------|-------|----------|
| HKDF-SHA256 | `Kdf::HkdfSha256` | `0x0001` | 32-byte hash and exporter secret | `hkdf` on `hmac` and `sha2` |
| HKDF-SHA384 | `Kdf::HkdfSha384` | `0x0002` | 48 bytes | the same |
| HKDF-SHA512 | `Kdf::HkdfSha512` | `0x0003` | 64 bytes | the same |
| AES-128-GCM | `Aead::Aes128Gcm` | `0x0001` | 16-byte key, 12-byte nonce, 16-byte tag | `aes`, with an AES-GCM private to the crate |
| AES-256-GCM | `Aead::Aes256Gcm` | `0x0002` | 32-byte key, 12-byte nonce, 16-byte tag | the same |
| Export-only | `Aead::ExportOnly` | `0xFFFF` | no encryption at all, exports only | |

Standards: [RFC 9180](https://www.rfc-editor.org/info/rfc9180) (HPKE), [RFC 5869](https://www.rfc-editor.org/info/rfc5869)
(HKDF), [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) (GCM). Curves are those of [ECDH](#ecdh); the KDF
is the crate's [HKDF](#hkdf) on its [HMAC](#hmac). AES-GCM is internal; the crate has no public modes of operation yet.

- **Suites and modes:** any KEM, KDF and AEAD, in all four modes: Base (sender anonymous), PSK (sender holds a
  pre-shared key), Auth (sender holds a known private key) and AuthPSK (both). Suites are negotiated by identifier, so
  the parts are values, not types: `Suite::from_ids` takes the identifiers, and a key of the wrong KEM is `KemMismatch`
  at run time.
- **Not implemented:** ChaCha20-Poly1305, X448, post-quantum and hybrid KEMs (the crate has [ML-KEM](#ml-kem), but not
  as an HPKE KEM).
- **Keys** are encoded as in ECDH (uncompressed NIST points, 32 bytes for X25519). Public keys and `enc` are validated
  when parsed into a `PublicKey`; the all-zero X25519 secret from a small-order point is refused.
- **Contexts** use a base nonce XORed with a 96-bit counter and stop after `2^96 - 1` messages. Both sides can export
  secrets of up to 255 hash lengths.
- **Randomness comes from the caller**, since the standard library has no stable secure RNG (see [Rand](#rand)).
  Key pairs come from `Kem::derive_key_pair` on random bytes; every sender setup derives its ephemeral key pair
  from `ikm_e` (RFC 9180, section 7.1.3), which also lets the RFC's vectors be checked through the sender's setup.

### Usage

```rust
use cryptors::hpke::{Aead, Kdf, Kem, PublicKey, RecipientMode, SenderMode, Suite};

fn main() -> Result<(), cryptors::hpke::Error> {
    // The recipient makes a key pair and publishes its public key.
    // In real use the input comes from a cryptographically secure random source.
    let suite = Suite::new(Kem::P256HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let sk_r = Kem::P256HkdfSha256.derive_key_pair(&[0x11; 32])?;
    let published = sk_r.public_key().as_bytes().to_vec();

    // The sender parses the key (invalid points are refused here) and seals two messages.
    let pk_r = PublicKey::from_bytes(Kem::P256HkdfSha256, &published)?;
    let (enc, mut sender) = suite.setup_sender(&pk_r, b"example v1", SenderMode::Base, &[0x22; 32])?;
    let first = sender.seal(b"message 1", b"attack at dawn")?;
    let second = sender.seal(b"message 2", b"bring coffee")?;

    // The recipient, from `enc` and the same `info`, opens them in order.
    let mut recipient = suite.setup_recipient(&enc, &sk_r, b"example v1", RecipientMode::Base)?;
    assert_eq!(recipient.open(b"message 1", &first)?, b"attack at dawn");
    assert_eq!(recipient.open(b"message 2", &second)?, b"bring coffee");
    assert_eq!(sender.export(b"reply key", 16)?, recipient.export(b"reply key", 16)?);

    // One message in PSK mode, with the single-shot functions and X25519.
    let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes256Gcm);
    let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&[0x33; 32])?;
    let (psk, psk_id) = (&[0x44; 32][..], &b"key 7"[..]);
    let (enc, ct) = suite.seal(sk_r.public_key(), b"", b"", b"hi", SenderMode::Psk { psk, psk_id }, &[0x55; 32])?;
    assert_eq!(suite.open(&enc, &sk_r, b"", b"", &ct, RecipientMode::Psk { psk, psk_id })?, b"hi");
    Ok(())
}
```

Real keys and setups need `Kem::private_key_len` random bytes (the private key size in the table above):

```rust
use cryptors::hpke::Kem;
use std::{fs::File, io::Read};

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any source of secure random bytes will do
let mut ikm = vec![0u8; Kem::P384HkdfSha384.private_key_len()];
rng.read_exact(&mut ikm)?;
let sk_r = Kem::P384HkdfSha384.derive_key_pair(&ikm)?;
// Read fresh bytes the same way for the `ikm_e` of every setup_sender.
```

`examples/hpke.rs` checks one RFC 9180 vector, then runs every KEM in every mode with keys from `/dev/urandom`:
`cargo run --release --example hpke`.

### Security

HPKE is not broken. RFC 9180 (section 9.1) cites proofs of confidentiality against active attackers, and of sender
authentication in the PSK, Auth and AuthPSK modes, given sound parts; none here has a known practical attack. None of
the KEMs resists a large quantum computer.

- **The randomness is the caller's.** `ikm_e` must be fresh, uniformly random, at least `Kem::private_key_len` bytes,
  and used once per sender setup: a repeated one reuses an AES-GCM key and nonce (breaking confidentiality and
  integrity), a guessable one lets anyone decrypt Base and PSK modes. The same goes for `derive_key_pair` input and
  PSKs, which need at least 32 bytes of entropy. A password is not enough: HKDF does not slow guessing, and
  non-key-committing AES-GCM makes it cheaper (RFC 9180, section 9.5). The crate refuses inputs and PSKs shorter than
  32 bytes or than a private key (the RFC only says "should not").
- **A context is a sequence; nonces must never repeat.** Each message is opened once, in order. A failed `open` keeps
  expecting the same message; a lost or reordered one makes the context useless. `Sender` and `Recipient` are not
  `Clone`; a context refuses its `2^96`th message.
- **Base mode authenticates nobody.** PSK modes prove the sender has the PSK, Auth modes a private key. A wrong key, PSK
  or sender shows as `Error::Open` on the first message, not at setup. Auth is open to key-compromise impersonation: the
  recipient's private key can forge messages from any sender (section 9.1.1); sign `(enc, ct)` where that matters.
- **No forward secrecy for the recipient:** a later leak of its private key (plus the PSK, in PSK modes) decrypts every
  past message. The sender side is forward secret.
- **No replay protection, no length hiding.** A message can be delivered to two contexts; a ciphertext is the plaintext
  length plus 16 bytes. `info`, associated data and exporter context bind only what they contain.
- **Constant-time by construction, less verified than ECDH.** No branch or address depends on a secret in HPKE, ECDH's
  arithmetic or GHASH. Hardware GHASH uses constant-time instructions; scalar GHASH uses masked integer multiplies (no
  key tables), relying on constant-time 64-bit multiplication, as on current aarch64 and x86-64 cores. Tags are
  compared in constant time. Known exceptions:
  - AES's scalar backend (CPUs without AES instructions) uses key- and data-dependent table lookups, see [AES](#aes).
  - `DeriveKeyPair` on a NIST curve takes longer when it rejects a candidate (about 2^-32 on P-256, far less elsewhere);
    this reveals nothing about the final key.
  - Only the aarch64 GHASH loop was inspected in compiled form; no timing measurement backs any of this.
- **Secrets are wiped on drop, best effort.** Private keys and context secrets (AES round keys, GHASH key and powers,
  base nonce, exporter secret, key-schedule intermediates) are zeroed on drop and hidden from `Debug`; a plaintext that
  fails its tag is zeroed before it is freed. Out of reach: stack and register copies, moved-from copies, and bytes
  returned to the caller.

### Testing

```sh
cargo test -- hpke:: gcm::   # RFC 9180's vectors, Go's, interop with Go both ways, the failures, and AES-GCM's backends
```

- **RFC 9180:** the 72 vectors of its test-vector file in this crate's scope, DHKEM(P-256), DHKEM(P-521) and
  DHKEM(X25519) in four modes each (the file has none for P-384 or HKDF-SHA384). They include Appendix A.1, A.3, A.4,
  A.6 and A.7, checked against the RFC text: encryptions at sequence numbers 0, 1, 2, 4, 255 and 256, exports, and KEM
  and key-schedule intermediates.
- **Go:** `crypto/hpke` vectors add 1000 random-length messages and 1000 exports (every length up to 999 bytes) per
  suite. Interop runs both ways over the 36 shared suites (four KEMs, three KDFs, three AEADs), P-384 and HKDF-SHA384
  included; `bench/hpkecmp` opens cryptors' output with Go. Go has Base mode only.
- **Failures:** in each mode, `open` fails after a change to any ciphertext byte, `enc`, associated data, `info`, PSK,
  PSK id, sender key, recipient key or mode, and when opening out of order or twice. Also covered: the `2^96 - 1` limit,
  PSK rules, small-order X25519 points, NIST keys off the curve / compressed / at infinity / wrong length (as public
  keys and as `enc`), invalid private keys, keys of another KEM, short inputs, the export limit, unknown identifiers,
  `Debug`.
- **Building blocks:** AES-GCM against its specification's test cases and Go values for 301 short and 9 long messages,
  on every GHASH backend, with every sealed byte flipped. Each hardware GHASH backend against scalar, around 16-block
  group boundaries and at every alignment. Scalar GHASH against SP 800-38D's bit-by-bit algorithm on dense operands.
  ECDH (with Wycheproof), HKDF and HMAC have their own tests.

The x86-64 GHASH backend passes under Rosetta 2 (PCLMULQDQ) but has not run on an x86 CPU:
`cargo test --target x86_64-apple-darwin -- hpke:: gcm::`.

Mutation check: of 43 deliberate breaks in a scratch copy, all but two failed a test: wiping a plaintext with a bad tag
(not observable) and an export-length check the KDF repeats. `seal` refusing a message over the AES-GCM limit is not
tested (it would take 64 GiB); the limit itself is.

### Benchmarking

```sh
# cryptors: HPKE, then the parts of its AES-GCM alone. One test thread, so the benchmarks don't compete with each other
# for the CPU.
cargo test --release -- hpke:: gcm:: --ignored --nocapture --test-threads=1
cd bench/hpkecmp && go test -v                       # Go's crypto/hpke as shipped, with its assembly
cd bench/hpkecmp && go test -tags purego -v          # Go's portable code, with no assembly
```

Method (both sides, Base mode, same keys, `info` and messages; best of five passes after a warm-up):

- **Setup:** `SetupBaseS` plus `SetupBaseR` with the KEM's own KDF and AES-128-GCM, repeated per pass 1000 times
  (X25519), 400 (P-256), 100 (P-384), 50 (P-521).
- **Seal/open:** 64 MiB as 1024 messages of 64 KiB through one context, DHKEM(X25519), HKDF-SHA256, each AEAD.
- **Cross-check:** Go's ephemeral keys come from `crypto/rand` (included in its setup time), so ciphertexts differ. Both
  sides print a recipient export for a fixed `enc` per KEM; all runs matched.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs. Setup in microseconds (lower is better), messages in MiB/s
(higher is better):

| Workload | cryptors | Go stdlib | Go portable (`purego`) |
|----------|----------|-----------|------------------------|
| Setup, DHKEM(X25519), HKDF-SHA256 | **97.8** | 114.7 | 127.7 |
| Setup, DHKEM(P-256), HKDF-SHA256 | 265.3 | **102.5** | 268.5 |
| Setup, DHKEM(P-384), HKDF-SHA384 | 900.5 | **782.4** | 797.3 |
| Setup, DHKEM(P-521), HKDF-SHA512 | 2301.5 | **2179.6** | 2193.0 |
| Seal, AES-128-GCM | **5613** | 5359 | 97 |
| Open, AES-128-GCM | 5738 | **6318** | 97 |
| Seal, AES-256-GCM | 4676 | **4798** | 87 |
| Open, AES-256-GCM | 4690 | **5320** | 88 |

Run-to-run spread: within 1.2%, except Go's AES-128-GCM seal (3%).

AES-GCM parts alone, same 64 KiB messages (cryptors only):

| Part | MiB/s |
|------|-------|
| GHASH, `aarch64` backend (PMULL) | 13165 |
| GHASH, `scalar` backend (`ctmul64`) | 562 |
| AES-128 in counter mode (FEAT_AES) | 12034 |
| AES-128-GCM seal, `aarch64` GHASH / `scalar` GHASH | 5586 / 530 |
| AES-128-GCM open, `aarch64` GHASH / `scalar` GHASH | 5753 / 537 |

Spread: 0.5% or less, except counter mode alone, where two of five runs came out 10% low.

- **Seal/open** processes each 1 KiB of a message once (copy, encrypt, hash) while it is in L1. Counter mode encrypts
  one block per AES call and GHASH reduces in general-purpose registers: two loops the CPU overlaps only as far as its
  reorder window allows.
- **Setup** is dominated by the KEM (three curve multiplications, eighteen HMAC tags and one AES key expansion per side)
  and follows [ECDH](#ecdh)'s numbers.

Not done yet, would make it faster:

- One loop running the AES rounds of a group of blocks side by side, then their GHASH.
- GHASH reduction in vector registers (PMULL by the GCM polynomial constant) instead of moving to general-purpose
  registers every 16 blocks.
- A multi-block AES entry point for counter mode. Where AES instructions are not in the target baseline (x86-64, Linux
  on aarch64), counter mode goes through the run-time dispatcher once per block, not inlined.
- For setup, the NIST-curve items listed under ECDH.

No x86 figures yet: Rosetta 2 timings say nothing about x86 CPUs. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners, using PCLMULQDQ and PMULL where
available; there AES is not in the target baseline, so the per-block dispatch above applies.

## MD5

MD5 ([RFC 1321](https://www.rfc-editor.org/info/rfc1321)) hashes an arbitrary-length message to a 128-bit (16-byte)
digest.

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

MD5 is broken. Collisions, including chosen-prefix collisions, take seconds on modern hardware and have been used to
forge CA certificates and signed code. It gives no integrity guarantee against an attacker: do not use it for
signatures, certificates, password hashing, or anything that needs collision resistance. It is acceptable only for
detecting accidental corruption, and even there SHA-256 is preferred.

### Testing

```sh
cargo test md5   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release md5 -- --ignored --nocapture --test-threads=1   # cryptors; names the backend selected on your machine
cd bench/md5cmp && go test -v                           # the Go stdlib counterpart
```

Apple M1 Pro:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| One 64 MiB message | **625 MiB/s** | — (no MD5 instruction exists) | 642 MiB/s |
| 1024 × 64 KiB messages | 625 MiB/s | **3022 MiB/s** (NEON, 16 lanes) | 641 MiB/s |

- The batch row hashes the same 64 MiB as the single-message row; the speedup comes only from filling the SIMD lanes.
- `crypto/md5` has no batch API, so its batch figure is 1024 sequential calls.
- The x86 (SSE2/AVX2) backends are differential-tested against scalar and match the aarch64 digests byte for byte, but
  have not been benchmarked on a real x86 CPU (Rosetta 2 timings are not meaningful).

## ML-DSA

ML-DSA, the Module-Lattice-Based Digital Signature Algorithm of [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
(CRYSTALS-Dilithium as NIST standardized it), is a post-quantum signature scheme: its lattice problems (module LWE and a
variant of module SIS) have no known quantum attack, while [ECDSA](#ecdsa) and [Ed25519](#ed25519) fall to Shor's
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

### Usage

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

### Security

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

### Testing

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

### Benchmarking

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

## ML-KEM

ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism of [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
(CRYSTALS-Kyber as NIST standardized it), is a post-quantum way to agree on a secret: a sender uses the receiver's
public key to make a random shared secret and a ciphertext holding it, and only the private key's holder can find the
secret in the ciphertext. Its lattice problem (module LWE) has no known quantum attack, while [ECDH](#ecdh) falls to
Shor's algorithm. That matters already, because a key exchange recorded today can be opened later; hybrid key exchanges
such as X25519MLKEM768 in TLS run ML-KEM next to X25519. Keys, ciphertexts and secrets are their own types (not `Digest`
or `BlockCipher`), generic over a parameter set: one of three types implementing the sealed trait `Parameters`.

Types: `DecapsulationKey<P>`, `EncapsulationKey<P>`, `Ciphertext<P>`, `SharedSecret<P>`, the parameter sets `MlKem512`,
`MlKem768` and `MlKem1024`, `Error`, `SEED_LEN`, `SHARED_SECRET_LEN`.

| Parameter set | Type | NIST category | Decapsulation key | Encapsulation key | Ciphertext | Shared secret |
|---------------|------|---------------|-------------------|-------------------|------------|---------------|
| ML-KEM-512 | `MlKem512` | 1 (key search on AES-128) | 64 bytes | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | `MlKem768` | 3 (key search on AES-192) | 64 bytes | 1,184 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | `MlKem1024` | 5 (key search on AES-256) | 64 bytes | 1,568 bytes | 1,568 bytes | 32 bytes |

- Keys, ciphertexts and secrets of different parameter sets do not compile together. Most protocols use ML-KEM-768.
- The decapsulation key is the 64-byte seed `d || z` of `ML-KEM.KeyGen` (`DecapsulationKey::from_seed`,
  `DecapsulationKey::seed`). FIPS 203's expanded decapsulation key (1,632 to 3,168 bytes) is not accepted: a seed is
  smaller and there is nothing to check in it.
- `EncapsulationKey::from_bytes` does the checks of FIPS 203 section 7.2: the length, and the "modulus check" that every
  coefficient is below `q = 3329`. `Ciphertext::from_bytes` checks the length, the only thing to check.
- **Decapsulation cannot fail.** A ciphertext not made for the key (made for another key, changed on the way, or random)
  still gives a secret, `J(z || c)`, which looks random and which the sender does not have ("implicit rejection"). The
  failure shows at the first use of the wrong secret.
- The standard library has no stable secure random source, so key generation and encapsulation take any `std::io::Read`,
  as in ECDH, ECDSA, Ed25519 and ML-DSA. A reader of fixed bytes gives the same key or secret every time, which is for
  tests. Encapsulation reads FIPS 203's 32-byte message `m` from it and nothing else; no function takes `m` as an
  argument, because FIPS 203 does not let an application choose it (section 6.2).

### Usage

```rust
use cryptors::mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey, Error, MlKem768};

// The receiver's key, from a seed of 64 bytes.
let seed: [u8; 64] = core::array::from_fn(|i| (i * 37 + 11) as u8);
let key = DecapsulationKey::<MlKem768>::from_seed(&seed);
assert_eq!(key.encapsulation_key().as_bytes()[..8], [0xa6, 0xd5, 0x10, 0xac, 0xe0, 0x7b, 0xbc, 0x1a]);

// The sender has the bytes of the encapsulation key (this is where a key of the wrong length, or with a coefficient
// that is not below q, is refused)...
let public = EncapsulationKey::<MlKem768>::from_bytes(key.encapsulation_key().as_bytes())?;

// ... and makes a secret and a ciphertext for it. A real program passes a source of secure random bytes; this is the
// 32 bytes of the message m, fixed, so that the answer is known.
let m: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
let (secret, ciphertext) = public.encapsulate(&mut &m[..])?;
assert_eq!(secret.as_bytes()[..8], [0xc9, 0x48, 0x02, 0xd6, 0xa8, 0x31, 0x78, 0xe9]);

// The receiver reads the ciphertext and finds the same secret.
let received = Ciphertext::<MlKem768>::from_bytes(ciphertext.as_bytes())?;
assert_eq!(key.decapsulate(&received), secret);

// A ciphertext that has been changed is not refused. It gives a secret that is not the sender's, and the same one
// every time.
let mut changed = ciphertext.as_bytes().to_vec();
changed[0] ^= 1;
let rejected = key.decapsulate(&Ciphertext::<MlKem768>::from_bytes(&changed)?);
assert_ne!(rejected, secret);

// A ciphertext of the wrong length is.
assert_eq!(Ciphertext::<MlKem768>::from_bytes(&changed[1..]), Err(Error::InvalidCiphertext));
```

Real keys come from `DecapsulationKey::generate`; the sender's encapsulation also needs random bytes from your own
source:

```rust
use cryptors::mlkem::{DecapsulationKey, EncapsulationKey, MlKem768};
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do

// The receiver: store key.seed(), and send the encapsulation key to the sender.
let key = DecapsulationKey::<MlKem768>::generate(&mut rng)?;
let to_send = key.encapsulation_key().as_bytes();

// The sender, which has those bytes: send the ciphertext, and keep the secret.
let public = EncapsulationKey::<MlKem768>::from_bytes(to_send)?;
let (secret, ciphertext) = public.encapsulate(&mut rng)?;
```

`examples/mlkem.rs` runs a complete exchange on each parameter set, with a changed ciphertext, bytes that are not a key
or a ciphertext, and a session key derived from the secret with [HKDF](#hkdf): `cargo run --release --example mlkem`.

### Security

The best known attacks are lattice reduction, classical or quantum, and the three parameter sets are chosen against them
(the categories are NIST's). FIPS 203 makes the scheme secure against an attacker who can have ciphertexts of their
choice decapsulated (IND-CCA2), with the Fujisaki-Okamoto transform: decapsulation encrypts the message it found again,
and compares.

- **Authenticates nobody.** Both sides get the same secret, but neither learns who the other is: a man in the middle is
  possible unless something binds the keys to identities (signatures such as [ML-DSA](#ml-dsa) or [Ed25519](#ed25519),
  certificates, a pre-shared secret). Prefer a fresh key pair for each exchange.
- **The secret is an input, not a protocol.** Its 32 bytes are uniform for anyone without the decapsulation key. Derive
  the protocol's keys from it with a key derivation function such as [HKDF](#hkdf), with the encapsulation key and the
  ciphertext in the input to bind them to this exchange.
- **Younger than the curves.** Lattice problems have been studied for less time than discrete logarithms, so many
  deployments pair ML-KEM with X25519 in a hybrid, where an attack on either alone is not enough. This crate has both,
  and no combiner for them.
- **Implicit rejection hides whether a ciphertext was good.** `decapsulate` takes the same steps for every ciphertext
  and picks the secret with a mask, so the time does not tell. A protocol must not reveal it another way, such as an
  error message that depends on the secret being right.
- **The randomness is the caller's.** `generate` and `encapsulate` are only as good as their reader. FIPS 203 asks for a
  generator at least as strong as the set: 128, 192 and 256 bits (section 3.3). A predictable reader makes a key or
  secret that can be guessed.
- **Keys are checked when read**, as described above. Every other string of the right length is a ciphertext, and every
  one with each coefficient below `q` is an encapsulation key.
- **Secret-independent arithmetic, checked one way only.** No branch or memory address derives from `s`, `d`, `z`, the
  message `m` or the noise. The transform, products, reductions, compression and noise sampling use only additions,
  multiplications, shifts and masks; the only tables, the roots of unity, are read in loop order. The ciphertext
  comparison ORs the differences of all bytes, and a mask picks the secret. The one sampler that depends on its bytes,
  `SampleNTT`, takes the public `rho`. In the assembly `rustc` 1.95 produced for `aarch64-apple-darwin` and
  `x86_64-apple-darwin`, the only conditional jumps in ML-KEM-768's key generation, encapsulation and decapsulation are
  fixed-count loops, comparisons with constant buffer sizes, checks of public lengths and of an allocation, and the
  loops that overwrite buffers. That is one compiler on two targets, not a proof; no timing was measured on real
  hardware, and nothing protects against power analysis or fault injection.
- **Keys stay in memory for as long as they exist.** The seed, the secret vector and every shared secret are zeroed when
  dropped; `Debug` shows no secret (an encapsulation key shows the first bytes of its hash). Not wiped: arithmetic
  temporaries in stack and registers, and copies left by moves. A decapsulation key keeps its expanded form (5, 9 and 14
  KiB of heap) so decapsulating does not expand it again; an encapsulation key holds 4, 7 and 12 KiB. Every operation
  uses at most 16 KiB of stack in a release build, 24 KiB in a debug build.

### Testing

```sh
cargo test -- mlkem:: sha3::xof   # known answers, vectors of NIST, Wycheproof and C2SP, and each part against its definition
cargo test --release mlkem::keypair::tests::accumulated_10000 -- --ignored   # 10,000 rounds for each set
MLKEM_VECTORS=/dir cargo test --release mlkem::conformance -- --ignored --nocapture   # every ACVP and Wycheproof vector
```

- **Accumulated known answers** of Go's `crypto/mlkem`: seeds, messages and bad ciphertexts from one SHAKE128, and a
  hash of all resulting keys, ciphertexts and secrets; 100 rounds per set are in the tests. Go and OpenSSL 3.6 agree on
  the ML-KEM-768 and ML-KEM-1024 values; OpenSSL makes the ML-KEM-512 one, which Go has no code for.
- **C2SP's accumulated vectors** (CCTV, `ML-KEM/README.md`): the same kind of stream, 10,000 rounds per set, with the
  expanded decapsulation key in the hash. They are for the FIPS 203 draft, whose key generation hashes `d` without the
  `k` the final standard adds, so the test makes keys that way. Everything after that hash is unchanged, so they cover
  sampling, the transform, compression, encoding, encapsulation and decapsulation for all three sets. All three hashes
  match (the test runs on demand).
- **NIST ACVP** (ACVP-Server `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`): all 240 were run once with no
  failure; 54 are in the tests. That is 75 key generation, 75 encapsulation, 30 decapsulation (good and modified
  ciphertexts) and 60 key checks (an encapsulation key with a coefficient too large, a decapsulation key with a modified
  hash).
- **Project Wycheproof:** all 1,725 ML-KEM cases, including random, bit-flipped, too long and too short ciphertexts;
  C2SP's `strcmp` vectors (a zero byte must not end the ciphertext comparison); malleable ciphertexts; seeds whose `rho`
  gives unusually large or many rejected matrix entries; encapsulation keys with an unreduced coefficient (100 of them)
  or the wrong length; and expanded decapsulation keys with a corrupted hash or encapsulation key. The 1,665 this API
  can express (60 have a seed of the wrong length, which `from_seed` refuses to compile) were run once with no failure;
  123 are in the tests.
- **C2SP's "unlucky" vectors:** draft seeds for which `SampleNTT` must read more than 575 bytes of SHAKE128 for one
  matrix entry, which a random seed needs once in 2^38.
- **OpenSSL 3.6.4** (once, outside the tests, all three sets, 100 rounds each): the same encapsulation key from the same
  seed, the same ciphertext and secret from the same message, and the same secret from a bad ciphertext.
- **Go:** `bench/mlkemcmp` reproduces with Go's `crypto/mlkem` the encapsulation key of Wycheproof's first
  key-generation case, and the key, ciphertext and secret of its benchmark inputs, which this crate's tests pin too
  (with OpenSSL's values for ML-KEM-512).
- **Each part against its definition:** the transform, its inverse and the `T_q` product against the specification's
  written-out algorithms and its appendix A tables (which the roots of unity computed at compile time must equal), and
  against polynomial multiplication by the definition `X^256 = -1`, at the extremes the bounds on intermediate values
  allow; Barrett's reduction for every 16-bit number; Montgomery's over its whole range; `Compress` and `Decompress`
  against the definitions with a true division for every number modulo `q`; the encodings against the specification's
  bit strings; the modulus check for every number from `q` to 4095; the two samplers against the written-out algorithms.
- **API behaviour:** a full exchange with the encapsulation key and ciphertext as bytes; readers giving exactly 32 and
  64 bytes, failing or running out; the implicit-rejection secret written out for a change to the first and last byte of
  `u`, of `v` and in the middle; every length around the right one for keys and ciphertexts; a coefficient equal to `q`
  in a key's last polynomial; `Debug` showing no secret; a dropped key and a dropped secret leaving nothing behind.
- **Mutation testing:** of 88 small changes (a constant, an operand, a sign, a dropped check, a flipped comparison, a
  dropped wipe) to the reductions, transform, product, encodings, samplers, key generation, encryption, decapsulation
  with its implicit rejection, and the API, each in a scratch copy, 86 fail a test and 2 survive. Both survivors
  overwrite a copy of the random bytes that is never read again (the seed in `generate`, the message in `encapsulate`),
  which cannot be observed. The first run had one more survivor, a gap: key generation without reducing `t` gives the
  same key bytes, so it passes every vector, but breaks the bound the product is sized for; a test now looks at it.
  Tests that only restated another's check were then removed: each remaining test reads a published vector, writes out
  the definition of a part, or is the only one to fail for some change.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release mlkem:: -- --ignored --nocapture --test-threads=1
cd bench/mlkemcmp && go test -v -run TestThroughput               # Go's crypto/mlkem as shipped, with its assembly Keccak
cd bench/mlkemcmp && go test -tags purego -v -run TestThroughput  # Go with a portable Keccak
```

Each run uses the same key, and times building a decapsulation key from its seed (expanding the matrix and the secret
vector, and the encapsulation key), building an encapsulation key from its bytes (the modulus check, its hash, and
expanding the matrix), encapsulating, and decapsulating a good ciphertext. Key generation is not timed. Both sides keep
the matrix in the key, so encapsulating and decapsulating do not expand it again. Encapsulation reads its 32 bytes from
a cheap generator here and from the system in Go, whose `Encapsulate` takes no reader. Each operation runs about 50 ms
to size a batch of about 100 ms, and the best of five batches is reported. Both sides print the first 8 bytes of the
shared secret of a fixed message, and all three runs print the same. Go has ML-KEM-768 and ML-KEM-1024 only.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| ML-KEM-512 new decapsulation key | 7.2 | — | — |
| ML-KEM-512 new encapsulation key | 3.9 | — | — |
| ML-KEM-512 encapsulate | 4.2 | — | — |
| ML-KEM-512 decapsulate | 6.2 | — | — |
| ML-KEM-768 new decapsulation key | **11.8** | 37.9 | 46.3 |
| ML-KEM-768 new encapsulation key | **7.7** | 10.6 | 17.4 |
| ML-KEM-768 encapsulate | **5.4** | 34.8 | 36.3 |
| ML-KEM-768 decapsulate | **8.2** | 50.6 | 54.1 |
| ML-KEM-1024 new decapsulation key | **18.6** | 57.9 | 71.8 |
| ML-KEM-1024 new encapsulation key | **13.2** | 18.3 | 29.8 |
| ML-KEM-1024 encapsulate | **7.0** | 53.6 | 55.5 |
| ML-KEM-1024 decapsulate | **10.6** | 79.5 | 83.7 |

Run-to-run spread was within 3% in every cell, on a desktop that was not idle (load average 3 to 5), so the last digit
means little.

- **Decapsulating takes 6.2 to 7.5 times less here than in Go, encapsulating 6.4 to 7.7 times, building a decapsulation
  key 3.1 to 3.2 times and building an encapsulation key 1.4 times.** Go's ML-KEM is also portable (only its Keccak is
  assembly), so this compares two implementations of one algorithm. Reading both, the difference is in how arithmetic
  and memory are handled (not measured separately). This one keeps coefficients in `i16` without reducing after each
  sum, multiplies with Montgomery's reduction, adds a row's products in 32 bits before one reduction, and keeps working
  vectors in stack arrays. Go reduces every sum with a conditional subtraction, and allocates slices and a SHAKE state
  for each polynomial it samples.
- **The matrix is most of the work of a key.** The "new encapsulation key" row (the matrix, a hash and the modulus
  check) is 65% (ML-KEM-768) and 71% (ML-KEM-1024) of the "new decapsulation key" row, which adds the noise, the
  transforms and the products. The matrix is `k * k` streams of about three SHAKE128 blocks each, on a Keccak both sides
  run on `FEAT_SHA3` here, which is why that gap is the smallest (1.4 times).
- **An encapsulation key is parsed, and its matrix expanded, once**: that is the "new encapsulation key" row.
  Encapsulating again to the same key repeats only the second row.

Possible speedups, not done: explicit NEON and AVX2 for transforms and products (the compiler uses NEON in places); the
two- and four-way Keccak of `sha3::shake128_many` for the matrix, which is many independent streams; batch
decapsulation.

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 translates the instructions, so its timings
say nothing about an x86 CPU. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on
GitHub's x86-64 and Arm runners.

## PBKDF2

PBKDF2 ([RFC 8018](https://www.rfc-editor.org/info/rfc8018), PKCS #5 v2.1) derives a key from a low-entropy password by
repeating a keyed hash as many times as the caller chooses, so each guess costs an attacker as much as it costs the
owner. FIPS 140, WPA2, LUKS1, 1Password and many file formats ask for it when a key comes from a password. It is one
function, [`derive`](#usage), built on the crate's [HMAC](#hmac) for any `D: Digest`; it implements neither `Digest` nor
`BlockCipher`.

For each block `i` of HashLen bytes of key (HashLen is the hash's output length), with `c` iterations:

- `U(1) = HMAC(password, salt | INT(i))`, where `INT(i)` is the block number as a 32-bit big-endian integer, from 1;
- `U(j) = HMAC(password, U(j - 1))`, for `j` from 2 to `c`;
- `T(i) = U(1) ^ U(2) ^ ... ^ U(c)`; the key is `T(1) | T(2) | ...`, cut to the length asked for.

The salt gives two users with the same password different keys. Each `U(j)` feeds the next, so the chain cannot run in
parallel; the blocks are independent.

| Hash | Call | HashLen | Block | Longest key ((2^32 − 1) × HashLen) |
|------|------|---------|-------|------------------------------------|
| MD5 | `derive::<Md5>` | 16 bytes | 64 bytes | 68,719,476,720 bytes |
| SHA-1 | `derive::<Sha1>` | 20 bytes | 64 bytes | 85,899,345,900 bytes |
| SHA-224 | `derive::<Sha224>` | 28 bytes | 64 bytes | 120,259,084,260 bytes |
| SHA-256 | `derive::<Sha256>` | 32 bytes | 64 bytes | 137,438,953,440 bytes |
| SHA-384 | `derive::<Sha384>` | 48 bytes | 128 bytes | 206,158,430,160 bytes |
| SHA-512 | `derive::<Sha512>` | 64 bytes | 128 bytes | 274,877,906,880 bytes |
| SHA-512/224 | `derive::<Sha512_224>` | 28 bytes | 128 bytes | 120,259,084,260 bytes |
| SHA-512/256 | `derive::<Sha512_256>` | 32 bytes | 128 bytes | 137,438,953,440 bytes |

No PBKDF2-HMAC-SHA3: SHA-3 is not on `Digest` yet (see [SHA-3](#sha-3)).

### Usage

```rust
use cryptors::{pbkdf2::{self, Error}, sha2::Sha256};

// RFC 7914, section 11: 1 iteration of HMAC-SHA-256, 64 bytes of key.
let mut key = [0; 64];
pbkdf2::derive::<Sha256>(b"passwd", b"salt", 1, &mut key).unwrap();
assert_eq!(key[..8], [0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f]);

// A password hash: a random salt, stored with the key and the count, and many iterations.
let salt = [0x42; 16]; // in a program: 16 random bytes, new for each password
let mut stored = [0; 32];
pbkdf2::derive::<Sha256>(b"correct horse", &salt, 600_000, &mut stored).unwrap();

// A shorter key is the start of a longer one, so ask for what you need.
let mut short = [0; 16];
pbkdf2::derive::<Sha256>(b"correct horse", &salt, 600_000, &mut short).unwrap();
assert_eq!(short, stored[..16]);

// No iterations and no key are errors, not panics; the buffer is left untouched.
assert_eq!(pbkdf2::derive::<Sha256>(b"correct horse", &salt, 0, &mut short), Err(Error::InvalidIterations));
assert_eq!(pbkdf2::derive::<Sha256>(b"correct horse", &salt, 1, &mut []), Err(Error::InvalidLength));
```

`derive(password, salt, iterations, &mut key)` takes a password and salt of any length (empty included), a `u32` count,
and the caller's key buffer of one byte to `2^32 - 1` blocks, so nothing is allocated.

`examples/pbkdf2.rs` checks RFC 7914's vector, then enrolls and checks a password as a login does (random salt, 600,000
iterations of HMAC-SHA-256): `cargo run --release --example pbkdf2`.

### Security

PBKDF2 is not broken: it relies on HMAC being a PRF. MD5 and SHA-1 are for older formats only; their collisions do not
break HMAC, but avoid them in new designs. PBKDF2's only defence is the work factor: it needs almost no memory, so it
runs at full speed on a GPU or an ASIC, unlike scrypt (RFC 7914) and Argon2 (RFC 9106). This crate has neither; prefer
them where you can. Where a standard asks for PBKDF2, use HMAC-SHA-256 or HMAC-SHA-512.

- **Use a random salt, new for each password.** It is not secret; store it with the key. RFC 8018 asks for at least 64
  bits (section 4.1), NIST SP 800-132 for at least 128; 16 random bytes are enough.
- **Use as many iterations as you can afford.** RFC 8018's minimum of 1,000 (section 4.2) is far too few today; OWASP's
  password storage guidance, at the time of writing, asks for 600,000 with HMAC-SHA-256 and 210,000 with HMAC-SHA-512.
  Store the count with the salt and raise it as hardware gets faster.
- **Ask for one block.** An attacker needs only the first block to test a guess; the owner pays for all of them. For
  more key material, derive HashLen bytes and expand them with [HKDF](#hkdf).
- **Long passwords are shortened.** HMAC hashes a key longer than the hash's block (64 bytes, or 128 for SHA-384 and
  SHA-512), so such a password gives the same key as its hash, and two passwords with the same hash share a key.
- **Compare keys without stopping at the first difference.** The crate has no public function for it;
  `examples/pbkdf2.rs` ORs all the differences.
- **Zeroization is best effort.** The password-keyed `Hmac` (worth as much as the password) is overwritten on return.
  Not wiped: the hash functions' stack values, the digests (each `U(j)`), and the caller's password and key buffers.

Control flow and addresses depend only on the lengths and the iteration count, never on a password byte. Unlike ECDH,
neither an inspection of the compiled code nor a timing measurement backs this.

### Testing

```sh
cargo test pbkdf2::   # RFC 6070 and 7914, Wycheproof, and vectors from Python, Go and OpenSSL for all eight hashes
```

- **RFC 6070** (HMAC-SHA-1, without its 16,777,216-iteration case) and **RFC 7914 section 11** (HMAC-SHA-256, with the
  80,000-iteration case).
- **Project Wycheproof**: 59 of its 298 PBKDF2 vectors for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (all those
  under 4096 iterations and one in five of the rest, to keep the debug-build test fast).
- **All eight hashes, 216 vectors** from Python's `hashlib`, reproduced by Go's `crypto/pbkdf2` and OpenSSL 3.6:
  passwords of 0, 1, HashLen, one block, one block + 1 and 2 blocks + 3 bytes; salts on both sides of the point where
  `salt | INT(i)` spills into a second block; keys of 1, HashLen − 1, HashLen, HashLen + 1, 2 × HashLen, 3 × HashLen + 5
  and 300 bytes; 1 to 1000 iterations; NUL bytes in the password and the salt.
- **The block number**: 65,538 blocks (2 MiB of SHA-256, 1.25 MiB of SHA-1) use three of the counter's four bytes, so
  a one-byte, 16-bit or little-endian counter fails, as does one that wraps at 8 or 16 bits.
- **The limits**: zero iterations and an empty key are refused with the buffer untouched; the `2^32 - 1`-block ceiling
  is checked on the numbers, since no test can allocate it.
- **Mutation check**: each of 21 deliberate breaks of `src/pbkdf2/kdf.rs` (a missing or extra iteration, the counter,
  the salt, the password, the XOR, the limits) is caught by at least one test.

HMAC is tested in its own module; see [HMAC](#hmac).

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release pbkdf2:: -- --ignored --nocapture --test-threads=1
cd bench/pbkdf2cmp && go test -v                # Go's crypto/pbkdf2, on its crypto/sha1, crypto/sha256 and crypto/sha512 as shipped
```

Two workloads each for SHA-1, SHA-256 and SHA-512, same inputs on both sides, each key the password of the next:

- **Password hash**: a key of one hash output, 100,000 iterations, 10 derivations per pass; millions of iterations/s.
- **One iteration**: keying HMAC plus two of its calls, 200,000 derivations per pass; operations per second.

One warm-up pass, best of five timed passes. Both sides print the same last key; the Go side checks known answers first.
PBKDF2 has no backend of its own and uses its hash's (FEAT_SHA1, FEAT_SHA256 and FEAT_SHA512 here), so `-tags purego`
is not run: see [SHA-256](#sha-256) and [SHA-512](#sha-512) for the hashes.

Apple M1 Pro, Go 1.27.1, medians of three interleaved runs, higher is better:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| PBKDF2-HMAC-SHA-1, 100,000 iterations | **13.07 M/s** | 8.88 M/s |
| PBKDF2-HMAC-SHA-256, 100,000 iterations | **12.66 M/s** | 8.93 M/s |
| PBKDF2-HMAC-SHA-512, 100,000 iterations | **4.38 M/s** | 3.64 M/s |
| PBKDF2-HMAC-SHA-1, one iteration | **5.46 M/s** | 2.00 M/s |
| PBKDF2-HMAC-SHA-256, one iteration | **5.80 M/s** | 2.07 M/s |
| PBKDF2-HMAC-SHA-512, one iteration | **2.35 M/s** | 978 k/s |

Run-to-run spread was within 3%, but the machine was not idle (load average 5), so the last digit means little.

- **Many iterations:** 1.2 to 1.5 times Go's rate. Both sides make two compression calls per iteration; cryptors starts
  each from the two states saved by `Hmac::new` and XORs into the caller's buffer (not profiled further).
- **One iteration:** 2.4 to 2.8 times. Setup dominates: keying HMAC and the first two calls, with no allocation here.

No x86 figures yet: Rosetta 2 timings say nothing about real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## Rand

Rand is the operating system's cryptographically secure random number generator, the source for every key, nonce, salt
and token. It adds nothing between the program and the system's generator, so it is exactly as strong as that. Each
call asks the system for the bytes it needs and nothing is kept between calls, so a forked child never shares state with
its parent and a restored virtual machine never repeats bytes it gave out. It is not a NIST SP 800-90A DRBG and has not
been validated under FIPS 140.

| Platform | Source |
|----------|--------|
| Linux, FreeBSD, DragonFly BSD | `getrandom(2)`; on a Linux older than 3.17, which has no such call, `/dev/urandom` |
| macOS, iOS, tvOS, watchOS, visionOS, OpenBSD | `arc4random_buf(3)` |
| Any other Unix (NetBSD, Android, illumos, Solaris, ...) | `/dev/urandom` |
| Windows and every other platform | none: every call fails with `ErrorKind::Unsupported` |

Four items, none generic: `Reader` (the generator as an `io::Read`), `fill(&mut buf)`, `text()` and
`below(&mut reader, max)`. The standard library has no stable interface to the system's generator (`std::random` is
unstable) and the crate has no dependencies, so the module declares the C library call itself. That is its only
`unsafe`: one call with a buffer's pointer and length.

### Usage

```rust
use cryptors::ecdh::{PrivateKey, X25519};
use cryptors::rand::{self, Reader};

// A 256-bit key, for AES-256 or HMAC. `fill` has no error to handle: if the system cannot give random bytes, nothing
// after it can be secure, and it panics.
let mut key = [0u8; 32];
rand::fill(&mut key);

// A token for a link or an API key: 26 characters of the RFC 4648 base32 alphabet (A-Z, 2-7), 130 bits.
let token = rand::text();
assert_eq!(token.len(), 26);

// `Reader` is what the keys of the crate take as their source of randomness. It returns an error rather than panic.
let alice = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
let bob = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
assert_eq!(
    alice.diffie_hellman(bob.public_key()).unwrap().as_bytes(),
    bob.diffie_hellman(alice.public_key()).unwrap().as_bytes()
);

// A uniform number in 0..max, with no bias: a die, the index of an item to draw. Any reader will do, so a test can give
// it fixed bytes: 0xff is masked to 7, which is not below 6, so it is drawn again, and 0x04 is.
assert!((1..=6).contains(&(rand::below(&mut Reader, 6).unwrap() + 1)));
assert_eq!(rand::below(&mut &[0xff, 0x04][..], 6).unwrap(), 4);
```

`below(rng, max)` reads the fewest bytes that hold `max - 1`, clears the first byte's bits above the highest one bit of
`max - 1`, and draws again if the result is not below `max`. A draw is refused with probability under a half, so fewer
than two draws are needed on average, and every number is equally likely. `value % max` is not uniform: a byte modulo 6
gives each of 0 to 3 in 43 cases of 256, and 4 and 5 in 42. `below` fails with `InvalidData` after 128 refused draws in
a row (a stuck reader), panics on a `max` of zero, and reads nothing for a `max` of 1.

With no public big integer in the crate, there is no random integer of any size and no random prime; `below` covers
numbers up to `2^64 - 1`. ([RSA](#rsa) draws its primes from a reader internally.)

`examples/rand.rs` fills a key, prints tokens, rolls a die 60,000 times and checks the faces, shuffles a deck with
`below`, and agrees on an X25519 secret between keys from `Reader`: `cargo run --release --example rand`.

### Security

- **Take every key, nonce and salt from here; never fall back to anything predictable.** The time, a process number,
  an address, or a hash of them can be guessed. If the system cannot answer, stop: `fill` and `text` panic; `Reader`
  and `below` return the error, for a program that must clean up first.
- **It fails only where the system does.** `getrandom` does not fail a valid request; with no flags it waits only while
  the kernel gathers its initial entropy, once, at boot. A sandbox that forbids the call (`EPERM`) is an error for the
  caller, not a reason to read a file; only `ENOSYS` (a Linux before 3.17) falls back to `/dev/urandom`.
- **A text is a secret, not a password a person types.** 130 bits suits a token, not something read aloud. A password
  chosen by a person goes through [PBKDF2](#pbkdf2), a key-agreement secret through [HKDF](#hkdf); neither is uniform.
- **Zeroization.** `text` and `below` overwrite the bytes they drew (secret until they become a character or a number)
  before returning; `fill` writes the caller's buffer, which the caller must wipe.

No secret random byte is a branch condition or a memory address, except that `below` redraws an out-of-range number.
The number of draws shows in the timing but says nothing about the result: a refused draw is thrown away, and the next
is independent of it. The system's generator, and its quality, are outside the crate.

### Testing

```sh
cargo test rand::   # the fill loop, the output's statistics, the text, `below` and its known answers, the /dev/urandom route
```

A generator meant to be unpredictable has no test vectors, so the tests check what can be checked:

- **The fill loop**: calls that return one byte at a time or are interrupted are retried for what is left; calls that
  return nothing, claim to have written too much, or fail give an error, not a loop or a panic.
- **Every length from empty to four megabytes** is filled to the last byte and not past it (guard bytes on both sides),
  and each page of a four-megabyte buffer is written.
- **The output**: a megabyte has every byte value about equally often (chi-square) and as many one bits as zero bits,
  within six standard deviations; a thousand 32-byte draws are all different, as are those of eight threads. A stuck,
  constant or short generator fails these.
- **`text`** maps each of the 256 byte values to the character of its low five bits in RFC 4648's table; 4000 tokens
  have 26 characters, all in the alphabet, each about equally often.
- **`below`** matches another implementation of the algorithm on 22 inputs (bounds from 1 to `2^64 - 1`, refused
  draws, bytes left unread), reading the same bytes. It is uniform for a bound a modulo would bias, and fails with the
  reader's error, with `UnexpectedEof`, and after exactly 128 refused draws.
- **`/dev/urandom`** is tested on every Unix, whichever route the machine takes. On Linux the fallback was run under a
  seccomp filter making `getrandom` fail with `ENOSYS`; with `EPERM` instead, the tests fail, as they should.
- **Mutation check**: each of 19 deliberate breaks of `src/rand/` (the mask, the comparison, the length, the character
  mapping, the number of draws, the short-write loop, the retry, the fallback) is caught by at least one test, except
  one that changes nothing observable (a byte of a buffer overwritten before it is read).

The tests run on the project's Linux machines (x86-64, Arm, and RISC-V under emulation) and on macOS. The FreeBSD,
DragonFly BSD and OpenBSD calls are written from their manuals and have not been run; Windows is not supported.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rand:: -- --ignored --nocapture --test-threads=1
cd bench/randcmp && go test -v                  # Go's crypto/rand.Read
```

Five buffer sizes, filled in place, the same on both sides: 16, 32 and 256 bytes (200,000 calls per pass, per-call cost
in operations per second), 4 KiB (20,000 calls) and 1 MiB (100 calls) (per-byte cost in MiB/s). One warm-up pass, best
of five timed passes. Random output cannot be compared, so the Go side checks that the buffers are filled and look
random, and replays the Rust tests' `below` table against `rand.Int`.

Apple M1 Pro, Go 1.27.1, medians of three interleaved runs, higher is better. Both sides call `arc4random_buf` on macOS:

| Buffer | cryptors | Go stdlib |
|--------|----------|-----------|
| 16 bytes | **4.44 M/s** | 3.79 M/s |
| 32 bytes | **4.34 M/s** | 3.71 M/s |
| 256 bytes | **3.70 M/s** (904 MiB/s) | 3.23 M/s (790 MiB/s) |
| 4 KiB | **3,099 MiB/s** | 3,041 MiB/s |
| 1 MiB | 3,041 MiB/s | 3,046 MiB/s |

Run-to-run spread was within 4%, with the machine not idle (load average 5).

- **Small buffers:** 1.15 to 1.17 times Go's rate. The system call is the same; only the code around it differs, and
  nothing was profiled.
- **Large buffers:** 1.02 times at 4 KiB and no gain at 1 MiB: the time is the generator's.

On Linux both sides call `getrandom(2)`, so the figures there are the kernel's; no x86 or Linux figures have been
measured. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm
runners.

## RC4

RC4 (also ARC4 or ARCFOUR) is the stream cipher Ron Rivest designed in 1987, as described in Bruce Schneier's *Applied
Cryptography*. The key sets up the state, and each step makes one keystream byte, XORed with the message: encrypting and
decrypting are the same operation.

**RC4 is broken.** Use it only to read existing data or talk to legacy systems. For anything new, use [AES](#aes).

| Cipher | Type | Key | State | Output |
|--------|------|-----|-------|--------|
| RC4 | `Rc4` | 1 to 256 bytes | 256 bytes | one byte per step |

### Usage

```rust
use cryptors::rc4::Rc4;

// Wikipedia's example: the key "Wiki" and the text "pedia".
let mut cipher = Rc4::new(b"Wiki").unwrap();
let mut data = *b"pedia";
cipher.apply_keystream(&mut data);
assert_eq!(data, [0x10, 0x21, 0xbf, 0x04, 0x20]);

// Decrypting is the same operation, with a fresh cipher: the keystream starts again.
Rc4::new(b"Wiki").unwrap().apply_keystream(&mut data);
assert_eq!(&data, b"pedia");

// The keystream goes on from one call to the next, so a message can be processed in pieces of any size.
let mut cipher = Rc4::new(b"Wiki").unwrap();
let mut message = *b"pedia";
let (head, tail) = message.split_at_mut(2);
cipher.apply_keystream(head);
cipher.apply_keystream(tail);
assert_eq!(message, [0x10, 0x21, 0xbf, 0x04, 0x20]);

// RFC 4345 (arcfour256) throws away the first 1536 bytes of the keystream.
let mut cipher = Rc4::new(b"Wiki").unwrap();
cipher.apply_keystream(&mut [0; 1536]);

// `xor_keystream` leaves the plaintext as it was and writes to another buffer.
let mut ciphertext = [0; 5];
cipher.xor_keystream(&mut ciphertext, b"pedia");

// A key of the wrong size is refused.
assert!(Rc4::new(&[]).is_err());
assert!(Rc4::new(&[0; 257]).is_err());
```

### Security

- **The keystream is biased.** The second byte is zero twice as often as it should be (Mantin and Shamir, 2001), and
  more biases follow. A plaintext sent again and again under many keys (a cookie, a password) can be counted out of the
  ciphertexts: AlFardan et al. (2013) and Vanhoef and Piessens (2015) did it to TLS and WPA-TKIP, and RFC 7465 (2015)
  forbids RC4 in TLS.
- **Related keys give related keystreams.** Fluhrer, Mantin and Shamir (2001) broke WEP, whose key was a counter
  followed by the same secret.
- **Discarding the start helps a little.** RFC 4345 throws away the first 1536 bytes, as the example does; other biases
  stay.

Using it:

- **There is no nonce.** One key is one keystream, so two messages under it reveal the XOR of the plaintexts: use a key
  once. Nothing is authenticated either: a flipped ciphertext bit flips the same plaintext bit. `examples/rc4.rs` shows
  both.
- **Not constant-time.** The key schedule and the generator index a 256-byte table by secret state, which cache timing
  can leak. RC4 allows nothing else.
- **The state is wiped on drop, best effort**, and hidden from `Debug`. Stack copies and copies left by moves are out of
  reach; build the cipher where it will stay.
- **`Rc4` is not `Clone`**: a copy would repeat the keystream.

### Testing

```sh
cargo test rc4::   # RFC 6229, the vectors of the 1994 posting, every length of key, a message in pieces
```

- **`rfc_6229`:** all 252 vectors of the RFC (14 keys of 40 to 256 bits, 16 keystream bytes at each of 18 offsets up to
  4096), read from `src/rc4/testdata/rfc6229.txt`; Go's `crypto/rc4` agrees with every line.
- **`known_answers`:** the vectors of the 1994 posting that first published the algorithm (also in Go's tests), and
  Wikipedia's three examples.
- **`every_key_length`:** the SHA-256 of 300 keystream bytes for each key length from 1 to 256, agreed by Go and a
  Python implementation; the only test of the lengths between the RFC's.
- **`pieces_match_the_whole`:** a message split at every point and into runs of many lengths, so the indices must carry
  over between calls.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rc4:: -- --ignored --nocapture --test-threads=1
cd bench/rc4cmp && go test -v                        # Go's crypto/rc4, which has no assembly and so no purego run
```

Both sides XOR 32 MiB in place in one call, with a 16-byte key `00 01 02 ...` and the keystream running on between
passes. Best of five passes after a warm-up. Both print the same first bytes, which OpenSSL also computes.

Apple M1 Pro, medians of five interleaved runs, in MiB/s:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| RC4 | **1112.1** | 1011.3 |

Each step depends on the one before, so the chain of loads and stores sets the speed. Go keeps the state in 32-bit
words; here it is bytes.

No x86 figures yet: nothing here can time real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## RSA

RSA encrypts a message to the holder of a private key, and lets the holder sign a message that anyone with the public key
can check. Its public keys are in almost every X.509 certificate, its signatures are TLS 1.2's and the JWT algorithms
`RS256` and `PS256`, and its encryption wraps the keys of CMS, S/MIME and JWE. [RFC 8017](https://www.rfc-editor.org/info/rfc8017)
(PKCS #1 v2.2) turns its one operation, a power modulo the product of two primes, into four schemes:

| Scheme | For | With the public key | With the private key | Defined in |
|--------|-----|---------------------|----------------------|------------|
| RSAES-OAEP | encryption | `encrypt_oaep`, `encrypt_oaep_mgf1` | `decrypt_oaep`, `decrypt_oaep_mgf1` | section 7.1 |
| RSASSA-PSS | signatures | `verify_pss`, `verify_pss_prehash` | `sign_pss`, `sign_pss_prehash` | section 8.1 |
| RSAES-PKCS1-v1_5 | encryption, for old protocols | `encrypt_pkcs1v15` | `decrypt_pkcs1v15`, `decrypt_pkcs1v15_session_key` | section 7.2 |
| RSASSA-PKCS1-v1_5 | signatures, as most certificates have them | `verify_pkcs1v15`, `verify_pkcs1v15_prehash` | `sign_pkcs1v15`, `sign_pkcs1v15_prehash` | section 8.2 |

- It is neither a `Digest` nor a `BlockCipher`. There are two types, `PublicKey` and `PrivateKey`, with a method for each
  scheme, and no type parameter but the hash: any `Digest` for OAEP and PSS, one of the eight of the sealed trait
  `Pkcs1Hash` (MD5, SHA-1 and the six SHA-2 functions) for a PKCS #1 v1.5 signature, which carries the hash's name.
- A key has two primes and a modulus of 1,024 to 16,384 bits, and an odd public exponent from 3 to 2^31 - 1 (65,537 for
  the keys it generates). The sizes and what they hold:

| Modulus | Security (NIST SP 800-57) | Ciphertext and signature | OAEP with SHA-256 holds | PKCS #1 v1.5 holds |
|---------|---------------------------|--------------------------|-------------------------|--------------------|
| 1,024 bits | 80 bits: old data only | 128 bytes | 62 bytes | 117 bytes |
| 2,048 bits | 112 bits | 256 bytes | 190 bytes | 245 bytes |
| 3,072 bits | 128 bits | 384 bytes | 318 bytes | 373 bytes |
| 4,096 bits | about 140 bits | 512 bytes | 446 bytes | 501 bytes |
| 7,680 bits | 192 bits | 960 bytes | 894 bytes | 949 bytes |
| 15,360 bits | 256 bits | 1,920 bytes | 1,854 bytes | 1,909 bytes |

RSA carries a key, not a document: it encrypts a few hundred bytes at most, so a message goes under a symmetric key that
RSA delivers, and a document is signed by signing its hash.

Standards:

- Schemes: RFC 8017 sections 7 and 8, with the encodings of section 9 (`EMSA-PSS`, `EMSA-PKCS1-v1_5`) and MGF1 (appendix
  B.2.1). The private operation uses the second representation of a private key (section 3.2), with the Chinese
  remainder theorem.
- Key generation: [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) appendix A.1, drawn from a reader as
  [c2sp.org/det-keygen](https://c2sp.org/det-keygen) specifies, so a deterministic reader gives the same key as any other
  implementation of it.
- Keys are numbers: big-endian bytes for the modulus, the exponent and the private key's components. The encodings that
  carry them (PKCS #1's `RSAPrivateKey`, PKCS #8, SubjectPublicKeyInfo) are ASN.1, which the crate has no parser for yet
  (X.509 is planned).
- Left out: keys of more than two primes, PSS with a hash for MGF1 other than the message's (OAEP has it), and PKCS #1 v1.5
  signatures with SHA-3 (not a `Digest` yet; the `_prehash` forms need a name that `Pkcs1Hash` does not have).

### Usage

```rust
use cryptors::rsa::{Error, PrivateKey, PublicKey, SaltLength};
use cryptors::sha1::Sha1;
use cryptors::sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// The first key of RSA Laboratories' PKCS #1 test vectors, 1,024 bits: the modulus, the private exponent and the primes.
let key = PrivateKey::from_components(
    &unhex(concat!(
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742",
        "c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d424",
        "7616d4f5ba10d4cfd226de88d39f16fb"
    )),
    65537,
    &unhex(concat!(
        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d181",
        "2b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31de",
        "f37d0cf539e9cfcdd3de653729ead5d1"
    )),
    &unhex("d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d"),
    &unhex("cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77"),
).unwrap();

// The sender has only the public key's numbers, and encrypts with OAEP. The "random" seed here is the vector's own, so
// that the ciphertext is the vector's too.
let public = PublicKey::new(&key.public_key().modulus(), key.public_key().exponent()).unwrap();
let message = unhex("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34");
let mut seed: &[u8] = &unhex("18b776ea21069d69776a33e96bad48e1dda0a5ef");
let ciphertext = public.encrypt_oaep::<Sha1, _>(&mut seed, &message, b"").unwrap();
assert_eq!(ciphertext[..16], unhex("354fe67b4a126d5d35fe36c777791a3f")[..]);

// The holder decrypts with the same hash and label; anything else is the same error.
assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b""), Ok(message));
assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b"other"), Err(Error::Decryption));

// PSS is randomized (here with a fixed string for the random bytes); PKCS #1 v1.5 is deterministic.
let mut noise: &[u8] = &[7; 32];
let signature = key.sign_pss::<Sha256, _>(&mut noise, b"a message", SaltLength::EqualsHash).unwrap();
assert_eq!(public.verify_pss::<Sha256>(b"a message", &signature, SaltLength::EqualsHash), Ok(()));
assert_eq!(public.verify_pss::<Sha256>(b"another", &signature, SaltLength::EqualsHash), Err(Error::VerificationFailed));
let signature = key.sign_pkcs1v15::<Sha256>(b"a message").unwrap();
assert_eq!(public.verify_pkcs1v15::<Sha256>(b"a message", &signature), Ok(()));
```

Real keys come from `PrivateKey::generate`. The randomness is a reader, as everywhere else in the crate:

```rust
use cryptors::rand::Reader;
use cryptors::rsa::PrivateKey;
use cryptors::sha2::Sha256;

let mut rng = Reader;                                       // the operating system's; any io::Read of random bytes will do
let key = PrivateKey::generate(&mut rng, 2048)?;
let ciphertext = key.public_key().encrypt_oaep::<Sha256, _>(&mut rng, b"a 32-byte session key goes here", b"")?;
assert_eq!(key.decrypt_oaep::<Sha256>(&ciphertext, b"").unwrap(), b"a 32-byte session key goes here");
```

`examples/rsa.rs` checks a known answer, generates a key, sends a secret with OAEP to the holder of its public numbers and
authenticates a message with it, signs with PSS and PKCS #1 v1.5, stores and restores a key, and shows each failure:

```sh
cargo run --release --example rsa
```

### Security

RSA does not resist a large quantum computer (Shor's algorithm factors the modulus); what must stay secret past one needs a
post-quantum scheme such as [ML-KEM](#ml-kem) or [ML-DSA](#ml-dsa).

- **Use OAEP and PSS in a new design.** PKCS #1 v1.5 encryption has no integrity check in its padding, and a service that
  says whether a ciphertext decrypts hands out the decryption of any ciphertext (Bleichenbacher, 1998, and the same attack
  on implementations again and again since, for TLS and for XML encryption). It is here to read old data.
  `decrypt_pkcs1v15_session_key` is the protection of RFC 3218 for the protocols that cannot move: it replaces a key you
  already hold, or leaves it, and does not say which.
- **One error for every failed decryption.** `Error::Decryption` does not say whether the ciphertext was short, large,
  had another label or a broken padding, and the checks of the padding take the same time whichever fails. A program
  that tells its peer more, by a message or by a delay, rebuilds the oracle of Manger's attack on OAEP.
- **A PKCS #1 v1.5 signature is rebuilt, not parsed.** The block is made again from the digest and compared, which is
  what keeps out the forgeries of the verifiers that read the `DigestInfo` leniently (Bleichenbacher, 2006; Mozilla's NSS,
  2014). A signature whose number is not below the modulus, or is not as long as it, is refused.
- **The randomness is the caller's.** A key from a predictable reader is guessable, and an OAEP ciphertext or a PSS
  signature made from one is not randomized. `rand::Reader` is the operating system's.
- **Sizes.** Keys under 1,024 bits are refused and 2,048 bits is the floor of NIST's guidance; the cap of 16,384 is so
  that a key from outside cannot make a verification take minutes. A key is for one purpose (FIPS 186-5, SP 800-56B):
  the types do not stop a program from signing and decrypting with one, and it should not.
- **Pick the hash on purpose.** SHA-256 and up. The hash of a v1.5 signature includes MD5 and SHA-1 for the signatures
  that still use them, and is only as strong as they are. For OAEP with another hash for MGF1 than for the label (some
  protocols fix it to SHA-1) there is `encrypt_oaep_mgf1`; use `encrypt_oaep` if you have the choice.
- **A fault does not give the key away.** The result of a private operation is raised to the public exponent and compared
  with its input before it is released, so a bit flipped in one of the two exponentiations of the Chinese remainder
  theorem (which would make a signature that reveals a prime, Boneh, DeMillo and Lipton, 1997) fails instead. There is no
  blinding: the operation takes the same time for every input, so there is nothing to hide.
- **Constant-time where it matters, checked by inspection and a coarse test.** Nothing that depends on a private key is
  used as a branch condition or a memory address in the private operation or the padding checks of a decryption: the
  exponentiation reads every entry of its table, and every choice between two numbers is a selection by a mask.
  `rustc`'s assembly for aarch64 and x86_64 was inspected for the product, the table lookup of the exponentiation and the
  search for the message in a decrypted block, and its conditional jumps there are loops over public lengths and checks of
  public lengths; the masks go through `black_box`, and the selections are conditional moves and bit operations. A coarse test in the manner of dudect (`timing_does_not_depend_on_the_input`, run by hand on a quiet machine) compared 6,000 private
  operations on inputs with little in them with 6,000 on random ones: the means differed by under 0.05% and Welch's t stayed
  under 2.4 in three runs (dudect's threshold is 4.5). That is one
  compiler's output for two targets, and a measurement on one machine; nothing protects against power analysis or fault
  injection that skips the check. Key generation is not constant-time (it is a search: refused candidates, trial division
  and Miller-Rabin rounds are visible, never the key it ends with), and neither is verification, which has no secret.
- **Key wiping is best effort.** A private key's numbers, and the temporaries of the operations and of key generation, are
  overwritten with zeros when they are dropped (checked by an allocator that looks for them in freed memory). Values on
  the stack and in registers are not wiped, nor are copies left by moves; the bytes returned by `d()`, `p()` and the like
  are the caller's.

### Testing

```sh
cargo test rsa::    # known answers, Wycheproof, the arithmetic against Python's integers, and key generation against other implementations
```

| Source | Coverage |
|--------|----------|
| Project Wycheproof | 75 files of OAEP and PKCS #1 v1.5 decryption, PKCS #1 v1.5 signatures (verification and generation) and PSS verification: 8,043 cases that this module can read, all passed once; 759 kept in the tests (every kind of fault in every file that matters) |
| RSA Laboratories' PKCS #1 vectors | OAEP examples: the ciphertext of each message from the vector's own seed, bit for bit. PSS: 60 signatures by keys of 1,024 to 1,031 bits, 1,536 and 2,048, verified and reproduced from their salts; the keys of 1,025 to 1,031 bits are the ones whose encoded message is a byte shorter than the modulus or has bits to clear |
| OpenSSL | 315 ciphertexts and signatures (OAEP with every hash and a label, v1.5 encryption, v1.5 signatures with all eight hashes, PSS with the salt lengths protocols use) under keys of 1,024, 1,025, 1,031, 2,047, 2,048, 3,072 and 4,096 bits; v1.5 signatures are reproduced exactly. `bench/rsacmp` checks Go reads them the same way |
| [c2sp.org/det-keygen](https://c2sp.org/det-keygen) | 21 key-generation seeds of 2,048, 2,064, 3,072, 4,096 and 8,192 bits: the key an HMAC_DRBG makes the process give, to the last bit of `d` |
| [c2sp.org/CCTV/keygen](https://c2sp.org/CCTV/keygen) | the benchmark's 708 candidates of 2,048 bits: the primes are the 354th and the last, and the key has the modulus and private exponent that Python and Go make |
| Arithmetic | products, powers and remainders against Python's integers for moduli of 1 to 32 limbs (all ones, a power of two plus one, a top limb of 1, a top limb with its high bits clear) and remainders modulo even numbers |
| Keys wrong in exactly one way | primes too close, a private exponent too short, a composite `p`, a modulus that is not `p * q`; and streams of candidates that make generation draw again: for a shared factor of 40 bits in `p - 1` and `q - 1`, for a `p - 1` that the public exponent divides, and for the same prime twice |

Wycheproof's files cover paddings of every wrong shape, BER lengths and missing NULLs in a `DigestInfo`, tiny and huge
signature values, ciphertexts of the wrong length, special salt lengths, and keys of odd sizes. 
Mutation testing: 195 mutants of the code (the Montgomery product and its constants, the exponentiations, the reductions, every
check of a key, the private operation, the four paddings and MGF1, the hash prefixes, key generation, and the wiping of each
buffer that holds a secret). 154 fail a test and 27 hang the suite, because key generation never ends on broken arithmetic. The
14 survivors are equivalent to the original: a check made twice in two places (the size of the key in OAEP, the digest's length
in PSS, the block that a v1.5 signature is compared with), a relaxed assertion, an exponent of 2 that the parity check refuses
anyway, a mask that the length check makes redundant (the session key, the search in the padding), the trial division that
Miller-Rabin repeats, the mask of a Miller-Rabin base that its range check repeats, the check of the modulus's size that the
shape of a candidate guarantees, and a modular inverse that takes smaller steps.

Everything this implementation makes was also read by others, once: 1,528 ciphertexts and signatures (every scheme, hash and
key size of the tests, with and without labels and salts) decrypt or verify with OpenSSL (1,304 of them; it has no OAEP with
SHA-512/224 or SHA-512/256) and with Go, which also reproduces the v1.5 signatures byte for byte. The tests run on x86-64
(under Rosetta) as well as Arm.

The tests also check:

- every scheme round-trips on keys of 1,024, 1,025, 1,031, 2,047 and 2,048 bits, at the longest message and with none;
- every error of a decryption is the same error, and so is every error of a verification, for ciphertexts and signatures
  that are too short, too long, equal to or above the modulus, zero, and changed in any byte;
- a private operation whose result fails the check releases nothing, whichever number of the key was damaged;
- the private operation makes the same number of Montgomery products for any input, and the exponentiation for any exponent;
- `Debug` shows no secret, and a dropped key, the temporaries of its use and of its generation leave nothing behind.

### Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rsa::keypair -- --ignored --nocapture --test-threads=1
cd bench/rsacmp && go test -v -run TestThroughput               # Go's crypto/rsa as shipped, with its assembly
cd bench/rsacmp && go test -tags purego -v -run TestThroughput  # Go's portable code, with no assembly
```

Method:

- Keys: three of OpenSSL's (`src/rsa/testdata/interop.txt`) of 2,048, 3,072 and 4,096 bits, which both sides read from there.
- Operations, as in Go's own benchmarks of `crypto/rsa`: a new private key (checks its numbers and makes the ones of the
  Chinese remainder theorem), OAEP and PKCS #1 v1.5 decryption and encryption of a message of 13 bytes, signing and
  verifying the SHA-256 digest of "testing" with PKCS #1 v1.5 and with PSS (salt as long as the hash), and, for 2,048 bits,
  generating a key from the 708 candidates of c2sp.org/CCTV/keygen's benchmark, so that both searches are the same.
- Each runs about 50 ms to size a batch of about 100 ms; best of five batches.
- The randomized operations read a cheap generator on both sides (`GODEBUG=cryptocustomrand=1` for Go), so the system RNG's
  cost is excluded.
- All three runs print the same first 8 bytes of the PKCS #1 v1.5 signature.

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| 2048 new private key | 714.4 | **585.6** | 690.7 |
| 2048 OAEP decrypt | 964.2 | **890.0** | 1105.0 |
| 2048 OAEP encrypt | **27.4** | 29.2 | 39.7 |
| 2048 sign PKCS1v15 | 964.2 | **921.2** | 1131.6 |
| 2048 verify PKCS1v15 | **27.1** | 28.6 | 37.1 |
| 2048 sign PSS | 967.1 | **911.4** | 1125.4 |
| 2048 verify PSS | **27.5** | 29.2 | 39.1 |
| 3072 new private key | 1956.4 | **1582.6** | 1931.2 |
| 3072 OAEP decrypt | 2997.4 | **2567.2** | 3280.6 |
| 3072 OAEP encrypt | **58.6** | 83.0 | 86.1 |
| 3072 sign PKCS1v15 | 3007.0 | **2622.4** | 3334.3 |
| 3072 verify PKCS1v15 | **58.1** | 82.0 | 81.9 |
| 3072 sign PSS | 2996.4 | **2611.8** | 3325.0 |
| 3072 verify PSS | **59.0** | 83.0 | 85.0 |
| 4096 new private key | 4224.5 | **3342.4** | 4179.6 |
| 4096 OAEP decrypt | 6837.8 | **5621.3** | 7310.7 |
| 4096 OAEP encrypt | **107.2** | 142.8 | 147.1 |
| 4096 sign PKCS1v15 | 6852.2 | **5760.5** | 7384.5 |
| 4096 verify PKCS1v15 | **106.6** | 141.9 | 141.7 |
| 4096 sign PSS | 6837.6 | **5723.7** | 7417.7 |
| 4096 verify PSS | **107.2** | 142.9 | 145.5 |
| 2048 generate key (ms) | 56.1 | **52.7** | 64.9 |

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better; the last row is in ms):

- PKCS #1 v1.5 decryption and encryption are within 1% of OAEP's at every size, and signing with PKCS #1 v1.5 and with PSS
  differ by under 1% too: the padding is nothing beside the exponentiation.
- The public operations (encrypt, verify) are 6% faster than Go's at 2,048 bits and 25 to 30% faster at 3,072 and 4,096,
  where Go's assembly does not apply (it has it for numbers of 1,024, 1,536 and 2,048 bits only) and its speed is about the
  `purego` column's.
- The private operations (decrypt, sign) are 5 to 8% slower than Go's at 2,048 bits, 15 to 17% at 3,072 and 19 to 22% at
  4,096, against its assembly (the primes of 1,024, 1,536 and 2,048 bits are the sizes it has), and 6 to 15% faster than its
  portable code, which is the like-for-like comparison. The product is Montgomery's with both halves of a round in one
  pass and two carries: about 0.64 ns per multiply-add, 2 cycles, with around ten instructions for each.
- A new private key costs 22 to 26% more than Go's. A new public key, which sets up the constants of the modulus, is 12, 25
  and 45 µs, and is paid once per key; Go pays it in every call that uses one.
- Key generation takes 7% longer than Go's, from the same candidates.

Not done yet, would make it faster:

- A squaring that uses the symmetry of the product: it saves a quarter of the multiplications, but its reduction has one
  carry chain where the product has two, which ran about a fifth slower per multiplication when the product was written that
  way. An estimate that it gains nothing, not a measurement of a squaring.
- Unrolled kernels for the sizes of 1,024 to 2,048 bits, as Go's assembly is, and an x86-64 kernel with `mulx` and `adx`.
- The checks of a new private key: the remainders modulo `p - 1` and `q - 1` are made a bit at a time, which is simple and
  constant-time and could use the Montgomery product.


No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings say nothing about an x86 CPU. The
manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## SHA-1

SHA-1 ([RFC 3174](https://www.rfc-editor.org/info/rfc3174)) hashes a message of up to 2^64 - 1 bits into a 160-bit
(20-byte) digest.

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

SHA-1 is broken. Practical collisions exist (SHAttered, 2017), and chosen-prefix collisions since 2020, at a cost far
below the 2^80 birthday bound. **Do not** use it for signatures, certificates, password hashing, or anything that needs
collision resistance; use SHA-256 or SHA-3 instead.

### Testing

```sh
cargo test sha1   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
cargo test --release sha1 -- --ignored --nocapture --test-threads=1   # cryptors; names the backend selected on your machine
cd bench/sha1cmp && go test -v                           # the Go stdlib counterpart
```

Apple M1 Pro:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| One 64 MiB message | ~790 MiB/s | **2143 MiB/s** (FEAT_SHA1) | 2365 MiB/s |

The x86 SHA-NI backend is tested for correctness only, not benchmarked.

## SHA-256

SHA-224 and SHA-256 are the 32-bit SHA-2 functions ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)):
Merkle-Damgard hashes with a 64-byte block.

| Function | Output | Block |
|----------|--------|-------|
| SHA-224 | 28 bytes | 64 bytes |
| SHA-256 | 32 bytes | 64 bytes |

SHA-224 has its own initial state, so it is not a truncated SHA-256 and the two digests are unrelated. The 64-bit
members (SHA-384, SHA-512, SHA-512/224, SHA-512/256) are under [SHA-512](#sha-512).

### Usage

```rust
use cryptors::{Digest, sha2::{Sha224, Sha256}};

let digest: [u8; 32] = Sha256::digest(b"abc");
assert_eq!(
    Sha256::hex_digest(b"abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);
assert_eq!(digest[0], 0xba);

// Own initial state, not a truncated SHA-256.
let short: [u8; 28] = Sha224::digest(b"abc");
assert_eq!(
    Sha224::hex_digest(b"abc"),
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
);
assert_eq!(short[0], 0x23);
```

### Security

Not broken: no known collision or preimage attack beats brute force. Fine for signatures, certificates and integrity
checks, with two caveats:

- **Length extension.** Given `sha256(m)` and the length of `m`, anyone can compute `sha256(m || padding || x)`, so
  `sha256(key || message)` is not a safe MAC; use [HMAC](#hmac). SHA-224 hides one 32-bit state word, which makes
  extension harder but not impossible. SHA-3 is not affected.
- **Not for passwords.** It is fast by design; use a password hash such as [PBKDF2](#pbkdf2).

### Testing

```sh
cargo test sha2::sha256     # known-answer vectors and differential tests against the scalar reference
```

Known answers are NIST's example messages plus inputs straddling the block and padding boundaries (55/56/57, 63/64/65
bytes, ...), with digests from OpenSSL. `matches_scalar_backend` checks every backend the CPU supports against the
scalar one; `--nocapture` names each backend checked.

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public functions use. One test thread,
# so the benchmarks don't compete with each other for the CPU.
cargo test --release sha2::sha256 -- --ignored --nocapture --test-threads=1
cd bench/sha256cmp && go test -v                        # Go's crypto/sha256 as shipped
cd bench/sha256cmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
cd bench/sha256cmp && GODEBUG=cpu.sha=off go test -v    # x86-64 only: Go's AVX2 path, the counterpart of x86_avx2
```

Apple M1 Pro, medians of three runs. SHA-224 and SHA-256 run the same 64 rounds, so their speeds match.

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA-224, one 64 MiB message | 409 MiB/s | 304 MiB/s | **2365 MiB/s** (FEAT_SHA256) | 2324 MiB/s |
| SHA-256, one 64 MiB message | 409 MiB/s | 305 MiB/s | **2365 MiB/s** (FEAT_SHA256) | 2324 MiB/s |

No x86 figures yet. Rosetta 2 does not expose SHA-NI, so that backend has never run on real SHA-NI hardware. The AVX2
and BMI backends are correctness-tested only under Docker (`--platform linux/amd64`), and Rosetta timings say nothing
about a real CPU. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64
and Arm runners; one run on a SHA-NI machine also times the non-SHA-NI paths.

## SHA-3

SHA-3 ([FIPS 202](https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions))
is a sponge over the Keccak-f[1600] permutation, not a Merkle-Damgard compression function like SHA-1/SHA-2. Six
functions share the sponge; the two SHAKE extendable-output functions (XOFs) let the caller choose the output length.

| Function | Output | Rate (absorbed per permutation) | Capacity |
|----------|--------|----------------------------------|----------|
| SHA3-224 | 224 bits (fixed) | 1152 bits (144 bytes) | 448 bits |
| SHA3-256 | 256 bits (fixed) | 1088 bits (136 bytes) | 512 bits |
| SHA3-384 | 384 bits (fixed) | 832 bits (104 bytes) | 768 bits |
| SHA3-512 | 512 bits (fixed) | 576 bits (72 bytes) | 1024 bits |
| SHAKE128 | any length (XOF) | 1344 bits (168 bytes) | 256 bits |
| SHAKE256 | any length (XOF) | 1088 bits (136 bytes) | 512 bits |

### Usage

```rust
use cryptors::sha3;

let digest: [u8; 32] = sha3::sha3_256(b"abc");
assert_eq!(
    sha3::sha3_256_hex(b"abc"),
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
);
assert_eq!(digest[0], 0x3a);

// Also sha3_224, sha3_384 and sha3_512, each with a `_hex` form.
// SHAKE fills the whole output buffer.
let mut xof = [0u8; 32];
sha3::shake128(b"", &mut xof);
assert_eq!(
    sha3::shake128_hex(b"", 32),
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
);
assert_eq!(xof[0], 0x7f);
```

Each `_many` function hashes a slice of messages side by side, one per vector lane:

```rust
use cryptors::sha3;

let digests: Vec<[u8; 32]> = sha3::sha3_256_many(&[b"many", b"messages"]);
assert_eq!(digests[0], sha3::sha3_256(b"many"));
assert_eq!(digests[1], sha3::sha3_256(b"messages"));

// For SHAKE the output length is shared by the whole batch.
let xofs: Vec<Vec<u8>> = sha3::shake128_many(&[b"a", b"b"], 64);
assert_eq!(xofs[0].len(), 64);
```

Messages may differ in length. They run in groups of 4 (AVX2) or 2 (SSE2, or aarch64 with FEAT_SHA3), and a group
costs little more than one digest. See [Hardware acceleration](#hardware-acceleration).

### Security

Not broken: no known collision or preimage attack, and unlike SHA-2's Merkle-Damgard design the sponge is immune to
length extension. Fit for the same uses as SHA-256/SHA-512 (signatures, certificates, integrity checks); use SHAKE
where a construction needs variable-length pseudorandom output.

### Testing

```sh
cargo test sha3   # known-answer vectors and differential tests against the scalar reference
```

### Benchmarking

```sh
# cryptors: your machine's backend, plus scalar if different. One test thread, so benchmarks don't compete.
cargo test --release sha3 -- --ignored --nocapture --test-threads=1
cd bench/sha3cmp && go test -v                 # Go's crypto/sha3 as shipped
cd bench/sha3cmp && go test -tags purego -v    # Go's portable code, the counterpart of our scalar backend
```

Apple M1 Pro, medians of three runs:

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA3-224, one 64 MiB message | 657 MiB/s | 414 MiB/s | **881 MiB/s** (FEAT_SHA3) | 882 MiB/s |
| SHA3-256, one 64 MiB message | 619 MiB/s | 391 MiB/s | **834 MiB/s** (FEAT_SHA3) | 829 MiB/s |
| SHA3-384, one 64 MiB message | 473 MiB/s | 299 MiB/s | **634 MiB/s** (FEAT_SHA3) | 645 MiB/s |
| SHA3-512, one 64 MiB message | 329 MiB/s | 208 MiB/s | **443 MiB/s** (FEAT_SHA3) | 447 MiB/s |
| SHAKE128, one 64 MiB message | 765 MiB/s | 480 MiB/s | **1026 MiB/s** (FEAT_SHA3) | 1021 MiB/s |
| SHAKE256, one 64 MiB message | 619 MiB/s | 390 MiB/s | **834 MiB/s** (FEAT_SHA3) | 831 MiB/s |
| SHA3-256, 1024 × 64 KiB messages | 622 MiB/s | 391 MiB/s | **1596 MiB/s** (FEAT_SHA3, 2 lanes) | 831 MiB/s |

- Speed tracks the rate: SHA3-512 absorbs 72 bytes per permutation, SHA3-224 144.
- The batch row uses `sha3_256_many`; `crypto/sha3` has no batch API, so its figure is 1024 sequential calls.
- No x86 figures yet. Rosetta 2 emulates AVX2 as pairs of NEON operations, so the x86 backends (BMI1/BMI2 scalar
  included) are verified for correctness only. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs
  both sides on GitHub's x86-64 and Arm runners.

## SHA-512

The four 64-bit SHA-2 functions from [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): the
[SHA-256](#sha-256) design with 64-bit words, a 128-byte block and 80 rounds.

| Function | Output | Block | Initial state |
|----------|--------|-------|---------------|
| SHA-384 | 384 bits (48 bytes) | 1024 bits (128 bytes) | first 64 bits of the fractional parts of the square roots of the 9th–16th primes |
| SHA-512 | 512 bits (64 bytes) | 1024 bits (128 bytes) | first 64 bits of the fractional parts of the square roots of the first eight primes |
| SHA-512/224 | 224 bits (28 bytes) | 1024 bits (128 bytes) | generated by the SHA-512/t procedure, from the string `SHA-512/224` |
| SHA-512/256 | 256 bits (32 bytes) | 1024 bits (128 bytes) | generated by the SHA-512/t procedure, from the string `SHA-512/256` |

Each shorter function has its own initial state, so it is not a truncated SHA-512 and the digests are unrelated. Only
the approved `t` = 224 and 256 are provided; their initial state is SHA-512 of the string `SHA-512/t`, started from
SHA-512's initial state XOR `0xa5a5a5a5a5a5a5a5`. A test recomputes both and checks the constants in the code.

### Usage

```rust
use cryptors::{Digest, sha2::{Sha384, Sha512, Sha512_224, Sha512_256}};

let digest: [u8; 64] = Sha512::digest(b"abc");
assert_eq!(
    Sha512::hex_digest(b"abc"),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);
assert_eq!(digest[0], 0xdd);

// Separate algorithms with their own initial states, not truncated SHA-512.
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

- **Not broken.** No collision or preimage attack better than brute force is known on any of the four; all are fine
  for signatures, certificates and integrity checks.
- **Length extension.** Given `sha512(m)` and the length of `m`, anyone can compute `sha512(m || padding || x)`, so
  `sha512(key || message)` is not a safe MAC; use [HMAC](#hmac). The truncated variants withhold part of the state
  (SHA-384: 128 bits, SHA-512/256: 256, SHA-512/224: 288), which puts length extension out of reach, but HMAC is still
  the right way to build a MAC from any of them.
- **Not for passwords.** They are fast by design; use a password-hashing construction such as [PBKDF2](#pbkdf2).

### Testing

```sh
cargo test sha2::sha512     # known-answer vectors and differential tests against the scalar reference, for all four functions
```

Known answers are NIST's example messages plus lengths around the block and padding boundaries (111/112/113,
127/128/129, ...), with digests from OpenSSL and Go's standard library, which agree. `matches_scalar_backend` checks
every backend the CPU supports against scalar; `--nocapture` names each one. The x86-64 build, with and without
BMI1/BMI2, passes the same tests under Docker (`--platform linux/amd64`).

### Benchmarking

```sh
# cryptors: every backend your CPU supports, starting with the one the public functions use.
# One test thread, so the benchmarks don't compete for the CPU.
cargo test --release sha2::sha512 -- --ignored --nocapture --test-threads=1
cd bench/sha512cmp && go test -v                        # Go's crypto/sha512 as shipped
cd bench/sha512cmp && go test -tags purego -v           # Go's portable code, the counterpart of our scalar backend
```

Apple M1 Pro, medians of three runs. The four functions run the same 80 rounds, so their speeds match within noise.

| Workload | cryptors scalar | Go portable (`purego`) | cryptors accelerated | Go stdlib |
|----------|-----------------|------------------------|----------------------|-----------|
| SHA-384, one 64 MiB message | 541 MiB/s | 437 MiB/s | **1371 MiB/s** (FEAT_SHA512) | 1366 MiB/s |
| SHA-512, one 64 MiB message | 540 MiB/s | 438 MiB/s | **1386 MiB/s** (FEAT_SHA512) | 1364 MiB/s |
| SHA-512/224, one 64 MiB message | 541 MiB/s | 437 MiB/s | **1374 MiB/s** (FEAT_SHA512) | 1363 MiB/s |
| SHA-512/256, one 64 MiB message | 540 MiB/s | 438 MiB/s | **1392 MiB/s** (FEAT_SHA512) | 1361 MiB/s |

No x86 figures yet: nothing here can time real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding
conventions, and how to submit a pull request.
