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

**Algorithms** (each has its own page in [`docs/`](docs))

- [AES](docs/aes.md)
- [DES](docs/des.md)
- [ECDH](docs/ecdh.md)
- [ECDSA](docs/ecdsa.md)
- [Ed25519](docs/ed25519.md)
- [HKDF](docs/hkdf.md)
- [HMAC](docs/hmac.md)
- [HPKE](docs/hpke.md)
- [MD5](docs/md5.md)
- [ML-DSA](docs/mldsa.md)
- [ML-KEM](docs/mlkem.md)
- [PBKDF2](docs/pbkdf2.md)
- [Rand](docs/rand.md)
- [RC4](docs/rc4.md)
- [RSA](docs/rsa.md)
- [SHA-1](docs/sha1.md)
- [SHA-256](docs/sha256.md)
- [SHA-3](docs/sha3.md)
- [SHA-512](docs/sha512.md)

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

| Algorithm | Description |
|-----------|-------------|
| [AES](docs/aes.md) | [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final): Advanced Encryption Standard (AES-128, AES-192 and AES-256) |
| [DES](docs/des.md) | [FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final): Data Encryption Standard and Triple DES (TDEA), withdrawn in 2005 and kept for legacy data |
| [ECDH](docs/ecdh.md) | [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final) and [RFC 7748](https://www.rfc-editor.org/info/rfc7748): Elliptic Curve Diffie-Hellman over P-256, P-384, P-521 and Curve25519 (X25519) |
| [ECDSA](docs/ecdsa.md) | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) and [RFC 6979](https://www.rfc-editor.org/info/rfc6979): Elliptic Curve Digital Signature Algorithm over P-224, P-256, P-384 and P-521, randomized and deterministic |
| [Ed25519](docs/ed25519.md) | [RFC 8032](https://www.rfc-editor.org/info/rfc8032): Edwards-curve Digital Signature Algorithm over edwards25519 (Ed25519, Ed25519ctx and Ed25519ph) |
| [HKDF](docs/hkdf.md) | [RFC 5869](https://www.rfc-editor.org/info/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function, over any hash of the crate that implements `Digest` |
| [HMAC](docs/hmac.md) | [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final) and [RFC 2104](https://www.rfc-editor.org/info/rfc2104): Keyed-Hash Message Authentication Code, over MD5, SHA-1 and the six SHA-2 functions |
| [HPKE](docs/hpke.md) | [RFC 9180](https://www.rfc-editor.org/info/rfc9180): Hybrid Public Key Encryption over DHKEM(P-256, P-384, P-521, X25519), HKDF and AES-GCM |
| [MD5](docs/md5.md) | [RFC 1321](https://www.rfc-editor.org/info/rfc1321): The MD5 Message-Digest Algorithm |
| [ML-DSA](docs/mldsa.md) | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): Module-Lattice-Based Digital Signature Algorithm (ML-DSA-44, ML-DSA-65 and ML-DSA-87), hedged and deterministic, with contexts, pre-hash and external μ |
| [ML-KEM](docs/mlkem.md) | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final): Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-512, ML-KEM-768 and ML-KEM-1024), with implicit rejection |
| [PBKDF2](docs/pbkdf2.md) | [RFC 8018](https://www.rfc-editor.org/info/rfc8018): Password-Based Key Derivation Function 2 (PKCS #5 v2.1), with HMAC over any hash of the crate that implements `Digest` |
| [Rand](docs/rand.md) | Cryptographically secure random number generator: the operating system's (`getrandom(2)`, `arc4random_buf(3)` or `/dev/urandom`), as an `io::Read`, with random bytes, random text and uniform numbers below a bound |
| [RC4](docs/rc4.md) | Rivest Cipher 4, the stream cipher of Schneier's *Applied Cryptography* (ARC4, ARCFOUR), with the vectors of [RFC 6229](https://www.rfc-editor.org/info/rfc6229); broken, kept for legacy data |
| [RSA](docs/rsa.md) | [RFC 8017](https://www.rfc-editor.org/info/rfc8017): PKCS #1 v2.2, RSA encryption (OAEP and PKCS #1 v1.5) and signatures (PSS and PKCS #1 v1.5), with keys of 1,024 to 16,384 bits that are generated or built from their numbers |
| [SHA-1](docs/sha1.md) | [RFC 3174](https://www.rfc-editor.org/info/rfc3174): US Secure Hash Algorithm 1 |
| [SHA-256](docs/sha256.md) | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-224 and SHA-256 |
| [SHA-3](docs/sha3.md) | FIPS 202: SHA-3 and SHAKE extendable output functions |
| [SHA-512](docs/sha512.md) | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-384, SHA-512, SHA-512/224, and SHA-512/256 |

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
  is ever a table index. The scalar backend cannot say that, see [AES](docs/aes.md). The wider VAES forms are not used, because
  a cipher called one block at a time cannot fill them.
- **DES, TDEA**: no instruction exists, and the sixteen rounds of a block form a single dependency chain, so there is
  one scalar implementation everywhere. See [DES](docs/des.md).
- **RC4**: no instruction exists, and each step of the generator reads two positions that the step before it may have
  swapped, so the steps are one dependency chain and there is one scalar implementation everywhere. See [RC4](docs/rc4.md).
- **ECDH, ECDSA, Ed25519**: no instruction exists for elliptic curve arithmetic either. They share one portable
  implementation built on `u128` multiplications; x86_64 uses plain `mulq`, not BMI2/ADX. They still benefit from
  hardware through their hash: ECDSA runs HMAC_DRBG on the SHA-256 and SHA-512 backends above, and Ed25519 hashes with
  SHA-512. See [ECDH](docs/ecdh.md), [ECDSA](docs/ecdsa.md) and [Ed25519](docs/ed25519.md).
- **ML-DSA**: no instruction exists for lattice arithmetic either, so the transform and the products are one portable
  implementation in safe Rust, which the compiler turns into NEON instructions in places on aarch64. Much of the time goes
  into SHAKE, which runs on the SHA-3 backends above (`FEAT_SHA3` on aarch64). See [ML-DSA](docs/mldsa.md).
- **ML-KEM**: no instruction exists for lattice arithmetic either, so the transform and the products are one portable
  implementation in safe Rust on `i16` coefficients, which the compiler turns into NEON instructions in places on
  aarch64. A good part of the time goes into SHAKE and SHA-3, which run on the SHA-3 backends above (`FEAT_SHA3` on
  aarch64). See [ML-KEM](docs/mlkem.md).
- **HKDF, HMAC, PBKDF2**: no instruction exists for them either; they run on the hash's own backend, whichever the
  CPU has from the table above, through the hash's incremental form. See [HKDF](docs/hkdf.md), [HMAC](docs/hmac.md) and
  [PBKDF2](docs/pbkdf2.md).
- **Rand**: no instruction is used, not even `RDRAND` or `RNDR`: the operating system's generator already mixes the
  hardware's source with others, and a generator of the crate's own on top of it would share its state across a fork.
  Nothing is selected at run time; the platform is chosen at compile time. See [Rand](docs/rand.md).
- **HPKE**: gets its curves, KDF and cipher from the algorithms above, and adds hardware GHASH. Carry-less multiply
  replaces the many integer multiplications of the software version, which makes GHASH 23 times faster here. See
  [HPKE](docs/hpke.md).
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
`src/sha2/` (`sha256/` and `sha512/`) are an implementation detail, and the [SHA-256](docs/sha256.md) and
[SHA-512](docs/sha512.md) pages cover the 32-bit and the 64-bit functions respectively. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the layout of the source tree.

## Example

Runnable examples for every algorithm are in the `examples/` directory: `cargo run --release --example <name>`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding
conventions, and how to submit a pull request.
