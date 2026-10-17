# Contributing to Cryptors

Thanks for your interest in contributing. Cryptors is an all-in-one, pure-Rust
cryptography library, and correctness is the top priority — a subtle bug in a
crypto primitive is worse than a missing feature.

## Getting started

```sh
git clone https://github.com/matteobovetti/cryptors.git
cd cryptors
make build
make test
```

Common tasks are available via the `Makefile`:

| Command | Description |
|---------|-------------|
| `make build` | Build all crates in debug mode |
| `make release` | Build all crates in release mode |
| `make check` | Type-check all crates without building artifacts |
| `make test` | Run the test suite for all crates |
| `make fmt` | Format the code with `rustfmt` |
| `make fmt-check` | Check formatting without modifying files |
| `make lint` | Run `clippy` and fail on warnings |
| `make doc` | Build documentation for all crates |
| `make doc-open` | Build documentation and open it in the browser |
| `make examples` | Run every program in `examples/` in release mode; each asserts its own known answers |
| `make bench` | Run benchmarks |
| `make bench-throughput` | Run the `#[ignore]`d throughput tests in release mode, one thread |
| `make bench-go` | Run the Go standard-library counterparts in `bench/` (needs Go) |
| `make audit` | Audit dependencies for known vulnerabilities |
| `make clean` | Remove build artifacts |
| `make all` | Run `fmt`, `check`, `lint`, and `test` |
| `make release-checks` | The final local gate before a release: `fmt-check`, `lint`, `check`, `test`, `examples`, `bench`, `bench-throughput` and `bench-go` (slow, and needs Go) |

Run `make fmt-check lint check test` before opening a pull request — they are
the checks CI runs, and they must pass cleanly. Run `make release-checks`
before releasing a new version: it adds the examples, the Rust benchmarks and
throughput tests, and the Go comparisons, so it takes a long time.

## Repository layout

```text
src/
  lib.rs          one `pub mod` per algorithm, and the re-export of `Digest` and `BlockCipher`
  digest.rs       the `Digest` trait shared by every fixed-output hash
  incremental.rs  the hashes' internal incremental form, a state that takes a message in pieces (not public)
  block_cipher.rs the `BlockCipher` trait shared by every block cipher
  aes/            one directory per algorithm
  des/            DES and Triple DES: a block cipher with one implementation, `scalar`
  ec/             the curve arithmetic that more than one algorithm shares: the NIST curves (ECDH, ECDSA) and the
                  field of Curve25519 (X25519, Ed25519); private, but ECDH and ECDSA re-export its curve types
  ecdh/           key agreement over P-256, P-384, P-521 and X25519: keys generic over the curve
  ecdsa/          signatures over P-224, P-256, P-384 and P-521: keys and signatures generic over the curve
  ed25519/        signatures over edwards25519 (Ed25519, Ed25519ctx, Ed25519ph): one curve, so nothing generic
    testdata/       Go's `sign.input` vectors, decompressed but otherwise as Go ships them
  gcm/            AES-GCM with GHASH backends (private; HPKE's AEAD until the crate has a public one)
  hkdf/           key derivation over any hash that implements `Digest`: one type generic over the hash, no backend
  hmac/           message authentication over any `Digest`: no backends of its own, it runs on the hash's
  hpke/           hybrid public key encryption over ECDH, HKDF and AES-GCM: a protocol, with its own layout
  md5/
  mldsa/          post-quantum signatures (FIPS 204): keys and signatures generic over the parameter set, no backend
    testdata/       the selection of ACVP, Wycheproof and NIST's rejection-loop vectors that the tests run, as text
  mlkem/          post-quantum key encapsulation (FIPS 203): keys, ciphertext and secret generic over the parameter set, no backend
    testdata/       the selection of ACVP, Wycheproof and C2SP vectors that the tests run, as text
  pbkdf2/         password-based key derivation over any hash that implements `Digest`: one function generic over the hash, no backend
    testdata/       Project Wycheproof's selection and the cross-checked vectors for all eight hashes, as text
  rand/           the operating system's random number generator: free functions and one type, no backend to select
  rc4/            the RC4 stream cipher: one type, no backend to select
    testdata/       RFC 6229's vectors, as text
  rsa/            RSA encryption and signatures (PKCS #1, RFC 8017): a public key and a private key, no backend to select
    testdata/       the selection of Wycheproof's vectors, RSA Laboratories', OpenSSL's, c2sp.org's and the arithmetic's, as text
  sha1/
  sha2/           a family of functions: one directory per word size
    mod.rs          the family's documentation, `mod sha256; mod sha512;`, re-exports
    sha256/         SHA-224 and SHA-256
    sha512/         SHA-384, SHA-512, SHA-512/224 and SHA-512/256
  sha3/           SHA-3 and SHAKE, and `xof.rs`, the streaming SHAKE that ML-DSA and ML-KEM use (not public)
  wipe.rs         overwrites a secret with zeros, in a way the compiler may not remove
bench/
  <name>cmp/      the Go standard-library counterpart of one algorithm
```

Inside an algorithm's directory (`src/sha1/` is a compact example,
`src/sha2/sha256/` the one with the most backends):

| File | Holds |
|------|-------|
| `mod.rs` | The module documentation shown on docs.rs (`//!`, with an example that doubles as a doctest), the `mod` declarations, and the `pub use` of the public types. `md5` and `sha3` also keep here the round macros that their backends share. |
| `digest.rs` | The public types or functions, the specification's constants, the runtime backend dispatcher, the implementation of the internal `Incremental` on that dispatcher, and the unit tests: known answers, differential tests against `scalar`, and the `#[ignore]`d throughput test. |
| `scalar.rs` | The portable implementation. It is always compiled, it is the fallback on any CPU, and it is the reference every other backend is tested against. |
| `aarch64.rs`, `x86.rs`, ... | One file per hardware backend, named after its architecture (`x86_avx2.rs` is a second x86 backend). Each is gated with `#[cfg(target_arch = ...)]` and entered only after the dispatcher has confirmed the CPU feature it needs. |

A block cipher has `cipher.rs` where a hash has `digest.rs`: the public types, the
runtime backend dispatcher and the unit tests. It also has `schedule.rs`, the key
schedule that every backend shares (only the S-box and the inverse MixColumns differ
between them, and are passed in). `src/aes/` is the example. A cipher with only a
portable implementation, like `src/des/` (no CPU has a DES instruction), keeps the
same shape: `schedule.rs`, `scalar.rs` and `cipher.rs`, plus `tables.rs` for the
constants of the standard and, for the tests only, `reference.rs`.

A key agreement, `src/ecdh/`, and a signature scheme, `src/ecdsa/`, have neither shape. There is no backend to
select, because no x86 or Arm CPU has an instruction for elliptic curves, and no trait shared with the other algorithms:
the keys are generic over a sealed `Curve` trait (one for each of the two), and the curves are the only types that
implement it. The curve types themselves, `P224`, `P256`, `P384` and `P521`, are defined once, in `src/ec/`, and
re-exported by the two modules that use them. The files of `src/ec/`, which is not public:

| File | Holds |
|------|-------|
| `nist.rs` | The four NIST curves: the types, their constants, the table of multiples of the generator that every user of a curve shares, and the encodings of points and scalars. |
| `weierstrass.rs` | The group law of the curves (complete formulas, a four-bit window), and the order of a curve as a modulus, which is the field of the scalars of ECDSA. |
| `field.rs` | The arithmetic modulo a prime that the two use (Montgomery form, any number of limbs). |
| `ct.rs` | The comparisons and selections that do not branch. Anything that depends on a secret goes through these. |
| `fe25519.rs` | The integers modulo `2^255 - 19` in five limbs of 51 bits, the field of X25519 and of Ed25519, with its tests against `field.rs`. |

The files of `src/ecdh/`, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the curves and the error. |
| `curve.rs` | `Curve`, the public half of the trait (the names and sizes), the private half it requires, which does the work on byte strings, and `Error`. |
| `keypair.rs` | `PrivateKey`, `PublicKey`, `SharedSecret`, and the tests of the API: known answers, Wycheproof, invalid keys, `generate`, the chained exchanges, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `nist.rs`, `x25519.rs` | One curve family each: its implementation of the private half of `Curve` (and, for X25519, the types and constants). |
| `vectors.rs` | Test data only (`#[cfg(test)]`): known answers, the Wycheproof selection and the chained exchanges' results. |

And those of `src/ecdsa/`:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the signature, the curves and the error. |
| `curve.rs` | `Curve`, its private half (which also lists what a source of per-message secrets does) and `Error`. |
| `keypair.rs` | `PrivateKey` and `PublicKey` with the four ways to sign and the two to verify, and the tests of the API: RFC 6979, Wycheproof, CAVP, the hedged and the chained signatures, the vectors for key generation, invalid keys and signatures, `generate`, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `signature.rs`, `der.rs` | `Signature` with its two encodings, and the strict DER reader and writer under it. |
| `algorithm.rs` | Signing and verifying as FIPS 186-5 writes them, on any curve of `src/ec/`; the tests of the digest rules and of the branch that a random nonce never reaches. |
| `hmac_drbg.rs` | The HMAC_DRBG (SP 800-90A) that makes the per-message secrets, on the crate's `Hmac`; its tests check it against RFC 6979, and the HMAC under it against Python's `hmac`. |
| `nist.rs` | The implementation of the private half of `Curve` for the four curves. |
| `vectors.rs` | Test data only: RFC 6979, c2sp's key generation vectors, a selection of CAVP and of Wycheproof, the signatures of another implementation, and the chains. |

Ed25519, `src/ed25519/`, is a signature scheme with neither shape either, and with no trait at all: it has one
curve, and its hash is part of the algorithm, so its keys are plain types. Of `src/ec/` it uses the field it shares
with X25519, `fe25519.rs`, and `ct.rs`; the rest is for curves in Weierstrass form. Its files, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the signature, the error and `MAX_CONTEXT_LEN`. |
| `signature.rs` | `SigningKey`, `VerifyingKey`, `Signature` and `Error`, the three schemes and the hash input that tells them apart, and the tests of the API: RFC 8032, Go's vectors, the 768 signatures, every rule of verification, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `edwards.rs` | The points of the curve and its constants: their encoding, the group law, the constant-time multiplication of the base point and the variable-time double multiplication of verification, with the two tables of multiples of the base point that every key shares. |
| `scalar.rs` | The arithmetic modulo the order of the group, in four 64-bit words with Barrett reduction, and the two recodings of a scalar into digits. |
| `testdata/sign.input` | Test data only: Go's 128 vectors, read with `include_str!`. |

A message authentication code, `src/hmac/`, has neither shape either. It has no backend to select, because it runs on
the hash's compression function, through the hash's own dispatcher, and it implements no trait: `Hmac<D>` is generic
over `Digest`. Its files:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declaration and the `pub use` of `Hmac`, `hmac` and `VerifyError`. |
| `mac.rs` | `Hmac`, the one-call `hmac` and `VerifyError`; the one-shot path for a hash from outside the crate; the comparison that does not stop at the first difference; and the tests: the RFC vectors, the vectors from Go and OpenSSL, truncation, verification, multi-part messages, wiping, `Debug` and the `#[ignore]`d `throughput`. |

What HMAC streams through is an internal interface of the hashes, `src/incremental.rs`: the `Incremental` trait, the
`State` that all eight hashes share (the chaining value, the bytes of an unfinished block and the length) with the
buffering and the padding that they share too, and the tests that hold every hash in pieces to its one-shot digest.
Each hash's `digest.rs` implements the trait in a few lines, on the compression function and the backend dispatcher it
already has, so a message in pieces goes through the same backend as a whole one. Code that only knows `D: Digest`
reaches it through `Digest::INCREMENTAL`, a hidden constant that the crate's hashes set and that is `None` for a hash
implemented elsewhere; the interface is not public, so it can change without breaking anyone.

A key derivation function, `src/hkdf/`, has less in it. There is no backend, because the work is in the hash, which picks
its own, and no trait, because `Hkdf<D>` is generic over `Digest`. Its files:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of `Hkdf` and `Error`. |
| `kdf.rs` | `Hkdf` (Extract, Expand, `derive`, `from_prk`), which holds an `Hmac<D>` keyed with the PRK, and `Error`, and the tests: RFC 5869, the vectors from Go and OpenSSL, the limits, wiping, `Debug` and the `#[ignore]`d `throughput`. |

A password-based key derivation function, `src/pbkdf2/`, is smaller still: one function. It has no backend, because the
work is in the hash, which picks its own, and no type, because the HMAC it keys with the password lives only as long as
the call. `derive` is generic over `Digest`. Its files:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declaration and the `pub use` of `derive` and `Error`. |
| `kdf.rs` | `derive`, `Error`, and the tests: RFC 6070 and RFC 7914, the Wycheproof selection and the cross-checked vectors for all eight hashes (read from `testdata/vectors.txt`), the block counter, the refused inputs, the length limit and the `#[ignore]`d `throughput`. |
| `testdata/vectors.txt` | Test data only (text, written by scripts kept outside the repository; do not edit by hand). |

The random number generator, `src/rand/`, is smaller than any of them and has no algorithm in it: each call asks the
operating system for bytes, so there is no backend to select at run time (the platform is chosen at compile time, with
`cfg_select!`), no trait, no state in the process and nothing generic. Its `unsafe` is of a kind no other module has: the declaration of the C library's `getrandom` or `arc4random_buf` and one call to it. Its files:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of `Reader`, `fill`, `text` and `below`. |
| `sys.rs` | The one place that differs by platform (`getrandom(2)`, `arc4random_buf(3)`, `/dev/urandom`, or nothing), the loop that makes a call that writes some bytes fill a whole buffer, and the tests of the loop and of the `/dev/urandom` route. |
| `random.rs` | `Reader`, `fill`, `text` and `below`, and the tests of the API: the output's statistics, the guard bytes, threads, the mapping of `text`, the table of known answers for `below`, uniformity, the limits and the `#[ignore]`d `throughput`. |

Nothing in it can be checked against a vector, because its output is meant to be unpredictable; its tests are of the
loop, of the statistics (loose enough to fail about once in 10^8 runs or less) and of the pure parts (`text`'s mapping
and `below`, which an independent implementation's answers pin). A platform's call is only tested on that platform: the
tests run on Linux (CI) and macOS, and the BSD calls have not been run.

RC4, `src/rc4/`, is a stream cipher, which fits neither trait: it has no block for `BlockCipher` and no digest for
`Digest`, and being the only one, it gets no trait of its own. It has no backend to select, because no CPU has an
instruction for it and each step of the generator depends on the one before. Its files:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation (security first, because RC4 is broken), the `mod` declaration and the `pub use` of `Rc4` and `Error`. |
| `cipher.rs` | `Rc4` (the key schedule, `apply_keystream`, `xor_keystream`), `Error`, and the tests: RFC 6229, the vectors of the first posting and Wikipedia's, a digest of the keystream under every key length, a message in pieces, the limits of the key, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `testdata/rfc6229.txt` | Test data only (text, written by a script kept outside the repository; do not edit by hand). |

RSA, `src/rsa/`, is a public-key encryption and signature algorithm with neither shape: no backend to select (no CPU
has an instruction for big-number multiplication beyond the 64 by 64 to 128 bit product that `u128` compiles to) and no
trait of its own. Its keys are two plain types, `PublicKey` and `PrivateKey`, with a method for each scheme; the only
type parameter is the hash, on the functions that take one, as in ECDSA. It has the big numbers of its own (private to
the module: the crate has no public big integer), and its `unsafe` is the volatile write that wipes a key, like the rest.
Its files, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, `SaltLength`, `Pkcs1Hash` and the error. |
| `keypair.rs` | `PublicKey` and `PrivateKey` with the four schemes (OAEP, PSS, PKCS #1 v1.5 encryption and signatures), the private operation by the Chinese remainder theorem with the check of its result, the validation of a key's components, and the tests of the API: the accessors, each rule of the validation (with the keys of `testdata/edge.txt`, each wrong in exactly one way), round trips on keys of every shape of size, the limits of each scheme, one error for every kind of bad ciphertext and signature, the session key function, a faulty computation that releases nothing, the same work for any input, `Debug`, wiping, and the `#[ignore]`d `throughput`. |
| `oaep.rs`, `pss.rs`, `pkcs1v15.rs`, `mgf1.rs` | The paddings of RFC 8017 on byte strings, with their tests: OAEP and the v1.5 encryption block are unpadded without a branch on a byte. |
| `hash.rs` | `Pkcs1Hash`, the sealed trait of the eight hashes that a v1.5 signature can name, with the prefix of each `DigestInfo`. |
| `bigmod.rs` | `Limbs` (numbers that wipe themselves) and `Modulus` (Montgomery's arithmetic for an odd modulus of any size, the constant-time exponentiation with a four-bit window, the reduction of a number of any length); tested against Python's integers. |
| `keygen.rs` | Key generation as c2sp.org/det-keygen has it: the candidates, trial division, Miller-Rabin, the private exponent modulo `lcm(p - 1, q - 1)`; not constant-time. |
| `bytes.rs`, `error.rs` | Byte strings that wipe themselves, and `Error`. |
| `conformance.rs`, `testdata/` | The vector-driven tests, and their data (text, written by scripts kept outside the repository; do not edit by hand): Wycheproof's OAEP, PKCS #1 v1.5 and PSS vectors, RSA Laboratories' OAEP and PSS vectors, what OpenSSL made, the vectors of c2sp.org/det-keygen, and the keys and candidate streams that make key generation take its rare paths; and the ignored `every_vector`, which runs the unselected Wycheproof files. |
| `testutil.rs` | Helpers of the tests: hex, the reader of the files, the HMAC_DRBG of the key generation vectors, and the allocator that finds numbers left in freed memory. |

ML-DSA, `src/mldsa/`, is a signature scheme with neither shape either, and with no backend to select: no CPU has an
instruction for lattice arithmetic, so one portable implementation runs everywhere, over the crate's own SHAKE (`src/sha3/`).
Its keys and signature are generic over a sealed `Parameters` trait, which only `MlDsa44`, `MlDsa65` and `MlDsa87`
implement. Its files, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the signature, the parameter sets, `PreHash` and the error. |
| `params.rs` | `Parameters`, the public half of the trait (names and sizes), the sealed half with the numbers of FIPS 204's table 1 and what follows from them, and the three types. |
| `keypair.rs` | `PrivateKey`, `PublicKey` and `Signature`, with the hedged and deterministic signatures of a message, of a digest (HashML-DSA) and of a message representative (external μ), and the tests of the API: the accumulated known answers, the modes, the context, the pre-hash, tampering, encodings, wiping, `Debug`, and the `#[ignore]`d `throughput` and `accumulated_10000`. |
| `algorithm.rs` | `ML-DSA.KeyGen_internal`, `Sign_internal` and `Verify_internal` on byte strings and for any set; `Expanded`, what signing works from (with `skEncode` and `skDecode`, for the tests only); the four checks of the rejection loop; and the count of rejections that tests read. |
| `field.rs` | The integers modulo `q` (Montgomery's reduction, `i32` values that stay unreduced where they can), the transform and its inverse, with the roots of unity computed at compile time. |
| `rounding.rs` | `Power2Round`, `Decompose`, `MakeHint` and `UseHint`, checked against the definitions for every number modulo `q`. |
| `sample.rs` | `ExpandA`, `ExpandS`, `ExpandMask` and `SampleInBall` over the streaming SHAKE. |
| `pack.rs` | The bit packing of FIPS 204's section 7.1 and the hint's encoding, whose decoder refuses every encoding but the canonical one. |
| `prehash.rs`, `error.rs` | `PreHash`, the twelve functions of HashML-DSA with their identifiers; and `Error`. |
| `conformance.rs`, `testdata/` | The vector-driven tests, and their data (text, written by scripts kept outside the repository; do not edit by hand): ACVP, Wycheproof and NIST's rejection-loop vectors, and the ignored `every_vector`, which runs the unselected files. |
| `testutil.rs` | Helpers of the tests. |

ML-KEM, `src/mlkem/`, is a key encapsulation mechanism with neither shape either, and with no backend to select: no CPU
has an instruction for lattice arithmetic, so one portable implementation runs everywhere, over the crate's own SHAKE and
SHA-3 (`src/sha3/`). Its keys, ciphertext and shared secret are generic over a sealed `Parameters` trait, which only
`MlKem512`, `MlKem768` and `MlKem1024` implement. Its files, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the ciphertext, the secret, the parameter sets and the error. |
| `params.rs` | `Parameters`, the public half of the trait (names and sizes), the sealed half with the numbers of FIPS 203's table 2 and what follows from them, and the three types. |
| `keypair.rs` | `DecapsulationKey` (the 64-byte seed and what it expands to), `EncapsulationKey`, `Ciphertext` and `SharedSecret`, and the tests of the API: the accumulated known answers, a whole exchange, the reader, implicit rejection, encodings, wiping, `Debug`, the inputs of `bench/mlkemcmp`, and the `#[ignore]`d `throughput` and `accumulated_10000`. The expanded decapsulation key of FIPS 203 exists in this file for the tests only. |
| `algorithm.rs` | `K-PKE.KeyGen`, `Encrypt` and `Decrypt`, and `ML-KEM.Encaps_internal` and `Decaps_internal` (with the implicit rejection) on byte strings and for any set, and the encoding of the encapsulation key with its modulus check. |
| `field.rs` | The integers modulo `q` (Montgomery's and Barrett's reductions on `i16`), the transform, its inverse and the product of `T_q`, with the roots of unity computed at compile time. Its tests hold the tables of FIPS 203's appendix A and the algorithms of the specification written out. |
| `pack.rs` | `Compress`, `Decompress`, `ByteEncode` and `ByteDecode` (with the modulus check), tested against the definitions for every number modulo `q`. |
| `sample.rs` | `SampleNTT` over the streaming SHAKE128 and `SamplePolyCBD` for both values of eta. |
| `error.rs` | `Error`. |
| `conformance.rs`, `testdata/` | The vector-driven tests, and their data (text, written by scripts kept outside the repository; do not edit by hand): ACVP, Wycheproof and C2SP's unlucky vectors, and the ignored `every_vector`, which runs the unselected files. |
| `testutil.rs` | Helpers of the tests, among them the key of the draft of FIPS 203 that C2SP's vectors are for. |

AES-GCM, `src/gcm/`, is private to the crate: HPKE's AEAD, until the crate has a public one. It has the anatomy of an
algorithm with backends, for GHASH, whose multiplication in GF(2^128) is what carry-less multiply instructions are for;
the counter mode is the crate's AES, on whichever of its backends the CPU has.

| File | Holds |
|------|-------|
| `mod.rs` | The documentation and the `mod` declarations, and the test helpers its files share. |
| `aead.rs` | `Gcm`, sealing and opening (counter mode and GHASH over 1 KiB at a time), and the tests of the whole: the specification's test cases and values from Go on every GHASH backend, tampering, the length limits and the `#[ignore]`d `throughput`. |
| `ghash.rs` | What every GHASH backend shares (the reduction, the powers of `H`, the padding and the length block) and the runtime dispatcher, with `matches_scalar_backend` and `unaligned_input`. |
| `scalar.rs`, `aarch64.rs`, `x86.rs` | The backends: `ctmul64`, the reference (tested against SP 800-38D's bit-by-bit algorithm), then PMULL and PCLMULQDQ. |

HPKE, `src/hpke/`, is a protocol over three primitives rather than a primitive with backends, and its files follow
RFC 9180:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the suite, the keys, the contexts, the modes and the error. |
| `suite.rs` | `Suite`, `Kem`, `Kdf` and `Aead`: the identifiers and sizes of section 7, and `LabeledExtract` and `LabeledExpand` (section 4) on `src/hkdf/`, generic over the hash. |
| `kem.rs` | `PrivateKey`, `PublicKey` and DHKEM (section 4.1) over the curves of `src/ecdh/`: `DeriveKeyPair`, `Encap`, `Decap` and their authenticated forms. |
| `context.rs` | The modes, the key schedule (section 5.1), `Sender` and `Recipient` with their sequence numbers and exports, and the setup and single-shot functions. |
| `secret.rs`, `error.rs` | Secret bytes of a length known at run time, wiped on drop; and `Error`. |
| `tests.rs` | The tests of the whole protocol: the vectors, interoperation with Go, the failures and the `#[ignore]`d `throughput`. |
| `vectors.rs` | Test data only: RFC 9180's file and Go's, filtered to the crate's scope by a script kept outside the repository. Do not edit it by hand. |

The backend modules are private: users see `cryptors::sha2::Sha256`, never the
path through `sha256`. When several functions share one algorithm, as the six
SHA-2 functions share two, they share a directory. Each word size then has the
anatomy above, and the parent `mod.rs` only documents the family, declares the
children, re-exports their types and holds what both need (`has_bmi`, the x86
BMI1/BMI2 check).

The fixed-output hashes (MD5, SHA-1, SHA-2) are unit types that implement
`Digest`, and, inside the crate, `Incremental`. SHA-3 has not been converted yet and exposes free functions, as its
extendable-output functions do not fit the trait. The block ciphers (AES, DES) implement
`BlockCipher` instead, and are not unit types: a cipher holds the key schedule it
was built with. ECDH and ECDSA implement neither: their curves are unit types, but they only
name the curve that a `PrivateKey<C>`, a `PublicKey<C>` or a `Signature<C>` belongs to. ECDSA takes the hash as
a type parameter, `D: Digest`, of the functions that sign and verify a message. Ed25519 implements neither trait
and has no type parameter: a `SigningKey`, a `VerifyingKey` and a `Signature`, with a method for each of its three
schemes. HMAC is generic over `Digest` rather than implementing it: an `Hmac<D>` holds the two hash states it computed
from its key. HKDF takes the hash as a type parameter of its one type, `Hkdf<D: Digest>`, which holds the pseudorandom
key it was built with. HPKE implements neither either, and is the one module that picks its algorithms at run time: a
suite is negotiated on the wire by its identifiers, so `Suite`, `Kem`, `Kdf` and `Aead` are values, and a key of one KEM
in a suite of another is an error rather than a type mismatch. ML-DSA implements neither trait either: like ECDSA's, its keys
and signature are generic over a sealed trait, here `Parameters`, whose three implementors are unit types that name the set.
ML-KEM does the same with its own `Parameters`: a decapsulation key, an encapsulation key, a ciphertext and a shared secret
of one set cannot be mixed with those of another.

Each algorithm in `bench/` is its own Go module with a throughput test that
mirrors the Rust one (same buffer, warm-up and best-of-5 method). The AES, ECDH, ECDSA, Ed25519, HPKE, ML-DSA, ML-KEM, RSA, SHA-2
and SHA-3 ones also split into `impl_asm_test.go` and `impl_purego_test.go`, so that
`-tags purego` selects Go's portable code, the counterpart of our `scalar`
backend (of our one implementation, for ECDH, ECDSA, Ed25519 and RSA; for ML-DSA and ML-KEM, which are portable code in Go too, it
swaps the Keccak under it). (`descmp` does not split: Go's
`crypto/des` is portable code on every platform, so it has one run, and so does `rc4cmp`, with `crypto/rc4`.) The ECDH
one also checks its inputs, with the NIST and RFC 7748 vectors and with the
chained exchanges of `src/ecdh/keypair.rs`, so a broken build fails instead of
passing as a figure, and the ECDSA one does the same with the signatures of
RFC 6979, the chained signatures of `src/ecdsa/keypair.rs` and the randomized
signatures of `src/ecdsa/vectors.rs`, which Go made, and the Ed25519 one with RFC 8032's first example and the 768
signatures of `src/ed25519/signature.rs`. (`hmaccmp` does not split either: it measures the hashes, whose
own modules time Go's portable code; it checks a known answer for each hash before it times anything.) The ML-DSA one checks the keys and signatures of Wycheproof's first
case in each set, which `src/mldsa/testdata/wycheproof.txt` holds too. The ML-KEM one checks the encapsulation key of
Wycheproof's first key-generation case, and the key, ciphertext and secret of its own benchmark inputs, which
`the_benchmark_inputs_have_the_answers_of_go_and_openssl` in `src/mlkem/keypair.rs` pins too (Go has no ML-KEM-512). The HKDF one checks
RFC 5869 A.1 and the longest outputs that `longest_output` in `src/hkdf/kdf.rs` expects. The HPKE one opens, with Go's `crypto/hpke`, the messages that
`src/hpke/tests.rs` seals in all 36 suites the two have in common, and prints an export that both sides compute from the
same keys. The PBKDF2 one checks RFC 6070's first three vectors, RFC 7914's first, and the first step of each chain that it times,
which `benchmark_inputs_have_the_known_answers` in `src/pbkdf2/kdf.rs` pins too. The Rand one checks that the buffers it
times are filled and look random (there is no output to compare) and replays the `BELOW` table of `src/rand/random.rs`
against `rand.Int`. The RC4 one checks RFC 6229's first vector, Wikipedia's three examples and the digest that
`every_key_length` in `src/rc4/cipher.rs` expects, and the first bytes of its own run. The RSA one reads the keys and the
candidate stream for key generation from `src/rsa/testdata/` (`interop.txt` and `candidates2048.txt`), so both sides time the
same keys, checks that Go reads the 315 ciphertexts and signatures that OpenSSL made there as the Rust tests do, and that
the key generated from the candidates has the modulus and private exponent that `the_benchmark_candidates_make_this_key` in
`src/rsa/keygen.rs` pins. `make bench-go` runs them all, and so does the manual `Benchmarks`
workflow (`.github/workflows/bench.yml`) on GitHub's x86-64 and Arm runners.

## Adding or implementing an algorithm

Each algorithm lives in its own directory under `src/` (laid out as above) and
is declared in `src/lib.rs`. When implementing one:

- Cite the governing spec in the `mod.rs` module-level doc comment (e.g.
  `RFC 1321`, `FIPS 197`), the same way `src/md5/mod.rs` does.
- If the primitive is broken or unsuitable for new designs (MD5, DES, RC4,
  SHA-1, ...), say so explicitly in the module doc comment.
- Include test vectors from the spec itself, not just hand-rolled inputs.
- Add edge-case tests around boundary conditions specific to the algorithm
  (e.g. block-length boundaries for hash functions).
- Write `scalar.rs` first and keep it correct on its own. A hardware backend
  goes in a file of its own, with a test (`matches_scalar_backend`) that checks
  it against `scalar` on every CPU that supports it.
- Make a fixed-output hash implement `Digest`, and a block cipher `BlockCipher`.
  A fixed-output hash also implements `Incremental` and sets `Digest::INCREMENTAL`,
  so that HMAC streams through it instead of copying; a construction built on a
  hash takes `D: Digest`, as HMAC does.
- Where Go's standard library has the same algorithm, add its counterpart under
  `bench/<name>cmp/` and to `make bench-go`.
- Add the algorithm to the table in `README.md`, and give it a page of its own
  in `docs/` like the existing ones (`docs/<name>.md`), linked from the table.

Keep implementations dependency-free unless there's a strong reason
otherwise — the crate currently has zero dependencies, and that's deliberate.

## Code style

- Format with `cargo fmt` (`make fmt`) and keep `cargo clippy` (`make lint`)
  warning-free; CI runs both with warnings treated as errors.
- Prefer clarity and auditability over cleverness — these implementations
  exist to be read and verified, not just to run fast.
- Avoid introducing `unsafe` unless there's no reasonable alternative, and
  justify it in a comment when you do.

## Testing

- `cargo test --all` must pass.
- Prefer deterministic test vectors (known inputs/outputs from the spec)
  over randomized tests.
- Mark expensive, non-correctness checks (e.g. throughput benchmarks run as
  tests) with `#[ignore]` and a comment explaining how to run them manually.
- Test names follow the module path, so one algorithm can be run alone:
  `cargo test sha2::sha512`, or with its throughput test
  `cargo test --release sha2::sha512 -- --ignored --nocapture --test-threads=1`
  (`make bench-throughput` runs them all). The `#[ignore]` message of each
  throughput test carries its own filter, so copy that command as written.

The `digest.rs` of each algorithm has the same test module, with
`src/sha2/sha256/digest.rs` and `src/sha2/sha512/digest.rs` as the reference
shape:

| Test | Checks |
|------|--------|
| `known_answers`, `million_a`, `padding_boundaries` | The public functions against vectors from the spec and from an independent implementation (OpenSSL, Go), including lengths on both sides of every padding boundary. |
| `scalar_known_answers` | The same vectors forced through the scalar backend, which the public functions skip on a machine with hardware instructions. |
| `matches_scalar_backend` | Every other backend, called directly, against scalar, over lengths that straddle block and padding boundaries. The name is fixed: the docs and the module docs cite it. |
| `unaligned_input` | Every backend, on messages that start at every offset within a block. The vector backends load with unaligned instructions, and only this test runs the ones that are not the public path. |
| `throughput` | Marked `#[ignore]`. |

A block cipher's `cipher.rs` has the same module with vectors in place of padding
boundaries: `known_answers` (the standards' examples), `chained` and `many_keys`
(vectors from OpenSSL and Go, one long chain of encryptions and many different
keys), `scalar_known_answers`, `matches_scalar_backend` (which also compares the
round keys), `unaligned_input` (which moves the round keys as well as the block),
`dropping_wipes_the_round_keys`, `debug_hides_the_key` and `throughput`.

ECDH's tests are `known_answers` (the standards' vectors, for each curve), `wycheproof` (the selection of Project
Wycheproof's cases in `vectors.rs`), `rejects_invalid_private_keys` and `rejects_invalid_public_keys`,
`x25519_refuses_points_of_small_order`, `edge_scalars_are_keys`, `a_zero_x_coordinate_is_not_special_on_the_nist_curves`,
`chained_exchanges` (rounds of exchanges between derived keys, with values from OpenSSL, which `bench/ecdhcmp`
recomputes in Go), the `generate_*` tests with a scripted reader, `encoding_lengths`, `equality_and_cloning`,
`dropping_wipes_the_secrets`, `debug_hides_the_secrets`, `curve::tests::errors_say_what_went_wrong` and `throughput`. Under it, each layer checks itself against
something that does not share its code: `field.rs` against integers computed in Python and, for one limb, `u128`;
`src/ec/nist.rs` against the relations that define a curve and against the generic multiplication (the table of multiples of
the generator); `fe25519.rs` and the X25519 ladder against the generic field and the ladder written on it. Those layers
are in `src/ec/` now, so `cargo test -- ecdh:: ec::` runs all of ECDH's tests, and `cargo test -- ecdsa:: ec::` all of ECDSA's.

ECDSA's tests are `rfc_6979_known_answers` (the 40 signatures of the RFC, through the whole API) and
`hmac_drbg::tests::rfc_6979_nonces` (the `k` of each), `wycheproof` (the selection in `vectors.rs`, with the DER and
the `r || s` forms), `nist_cavp_signature_verification`, `deterministic_key_generation_vectors` (c2sp.org/det-keygen),
`hedged_known_answers` (another implementation of the same construction, given the same random bytes),
`chained_signatures` (rounds of derived keys signing the state, with values from OpenSSL, which `bench/ecdsacmp`
recomputes in Go), `signatures_verify_and_only_those`, `digests_of_any_length` and `the_message_and_digest_forms_agree`,
`digests_that_are_not_digests`, `a_failing_random_source_is_reported`, `rejects_invalid_private_keys`,
`rejects_invalid_public_keys` and `rejects_invalid_signatures`, `edge_scalars_are_keys`, the `generate_*` tests with a
scripted reader, `encoding_lengths` and `der_sizes_are_the_documented_ones`, `equality_and_cloning`, `dropping_wipes_the_private_key`,
`debug_hides_the_secrets`, `algorithm::tests::*` (the digest rules, the retry for a zero `s` that a random nonce never
reaches, and the panic for a generator that never gives a number), `hmac_drbg::tests::*` (the layout of the seed), `der::tests::*`
(every way to write a signature that is not the one DER prescribes, and the length at which the long form starts),
`curve::tests::errors_say_what_went_wrong` and `throughput`.

Ed25519's tests are `known_answers` (every example of RFC 8032 for the three schemes), `go_sign_input` (Go's vectors,
from `testdata/`), `many_keys` (768 signatures under 256 keys, with values from Go that OpenSSL agrees with and that
`bench/ed25519cmp` recomputes), one test for each rule of verification (`rejects_tampering`,
`rejects_s_not_below_order`, `rejects_non_canonical_r`, `rejects_non_canonical_public_keys`,
`rejects_small_order_public_keys` and `cofactorless_equation`), `context_lengths`, `wrong_lengths`,
`generate_reads_a_seed`, `dropping_wipes_the_secret_key`, `debug_hides_the_key` and `throughput`, which reports the
time of an operation rather than MiB/s. Under them, each layer checks itself against something that does not share its
code: the shared field, `src/ec/fe25519.rs`, against the generic field of `src/ec/field.rs`, at the largest limbs its
bounds allow (ECDH's tests, and `negation_and_pow_p58_match_the_generic_field`,
`sqrt_ratio_finds_the_roots_there_are` and `sign_and_zero_follow_the_canonical_value` for what only Ed25519 uses);
`scalar.rs` against a reduction one bit at a time; and the double multiplication of `edwards.rs` against plain
double-and-add. `cargo test -- ed25519 ec::fe25519` runs all of them.

HMAC's tests are `rfc4231` and `rfc2202` (the RFCs' vectors, through every way of computing a tag and through the
one-shot path as well), `generated_vectors` (from OpenSSL and Go, for every hash, at the key-length boundaries and on
both sides of the inner hash's padding boundary), `truncated_tags`, `verify_accepts_only_the_tag`,
`parts_match_the_whole_message`, `dropping_wipes_the_states`, `debug_hides_the_key` and `throughput`. Under it,
`incremental::tests` holds every hash in pieces to its one-shot digest (`pieces_match_one_shot_at_every_split`,
`long_message_in_uneven_pieces`, `a_clone_carries_on_from_the_same_point`) and checks `dropping_wipes_the_state`;
`wipe::tests::wipe_bytes_zeroes_every_byte` checks the bulk wipe both use. `cargo test -- hmac:: incremental::` runs
them all.

HKDF's tests are `rfc_5869` (the seven cases of Appendix A, through every function of the API), `salt_lengths` and
`prk_lengths` (salts and PRKs of HashLen, one block and one byte more, where HMAC starts hashing its key), `longest_output`
(255 blocks, one byte more refused, and shorter outputs as its prefixes) and `long_inputs`, all four with vectors from Go
and OpenSSL for all eight hashes, then `lengths_of_inputs` (an empty salt, a short PRK), `dropping_wipes_the_prk` (an
`Hkdf` is its `Hmac` and nothing else, so every byte of it must be zero after the drop), `debug_hides_the_prk` and
`throughput`. `cargo test hkdf::` runs them; HMAC's own are above.

PBKDF2's tests are `known_answers` (RFC 6070's vectors for HMAC-SHA-1, without its 16,777,216-iteration case, and
RFC 7914's for HMAC-SHA-256), `wycheproof` (59 of the 298 vectors of Project Wycheproof, all those under 4096 iterations
and one in five of the rest) and `all_hashes_at_the_boundaries` (216 vectors for all eight hashes, from Python's `hashlib`
with Go and OpenSSL agreeing: passwords and salts at the block boundaries, keys around multiples of the hash's output,
1 to 1000 iterations; both files are read from `testdata/vectors.txt`), `block_counter` (65,538 blocks, so that a counter of
one byte, 16 bits or the wrong byte order fails), `benchmark_inputs_have_the_known_answers` (the first step of the chains
that `throughput` and `bench/pbkdf2cmp` time), `invalid_inputs_are_refused`, `the_longest_key_is_two_to_the_32_minus_one_blocks`
(on the numbers: no test can allocate it), `errors_say_what_went_wrong` and `throughput`. `cargo test pbkdf2::` runs them;
HMAC's own are above.

Rand's tests are `fill_writes_every_byte_and_only_those` (lengths from 0 to 65,537, with guard bytes on both sides),
`the_whole_of_a_large_buffer_is_filled`, `what_comes_out_looks_random` (chi-square and bit balance on a megabyte),
`no_two_draws_are_alike` and `threads_do_not_share_their_bytes`, `the_reader_fills_what_it_is_given` and
`the_reader_feeds_the_keys_of_the_crate`, `encode_maps_a_byte_to_the_character_of_its_low_five_bits` and
`text_is_26_characters_of_the_alphabet`, `below_agrees_with_the_known_answers` (the `BELOW` table, which `bench/randcmp`
replays), `below_a_bound_of_one_reads_nothing`, `below_fails_when_the_source_does`,
`below_gives_up_on_a_source_that_never_gives_a_number` (the 128th draw is the last, exactly), `a_zero_bound_is_a_mistake`,
`below_is_uniform` and `throughput`; in `sys.rs` the tests of the fill loop (short writes, interruptions, an empty
buffer, errors, an answer of zero or of too many bytes), `the_device_fills_a_buffer`, and on Linux
`a_kernel_without_the_call_falls_back_to_the_device`, `any_other_failure_is_the_callers` and `enosys_is_unsupported`.
`cargo test rand::` runs them. The fall back to `/dev/urandom` itself was also run once under a seccomp filter that makes
`getrandom` fail with `ENOSYS` (and, to see that the filter bites, with `EPERM`, when the tests fail): `docker run
--security-opt seccomp=<profile>` on a test binary built beforehand, because `cargo` itself needs the call.

RC4's tests are `rfc_6229` (the RFC's 252 vectors, from `testdata/rfc6229.txt`), `known_answers` (the vectors of the
posting of 1994 and the examples of Wikipedia), `every_key_length` (a SHA-256 of the keystream under each key of 1 to 256
bytes, from Go and a Python implementation that agree), `pieces_match_the_whole` (the indices must be carried from one
call to the next), `xor_keystream_leaves_the_source_alone` and `xor_keystream_needs_equal_lengths`, `key_length_limits`,
`dropping_wipes_the_state`, `debug_hides_the_state` and `throughput`. `cargo test rc4::` runs them.

RSA's tests are, in `conformance.rs`, `wycheproof_oaep`, `wycheproof_pkcs1_decrypt`, `wycheproof_pkcs1_sign`,
`wycheproof_pkcs1_verify` and `wycheproof_pss` (the selection of Project Wycheproof's vectors in `testdata/wycheproof.txt`,
with `every_vector` to run all of them), `oaep_rsa_laboratories` and `pss_rsa_laboratories` (RSA Laboratories' vectors,
reproduced bit for bit from their seeds and salts), `openssl_made` (315 ciphertexts and signatures, on keys of seven
sizes), `det_keygen_1` to `det_keygen_3` and `det_keygen_large` (the vectors of c2sp.org/det-keygen); in `keypair.rs`,
`a_key_gives_back_its_components`, `public_keys_are_checked`, `private_keys_are_checked`, `every_scheme_round_trips`,
`every_hash_signs`, `messages_that_do_not_fit`, `a_failing_random_source_is_reported`, `bad_ciphertexts_are_all_the_same_error`,
`bad_signatures_are_all_the_same_error`, `the_session_key_function_keeps_the_key_unless_the_message_is_its_length`,
`a_signature_without_its_leading_zero_byte_is_refused`, `a_pss_signature_of_a_block_one_byte_too_long_is_refused`,
`primes_of_very_different_sizes_work`, `a_faulty_computation_releases_nothing`,
`the_private_operation_does_the_same_work_for_any_input`, `keys_compare_clone_and_hide_their_secrets`,
`dropping_wipes_the_private_key`, `throughput` and the ignored `timing_does_not_depend_on_the_input`; in `keygen.rs`, the small
primes, the rounds of Miller-Rabin (`a_candidate_gets_the_rounds_of_its_size`, `a_round_of_miller_rabin_is_the_strong_test`,
`bases_are_drawn_from_2_to_w_minus_2`), the shape of a candidate, the small arithmetic against `u128`, primality of known numbers,
`the_benchmark_candidates_hold_two_primes` and `the_benchmark_candidates_make_this_key`, the retries
(`generation_draws_again_when_the_primes_are_no_good`), `generation_refuses_the_same_prime_twice`, sources that run dry,
keys of odd sizes and `generation_leaves_nothing_behind`; in `bigmod.rs`, the arithmetic against Python's integers
(`modular_arithmetic_matches_python`, `remainder_matches_python`) and `dropping_wipes_the_limbs`; and the tests of the
paddings in `oaep.rs`, `pss.rs`, `pkcs1v15.rs` and `mgf1.rs`. `cargo test rsa::` runs them. The tests that find numbers in
freed memory use an allocator that counts the words of a block that equal a number being watched (`testutil::probe`), with
a control that finds them in memory that is not wiped.

HPKE's tests are `rfc9180_appendix_a` (every suite of Appendix A in scope, A.1, A.3, A.4, A.6 and A.7, in the four
modes, which the script that wrote `vectors.rs` compared with the RFC's text) and `cfrg_vectors` (the rest of RFC 9180's
file in scope), which also check the KEM's shared secret and the outputs of the key schedule; `go_accumulated` (Go's own
vectors, a thousand messages and a thousand exports each); `opens_what_go_sealed` and `seals_what_go_opens` (36 suites
each way, with `bench/hpkecmp` on the other side); `every_change_fails_to_open`, `messages_open_only_in_order`,
`sequence_number_limit`, `invalid_psk_inputs`, `x25519_small_order_keys_are_rejected`,
`nist_invalid_public_keys_are_rejected`, `invalid_private_keys_are_rejected`, `keys_of_another_kem_are_refused`,
`input_keying_material_lengths`, `export_lengths`, `unsupported_algorithms`, `debug_hides_the_secrets` and
`throughput`; HKDF's and HMAC's own are above. AES-GCM's are
`gcm::aead::tests::known_answers`, `many_lengths` and `long_messages` (on every GHASH backend), `any_change_fails_to_open`,
`length_limits` and `throughput`, `gcm::ghash::tests::matches_scalar_backend`, `unaligned_input` and
`dropping_wipes_the_powers`, and `gcm::scalar::tests::multiplication_matches_algorithm_1` and `dropping_wipes_the_key`.
`cargo test -- hpke:: gcm::` runs both.

ML-DSA's tests are `accumulated_100` (the known answers of C2SP's CCTV, with `accumulated_10000` to run on demand),
`conformance::acvp_selection` and `wycheproof_selection` (the selections of NIST's and Wycheproof's vectors, which
`conformance::every_vector` runs in full from `MLDSA_VECTORS`), `rejection_loop` (NIST's 27 known answers for the loop,
with the rejections counted), `modes_agree`, `context`, `prehash`, `what_is_signed` (`M'` written out for both kinds),
`message_lengths`, `tampering`, `encodings_are_checked`, `a_failing_reader_is_reported`, `generate_reads_the_seed`,
`keys_compare_clone_and_hide_their_secrets`, `dropping_a_key_wipes_it` and `the_secret_vectors_are_wiped`,
`algorithm::tests::the_bounds_of_the_checks`, and, under them, each part against its definition: `field::tests::*` (the
transform against a schoolbook product, the reductions over their ranges, the bounds of the intermediate values),
`rounding::tests::*` (every number modulo `q`), `sample::tests::*`, `pack::tests::*` (every width, and every hint
encoding that is not canonical), `prehash::tests::*` and `params::tests::*`, with `sha3::xof::tests::*` for the streaming
SHAKE. `cargo test -- mldsa:: sha3::xof` runs all of them.

ML-KEM's tests are `accumulated_100` (the "accumulated" known answers of Go's `crypto/mlkem`, for all three sets, with
the values from Go and OpenSSL; `accumulated_10000` runs C2SP's on demand), `conformance::acvp_selection`,
`wycheproof_selection` and `cctv_unlucky_vectors` (the selections of NIST's, Wycheproof's and C2SP's vectors, which
`conformance::every_vector` runs in full from `MLKEM_VECTORS`), `a_key_exchange`, `the_reader_gives_the_message`,
`a_failing_reader_is_reported`, `implicit_rejection`, `encodings_are_checked`, `keys_compare_clone_and_hide_their_secrets`,
`dropping_a_key_wipes_it`, `dropping_a_shared_secret_wipes_it`, `the_secret_vector_is_wiped`,
`the_benchmark_inputs_have_the_answers_of_go_and_openssl`, and, under them, each part against its definition:
`field::tests::*` (the transform, its inverse and the product of `T_q` against FIPS 203 written out and against the product of
polynomials by the definition, the tables of appendix A, the reductions over their ranges, the bounds of the intermediate
values), `pack::tests::*` (`Compress` and `Decompress` for every number modulo `q`, the packing against the bit strings of the
specification, the modulus check), `sample::tests::*`, `algorithm::tests::*` (K-PKE round trips, the encoding of the key,
the ranges of what key generation makes), `params::tests::sizes_are_those_of_fips_203` and `error::tests::*`, with
`sha3::xof::tests::*` for the streaming SHAKE. `cargo test -- mlkem:: sha3::xof` runs all of them. Each test that does not read a
published vector was checked against a set of 88 mutants of the code (see `docs/mlkem.md`): it is either the written-out
definition of a part, or the only one to fail for some change.

A cipher with a single implementation has no backend to compare, so `src/des/` swaps
`scalar_known_answers`, `matches_scalar_backend` and `unaligned_input` for
`matches_reference`: a second DES, written for the tests only in `reference.rs`, as
literally as the text of the standard, against which the round keys and the blocks of
the real one are compared. It adds `triple_des_is_three_des` (the single-block path of
TDEA against three DES operations in a row) and `parity_bits_are_ignored`.

Where an algorithm has no externally generated boundary vectors (MD5 and SHA-1
do not yet), a second, independently written padding routine stands in for
them, as in `reference_digest`. Where it has them, that routine is redundant.

A test earns its place by failing when something breaks that no other test
would notice. Before adding one that compares the public API with the scalar
backend, or re-checks output lengths or hex formatting, check that the known
answers do not already fail for the same bug. The way to check is to break the
code it guards in a scratch copy (flip a rotation amount, a constant or the
padding byte) and see which tests fail.

## Pull requests

- Keep PRs focused on a single algorithm or change where possible.
- Make sure `make fmt-check lint check test` passes locally before pushing.
- Describe what the change implements/fixes and reference the relevant spec
  or RFC in the PR description.

## Reporting security issues

This library is a from-scratch cryptography implementation; please report
suspected vulnerabilities privately rather than opening a public issue.
Contact the maintainer through GitHub.
