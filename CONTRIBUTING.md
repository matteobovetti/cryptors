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
| `make bench` | Run benchmarks |
| `make bench-throughput` | Run the `#[ignore]`d throughput tests in release mode, one thread |
| `make bench-go` | Run the Go standard-library counterparts in `bench/` (needs Go) |
| `make audit` | Audit dependencies for known vulnerabilities |
| `make clean` | Remove build artifacts |
| `make all` | Run `fmt`, `check`, `lint`, and `test` |
| `make ci` | Run `fmt-check`, `lint`, `check`, and `test` (used in CI) |

Run `make ci` before opening a pull request — it's the same set of checks CI
runs, and it must pass cleanly.

## Repository layout

```text
src/
  lib.rs          one `pub mod` per algorithm, and the re-export of `Digest` and `BlockCipher`
  digest.rs       the `Digest` trait shared by every fixed-output hash
  block_cipher.rs the `BlockCipher` trait shared by every block cipher
  aes/            one directory per algorithm
  des/            DES and Triple DES: a block cipher with one implementation, `scalar`
  ec/             the arithmetic of the NIST curves that ECDH and ECDSA share (private; they re-export its curve types)
  ecdh/           key agreement over P-256, P-384, P-521 and X25519: keys generic over the curve
  ecdsa/          signatures over P-224, P-256, P-384 and P-521: keys and signatures generic over the curve
  md5/
  sha1/
  sha2/           a family of functions: one directory per word size
    mod.rs          the family's documentation, `mod sha256; mod sha512;`, re-exports
    sha256/         SHA-224 and SHA-256
    sha512/         SHA-384, SHA-512, SHA-512/224 and SHA-512/256
  sha3/
  wipe.rs         overwrites a secret with zeros, in a way the compiler may not remove
bench/
  <name>cmp/      the Go standard-library counterpart of one algorithm
```

Inside an algorithm's directory (`src/sha1/` is a compact example,
`src/sha2/sha256/` the one with the most backends):

| File | Holds |
|------|-------|
| `mod.rs` | The module documentation shown on docs.rs (`//!`, with an example that doubles as a doctest), the `mod` declarations, and the `pub use` of the public types. `md5` and `sha3` also keep here the round macros that their backends share. |
| `digest.rs` | The public types or functions, the specification's constants, the runtime backend dispatcher, and the unit tests: known answers, differential tests against `scalar`, and the `#[ignore]`d throughput test. |
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

The files of `src/ecdh/`, from the API down:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the curves and the error. |
| `curve.rs` | `Curve`, the public half of the trait (the names and sizes), the private half it requires, which does the work on byte strings, and `Error`. |
| `keypair.rs` | `PrivateKey`, `PublicKey`, `SharedSecret`, and the tests of the API: known answers, Wycheproof, invalid keys, `generate`, the chained exchanges, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `nist.rs`, `x25519.rs` | One curve family each: its implementation of the private half of `Curve` (and, for X25519, the types and constants). |
| `fe25519.rs` | The field of X25519, in five limbs of 51 bits. |
| `vectors.rs` | Test data only (`#[cfg(test)]`): known answers, the Wycheproof selection and the chained exchanges' results. |

And those of `src/ecdsa/`:

| File | Holds |
|------|-------|
| `mod.rs` | The documentation, the `mod` declarations and the `pub use` of the keys, the signature, the curves and the error. |
| `curve.rs` | `Curve`, its private half (which also lists what a source of per-message secrets does) and `Error`. |
| `keypair.rs` | `PrivateKey` and `PublicKey` with the four ways to sign and the two to verify, and the tests of the API: RFC 6979, Wycheproof, CAVP, the hedged and the chained signatures, the vectors for key generation, invalid keys and signatures, `generate`, wiping, `Debug` and the `#[ignore]`d `throughput`. |
| `signature.rs`, `der.rs` | `Signature` with its two encodings, and the strict DER reader and writer under it. |
| `algorithm.rs` | Signing and verifying as FIPS 186-5 writes them, on any curve of `src/ec/`; the tests of the digest rules and of the branch that a random nonce never reaches. |
| `hmac_drbg.rs` | A private HMAC and the HMAC_DRBG (SP 800-90A) that makes the per-message secrets, until the crate has a public HMAC; its tests check it against RFC 6979 and against Python's `hmac`. |
| `nist.rs` | The implementation of the private half of `Curve` for the four curves. |
| `vectors.rs` | Test data only: RFC 6979, c2sp's key generation vectors, a selection of CAVP and of Wycheproof, the signatures of another implementation, and the chains. |

The backend modules are private: users see `cryptors::sha2::Sha256`, never the
path through `sha256`. When several functions share one algorithm, as the six
SHA-2 functions share two, they share a directory. Each word size then has the
anatomy above, and the parent `mod.rs` only documents the family, declares the
children, re-exports their types and holds what both need (`has_bmi`, the x86
BMI1/BMI2 check).

The fixed-output hashes (MD5, SHA-1, SHA-2) are unit types that implement
`Digest`. SHA-3 has not been converted yet and exposes free functions, as its
extendable-output functions do not fit the trait. The block ciphers (AES, DES) implement
`BlockCipher` instead, and are not unit types: a cipher holds the key schedule it
was built with. ECDH and ECDSA implement neither: their curves are unit types, but they only
name the curve that a `PrivateKey<C>`, a `PublicKey<C>` or a `Signature<C>` belongs to. ECDSA takes the hash as
a type parameter, `D: Digest`, of the functions that sign and verify a message.

Each algorithm in `bench/` is its own Go module with a throughput test that
mirrors the Rust one (same buffer, warm-up and best-of-5 method). The AES, ECDH, ECDSA, SHA-2
and SHA-3 ones also split into `impl_asm_test.go` and `impl_purego_test.go`, so that
`-tags purego` selects Go's portable code, the counterpart of our `scalar`
backend (of our one implementation, for ECDH and ECDSA). (`descmp` does not split: Go's
`crypto/des` is portable code on every platform, so it has one run.) The ECDH
one also checks its inputs, with the NIST and RFC 7748 vectors and with the
chained exchanges of `src/ecdh/keypair.rs`, so a broken build fails instead of
passing as a figure, and the ECDSA one does the same with the signatures of
RFC 6979, the chained signatures of `src/ecdsa/keypair.rs` and the randomized
signatures of `src/ecdsa/vectors.rs`, which Go made. `make bench-go` runs them all, and so does the manual `Benchmarks`
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
- Where Go's standard library has the same algorithm, add its counterpart under
  `bench/<name>cmp/` and to `make bench-go`.
- Update the algorithm table in `README.md`, setting the status to
  Implemented, In progress or Planned, and give the algorithm a section like
  the existing ones.

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
| `matches_scalar_backend` | Every other backend, called directly, against scalar, over lengths that straddle block and padding boundaries. The name is fixed: the README and the module docs cite it. |
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
- Make sure `make ci` passes locally before pushing.
- Describe what the change implements/fixes and reference the relevant spec
  or RFC in the PR description.

## Reporting security issues

This library is a from-scratch cryptography implementation; please report
suspected vulnerabilities privately rather than opening a public issue.
Contact the maintainer through GitHub.
