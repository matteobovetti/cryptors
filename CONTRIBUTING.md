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
  lib.rs          one `pub mod` per algorithm, and the re-export of `Digest`
  digest.rs       the `Digest` trait shared by every fixed-output hash
  md5/            one directory per algorithm
  sha1/
  sha2/           a family of functions: one directory per word size
    mod.rs          the family's documentation, `mod sha256; mod sha512;`, re-exports
    sha256/         SHA-224 and SHA-256
    sha512/         SHA-384, SHA-512, SHA-512/224 and SHA-512/256
  sha3/
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

The backend modules are private: users see `cryptors::sha2::Sha256`, never the
path through `sha256`. When several functions share one algorithm, as the six
SHA-2 functions share two, they share a directory. Each word size then has the
anatomy above, and the parent `mod.rs` only documents the family, declares the
children, re-exports their types and holds what both need (`has_bmi`, the x86
BMI1/BMI2 check).

The fixed-output hashes (MD5, SHA-1, SHA-2) are unit types that implement
`Digest`. SHA-3 has not been converted yet and exposes free functions, as its
extendable-output functions do not fit the trait.

Each algorithm in `bench/` is its own Go module with a throughput test that
mirrors the Rust one (same buffer, warm-up and best-of-5 method). The SHA-2 and
SHA-3 ones also split into `impl_asm_test.go` and `impl_purego_test.go`, so that
`-tags purego` selects Go's portable code, the counterpart of our `scalar`
backend. `make bench-go` runs them all, and so does the manual `Benchmarks`
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
- Make a fixed-output hash implement `Digest`.
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
