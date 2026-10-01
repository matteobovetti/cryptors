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
| `make audit` | Audit dependencies for known vulnerabilities |
| `make clean` | Remove build artifacts |
| `make all` | Run `fmt`, `check`, `lint`, and `test` |
| `make ci` | Run `fmt-check`, `lint`, `check`, and `test` (used in CI) |

Run `make ci` before opening a pull request — it's the same set of checks CI
runs, and it must pass cleanly.

## Adding or implementing an algorithm

Each algorithm lives in its own module under `src/` (see `src/md5.rs` for the
reference shape) and is declared in `src/lib.rs`. When implementing one:

- Cite the governing spec in a module-level doc comment (e.g. `RFC 1321`,
  `FIPS 197`), the same way `src/md5.rs` does.
- If the primitive is broken or unsuitable for new designs (MD5, DES, RC4,
  SHA-1, ...), say so explicitly in the module doc comment.
- Include test vectors from the spec itself, not just hand-rolled inputs.
- Add edge-case tests around boundary conditions specific to the algorithm
  (e.g. block-length boundaries for hash functions).
- Update the algorithm table in `README.md`, moving the status from
  :white_large_square: to :construction: (in progress) or :white_check_mark:
  (implemented).

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

## Pull requests

- Keep PRs focused on a single algorithm or change where possible.
- Make sure `make ci` passes locally before pushing.
- Describe what the change implements/fixes and reference the relevant spec
  or RFC in the PR description.

## Reporting security issues

This library is a from-scratch cryptography implementation; please report
suspected vulnerabilities privately rather than opening a public issue.
Contact the maintainer through GitHub.
