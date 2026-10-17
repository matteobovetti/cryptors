# AGENTS.md

This file provides guidance to Coding agents when working with code in this repository.

`cryptors` is a zero-dependency, pure-Rust cryptography library (edition 2024, MSRV 1.95). Correctness comes first; implementations are meant to be read and audited. `CONTRIBUTING.md` is detailed and current (per-algorithm file layout, the standard test names, how to add an algorithm) — read it before adding or restructuring anything. Do not add dependencies.

## Commands

```sh
make fmt-check lint check test   # what CI runs (clippy -D warnings): must pass before a PR
make release-checks      # final gate before a release: the above + examples, bench, bench-throughput, bench-go (slow, needs Go)
cargo test sha2::sha512  # one algorithm; test names follow the module path
cargo test -- ecdh:: ec::   # ECDH's tests also live in the shared src/ec layer
cargo test --release sha2::sha512 -- --ignored --nocapture --test-threads=1   # throughput test
make bench-throughput    # all #[ignore]d throughput tests (release, one thread — never run benchmarks in parallel)
make bench-go            # Go stdlib counterparts in bench/<name>cmp (needs Go)
```

CI builds with `RUSTFLAGS=-Dwarnings` on x86_64, aarch64 and a RISC-V (QEMU) target that has no hardware backend, across the five latest stable Rust releases.

## Architecture

- `src/lib.rs` has one `pub mod` per algorithm; `Digest` (fixed-output hashes) and `BlockCipher` (AES, DES) are the only shared public traits. `ec`, `gcm`, `incremental` and `wipe` are private.
- **Backends**: algorithms with hardware paths (hashes, AES, GHASH) have `scalar.rs` (portable, always compiled, the reference) plus `aarch64.rs`/`x86*.rs` backends gated by `cfg(target_arch)` and entered only after runtime feature detection in the `digest.rs`/`cipher.rs` dispatcher. Every backend is tested against `scalar` (`matches_scalar_backend` — name is cited by docs, don't rename).
- **Layered, not flat**: HMAC, HKDF and ECDSA take `D: Digest` and run on the hash's own dispatcher via the private `Incremental` trait (`src/incremental.rs`, reached through the hidden `Digest::INCREMENTAL`). ECDH/ECDSA keys are generic over a sealed `Curve` trait; curve arithmetic is shared in `src/ec/` (Weierstrass curves, plus the Curve25519 field used by X25519 and Ed25519). HPKE composes ECDH + HKDF + `gcm` and selects its suite at run time.
- Anything touching secrets goes through `src/ec/ct.rs` (no branching) and is wiped on drop via `src/wipe.rs`; tests check wiping and that `Debug` hides secrets.
- `bench/<name>cmp/` are separate Go modules that mirror the Rust throughput tests and also re-verify known answers; `-tags purego` is the counterpart of our scalar backend.
- `docs/plans/` holds written performance plans (some unimplemented).

## Conventions

- Test vectors come from the spec / Wycheproof / OpenSSL / Go, not hand-rolled. `vectors.rs` files (e.g. `src/hpke/vectors.rs`) are generated; don't edit by hand.
- A test must fail for something no other test catches; verify by breaking the guarded code in a scratch copy before adding one.
- `unsafe` only where there is no alternative, with a justifying comment (SIMD/intrinsics backends).
- Rust doc comments (`*.rs`) must not mention Go, laptop timings or relative speed claims; benchmark numbers live in `README.md`, `docs/` and `bench/`.
- Keep the README algorithm table and the per-algorithm pages in `docs/<name>.md` in step with the code.
- Source files named like credentials (`key.rs`, `keys.rs`, `private_key*`, `*.pub`, …) are blocked by the repo's permission settings; use names like `keypair.rs`.
