# SHA-3

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

## Usage

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
costs little more than one digest. See [Hardware acceleration](../README.md#hardware-acceleration).

## Security

Not broken: no known collision or preimage attack, and unlike SHA-2's Merkle-Damgard design the sponge is immune to
length extension. Fit for the same uses as SHA-256/SHA-512 (signatures, certificates, integrity checks); use SHAKE
where a construction needs variable-length pseudorandom output.

## Testing

```sh
cargo test sha3   # known-answer vectors and differential tests against the scalar reference
```

## Benchmarking

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
