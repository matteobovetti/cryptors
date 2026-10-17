# AES

AES ([FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)) is a block cipher: a keyed permutation of 128-bit blocks.
The crate provides the FIPS 197 cipher only, one block at a time; modes of operation (CBC, CTR, GCM, ...) are not
included yet. It implements `BlockCipher` rather than `Digest`: the same shape (associated lengths and array types,
static dispatch), but it holds a key. Future cipher modes will be generic over it, as [HMAC](hmac.md) is over `Digest`.

| Cipher | Key | Block | Rounds |
|--------|-----|-------|--------|
| AES-128 | 16 bytes | 16 bytes | 10 |
| AES-192 | 24 bytes | 16 bytes | 12 |
| AES-256 | 32 bytes | 16 bytes | 14 |

## Usage

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

## Security

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

## Testing

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

## Benchmarking

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
