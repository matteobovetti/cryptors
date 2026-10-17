# SHA-1

SHA-1 ([RFC 3174](https://www.rfc-editor.org/info/rfc3174)) hashes a message of up to 2^64 - 1 bits into a 160-bit
(20-byte) digest.

## Usage

```rust
use cryptors::{Digest, sha1::Sha1};

let digest: [u8; 20] = Sha1::digest(b"abc");
assert_eq!(
    Sha1::hex_digest(b"abc"),
    "a9993e364706816aba3e25717850c26c9cd0d89d"
);
assert_eq!(digest[0], 0xa9);
```

## Security

SHA-1 is broken. Practical collisions exist (SHAttered, 2017), and chosen-prefix collisions since 2020, at a cost far
below the 2^80 birthday bound. **Do not** use it for signatures, certificates, password hashing, or anything that needs
collision resistance; use SHA-256 or SHA-3 instead.

## Testing

```sh
cargo test sha1   # known-answer vectors and differential tests against the scalar reference
```

## Benchmarking

```sh
cargo test --release sha1 -- --ignored --nocapture --test-threads=1   # cryptors; names the backend selected on your machine
cd bench/sha1cmp && go test -v                           # the Go stdlib counterpart
```

Apple M1 Pro:

| Workload | cryptors scalar | cryptors accelerated | Go stdlib |
|----------|-----------------|----------------------|-----------|
| One 64 MiB message | ~790 MiB/s | **2143 MiB/s** (FEAT_SHA1) | 2365 MiB/s |

The x86 SHA-NI backend is tested for correctness only, not benchmarked.
