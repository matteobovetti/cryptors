# MD5

MD5 ([RFC 1321](https://www.rfc-editor.org/info/rfc1321)) hashes an arbitrary-length message to a 128-bit (16-byte)
digest.

## Usage

```rust
use cryptors::{Digest, md5::Md5};

let digest: [u8; 16] = Md5::digest(b"abc");
assert_eq!(Md5::hex_digest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
assert_eq!(digest[0], 0x90);

// Several independent messages, hashed side by side in SIMD lanes.
let digests: Vec<[u8; 16]> = Md5::digest_many(&[b"abc", b"", b"a longer message"]);
assert_eq!(digests[0], digest);
```

## Security

MD5 is broken. Collisions, including chosen-prefix collisions, take seconds on modern hardware and have been used to
forge CA certificates and signed code. It gives no integrity guarantee against an attacker: do not use it for
signatures, certificates, password hashing, or anything that needs collision resistance. It is acceptable only for
detecting accidental corruption, and even there SHA-256 is preferred.

## Testing

```sh
cargo test md5   # known-answer vectors and differential tests against the scalar reference
```

## Benchmarking

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
