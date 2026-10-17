# HMAC

HMAC turns a hash into a message authentication code: a short tag, computed from a secret key and a message, that
proves the message came from a key holder and was not changed. TLS, IPsec, SSH, JWT (HS256), [HKDF](hkdf.md) and the
HMAC_DRBG of [ECDSA](ecdsa.md) use it. `Hmac<D>` works with any `D: Digest`, holds its key, and implements neither
`Digest` nor `BlockCipher`.

| HMAC with | `D` | Block | Tag | Shortest truncated tag | Hash defined in | Test vectors |
|-----------|-----|-------|-----|------------------------|-----------------|--------------|
| MD5 | `Md5` | 64 bytes | 16 bytes | 10 bytes | [RFC 1321](https://www.rfc-editor.org/info/rfc1321) | [RFC 2202](https://www.rfc-editor.org/info/rfc2202) |
| SHA-1 | `Sha1` | 64 bytes | 20 bytes | 10 bytes | [RFC 3174](https://www.rfc-editor.org/info/rfc3174) | [RFC 2202](https://www.rfc-editor.org/info/rfc2202) |
| SHA-224 | `Sha224` | 64 bytes | 28 bytes | 14 bytes | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | [RFC 4231](https://www.rfc-editor.org/info/rfc4231) |
| SHA-256 | `Sha256` | 64 bytes | 32 bytes | 16 bytes | the same | the same |
| SHA-384 | `Sha384` | 128 bytes | 48 bytes | 24 bytes | the same | the same |
| SHA-512 | `Sha512` | 128 bytes | 64 bytes | 32 bytes | the same | the same |
| SHA-512/224 | `Sha512_224` | 128 bytes | 28 bytes | 14 bytes | the same | none published; Go and OpenSSL, which agree |
| SHA-512/256 | `Sha512_256` | 128 bytes | 32 bytes | 16 bytes | the same | the same |

- Standard: [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final), which adopts
  [RFC 2104](https://www.rfc-editor.org/info/rfc2104): `HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))`.
- No HMAC-SHA3 yet: SHA-3 does not implement `Digest`.
- Keys may have any length, including zero; one longer than a block is hashed first.
- `Hmac::new` hashes both padded keys once and keeps the two states (FIPS 198-1, section 6); each tag then hashes only
  the message and the inner digest.
- `verify` takes only the full tag, `verify_truncated` its leftmost bytes down to the last column above; neither
  accepts an empty tag.

## Usage

```rust
use cryptors::{hmac::{self, Hmac, VerifyError}, sha2::{Sha256, Sha512}};

// RFC 4231, test case 2.
let mac = Hmac::<Sha256>::new(b"Jefe");
let tag: [u8; 32] = mac.mac(b"what do ya want for nothing?");
assert_eq!(tag[..4], [0x5b, 0xdc, 0xc1, 0x46]);

// Constant-time check; never compare tags with `==`.
assert_eq!(mac.verify(b"what do ya want for nothing?", &tag), Ok(()));
assert_eq!(
    mac.verify(b"what do ya want for everything?", &tag),
    Err(VerifyError::Mismatch)
);

// Truncated tags, e.g. IPsec's HMAC-SHA-256-128.
assert_eq!(mac.verify_truncated(b"what do ya want for nothing?", &tag[..16]), Ok(()));

// A message in pieces, never copied into one buffer.
assert_eq!(mac.mac_parts(&[b"what do ya ", b"want for nothing?"]), tag);

// One call, for one message under a key.
let tag: [u8; 64] = hmac::hmac::<Sha512>(b"Jefe", b"what do ya want for nothing?");
assert_eq!(tag[..4], [0x16, 0x4b, 0x7a, 0x7b]);
```

A real key is random bytes from your own source (the standard library has no stable secure one):

```rust
use cryptors::{hmac::Hmac, sha2::Sha256};
use std::{fs::File, io::Read};

let mut key = [0u8; 32];
File::open("/dev/urandom")?.read_exact(&mut key)?;      // on Unix; any io::Read of random bytes will do
let mac = Hmac::<Sha256>::new(&key);
```

`examples/hmac.rs` runs a sender and receiver over all eight hashes and shows a forged tag and a changed message being
refused: `cargo run --release --example hmac`.

## Security

HMAC is not broken with any of these hashes: it needs the compression function to act as a keyed random function, not
collision resistance, so the MD5 and SHA-1 collision attacks do not carry over. Avoid both in new designs anyway: RFC
6151 advises against HMAC-MD5, MD5 was never NIST-approved, and NIST retires SHA-1 by the end of 2030. Use HMAC-SHA-256
or a 64-bit SHA-2. Against a quantum computer (Grover), a 256-bit key keeps about 128 bits.

- **Compare tags with `verify`, never `==`.** `verify` checks every byte; `==` stops at the first difference, letting
  an attacker forge a tag byte by byte.
- **The protocol fixes the tag length.** `verify_truncated` accepts `Hmac::<D>::MIN_TAG_LEN` (half the output, rounded
  up, at least 10 bytes; RFC 2104 section 5) up to the full tag. That clears NIST's 32-bit floor (SP 800-107 Rev. 1,
  section 5.3.3) and covers HMAC-SHA-256-128 (IPsec, RFC 4868) and HMAC-SHA1-80 (SRTP). The length is not
  authenticated: enforce the protocol's, or a forger sends the shortest one accepted.
- **Use a random key at least as long as the tag, not a password.** HMAC is too fast for passwords; derive the key with
  a password hash such as [PBKDF2](pbkdf2.md).
- **Timing depends only on lengths; checked in assembly, never timed on real hardware.** The hashes have no
  data-indexed tables or data branches, the pads are XORs, and the comparison ORs all byte differences and branches
  once on the result (through `core::hint::black_box`, a request, not a guarantee). In `rustc`'s `aarch64` and `x86_64`
  assembly, its only conditional jumps are the loop over the public tag length and the length check before it. No
  protection against power analysis or fault injection. Not hidden (none secret): the key, message and received-tag
  lengths, and whether a tag was refused for its length or its contents.
- **The key lives as long as the `Hmac`.** Both saved states (either lets a forger tag any message), the per-tag states
  and `new`'s padded-key block are zeroed on drop and hidden from `Debug`. Best effort only: the compression functions'
  working values (stack, registers), the digest of a key longer than a block, and copies left by moving an `Hmac` (into
  a `Box` or `Vec`, say) are not wiped, so build it where it will stay if that matters.

## Testing

```sh
cargo test -- hmac:: incremental::   # the RFC vectors, vectors from Go and OpenSSL, verification, and the hashes in pieces
```

- **Known answers:** RFC 4231's seven cases for HMAC-SHA-224/256/384/512 (with long keys and 128-bit truncation) and
  RFC 2202's seven for HMAC-MD5 and HMAC-SHA-1 (with 96-bit truncations), each through `hmac`, `Hmac::mac`, `mac_parts`
  and `verify`, on the streaming path and on the one-shot path used by hashes from outside the crate. ECDSA's RFC 6979
  tests exercise HMAC through HMAC_DRBG.
- **Go and OpenSSL vectors** for all eight hashes (the only source for SHA-512/224 and SHA-512/256), on which Go's
  `crypto/hmac` and OpenSSL 3.6 agree: RFC 4231 inputs, empty key and message, keys of block length -1, 0 and +1, and
  messages on both sides of the inner hash's padding boundary.
- **Hashes in pieces:** each hash's crate-internal incremental form matches the one-shot digest around every block and
  padding boundary up to two blocks (split at every byte, and byte by byte) and for a 100,000-byte message in uneven
  pieces; a copied state continues like the original.
- **Verification:** every tag bit flipped and every length from empty to one byte too long, on `verify` and
  `verify_truncated`; each hash's shortest truncated tag against the policy.
- **Multi-part messages:** split in two at every byte, in three at every pair, one byte per part, and none, on both paths.
- **Wiping:** dropping an `Hmac` or a hash state leaves zeros; `Debug` shows nothing of the key.

Each test was checked by breaking the code it guards in a scratch copy and seeing it fail.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release hmac:: -- --ignored --nocapture --test-threads=1
cd bench/hmaccmp && go test -v                       # Go's crypto/hmac, on Go's hashes as shipped
```

Per hash, same 32-byte key and bytes on both sides, best of five passes after a warm-up: one 64 MiB message and
1,000,000 messages of 64 bytes under one key, each next to the bare hash; then the same messages keyed afresh for each
(`hmac::hmac` here, `hmac.New` in Go), as HKDF does on every call. Both sides print the same tags; the Go side first
checks a known answer per hash.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs. MiB/s for the long message, millions of tags per second for
short ones; higher is better. "One-shot hash" is the earlier design, which copied the padded key and message into one
buffer and called `digest`; hashes from outside the crate still take that path.

| Workload | cryptors | Go stdlib | cryptors, one-shot hash | cryptors, hash alone | Go, hash alone |
|----------|----------|-----------|-------------------------|----------------------|----------------|
| HMAC-SHA-256, one 64 MiB message | **2341** | 2313 | 2100 | 2355 | 2324 |
| HMAC-SHA-512, one 64 MiB message | **1396** | 1377 | 1283 | 1397 | 1377 |
| HMAC-SHA-1, one 64 MiB message | 2202 | **2359** | 1986 | 2195 | 2365 |
| HMAC-MD5, one 64 MiB message | 619 | **637** | 607 | 623 | 637 |
| HMAC-SHA-256, 64-byte messages, keyed once | **9.99** | 7.47 | 7.47 | 20.6 | 12.1 |
| HMAC-SHA-512, 64-byte messages, keyed once | **4.51** | 3.70 | 2.57 | 13.9 | 6.99 |
| HMAC-SHA-1, 64-byte messages, keyed once | **10.22** | 7.46 | 7.04 | 18.7 | 12.7 |
| HMAC-MD5, 64-byte messages, keyed once | **3.38** | 3.01 | 2.05 | 5.22 | 4.69 |
| HMAC-SHA-256, 64-byte messages, keyed for each | **6.08** | 3.25 | 6.26 | | |
| HMAC-SHA-512, 64-byte messages, keyed for each | **2.50** | 1.45 | 2.49 | | |
| HMAC-SHA-1, 64-byte messages, keyed for each | **6.20** | 3.10 | 6.23 | | |
| HMAC-MD5, 64-byte messages, keyed for each | **1.98** | 1.56 | 1.97 | | |

Spread was within about 5% per cell (7% in a few Go cells, 19% for Go's bare SHA-256 on short messages) on a shared,
non-idle desktop, so 2-3% differences are noise. Adding the incremental form left each hash's one-shot speed within
0.4% of before.

- **Long message:** the message is hashed in place, so HMAC runs at hash speed. The one-shot hash lost 9% (SHA-256),
  8% (SHA-1), 6% (SHA-512) and 3% (MD5) to copying and wiping.
- **Short messages, keyed once:** from the two saved states, a 64-byte tag takes three compression calls (two with
  SHA-512's 128-byte block); the one-shot hash re-hashed both padded keys each time (five, or four), so it is
  1.34-1.76x slower.
- **Short messages, keyed for each:** both designs run five compression calls (four with SHA-512), so they are level.
  Building the two states costs at most 3% (SHA-256); `hmac::hmac` consumes its states rather than copying them.
- **Wiping:** one volatile store per byte took 36% of an HMAC-SHA-256 tag (6.53 vs 10.23 M tags/s, medians of three
  interleaved runs); `wipe_bytes`, 16 bytes per store, is within 1.5% of not wiping at all.

Possible speedups, none done:

- **Faster hashes:** faster SHA-1 or MD5 backends speed HMAC up directly.
- **A smaller state:** each holds a 144-byte block (the longest an outside `Digest` may have), though the crate's
  hashes need 64 or 128, and each tag copies and wipes two.
- **A stateless one-call form** for single-use keys, skipping the two states (the 3% in the SHA-256 keyed-for-each row).
- **Batched HMAC-MD5** with the up-to-16-lane `Md5::digest_many` on NEON.

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings say nothing about an x86 CPU. The
manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
