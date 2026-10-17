# PBKDF2

PBKDF2 ([RFC 8018](https://www.rfc-editor.org/info/rfc8018), PKCS #5 v2.1) derives a key from a low-entropy password by
repeating a keyed hash as many times as the caller chooses, so each guess costs an attacker as much as it costs the
owner. FIPS 140, WPA2, LUKS1, 1Password and many file formats ask for it when a key comes from a password. It is one
function, [`derive`](#usage), built on the crate's [HMAC](hmac.md) for any `D: Digest`; it implements neither `Digest` nor
`BlockCipher`.

For each block `i` of HashLen bytes of key (HashLen is the hash's output length), with `c` iterations:

- `U(1) = HMAC(password, salt | INT(i))`, where `INT(i)` is the block number as a 32-bit big-endian integer, from 1;
- `U(j) = HMAC(password, U(j - 1))`, for `j` from 2 to `c`;
- `T(i) = U(1) ^ U(2) ^ ... ^ U(c)`; the key is `T(1) | T(2) | ...`, cut to the length asked for.

The salt gives two users with the same password different keys. Each `U(j)` feeds the next, so the chain cannot run in
parallel; the blocks are independent.

| Hash | Call | HashLen | Block | Longest key ((2^32 − 1) × HashLen) |
|------|------|---------|-------|------------------------------------|
| MD5 | `derive::<Md5>` | 16 bytes | 64 bytes | 68,719,476,720 bytes |
| SHA-1 | `derive::<Sha1>` | 20 bytes | 64 bytes | 85,899,345,900 bytes |
| SHA-224 | `derive::<Sha224>` | 28 bytes | 64 bytes | 120,259,084,260 bytes |
| SHA-256 | `derive::<Sha256>` | 32 bytes | 64 bytes | 137,438,953,440 bytes |
| SHA-384 | `derive::<Sha384>` | 48 bytes | 128 bytes | 206,158,430,160 bytes |
| SHA-512 | `derive::<Sha512>` | 64 bytes | 128 bytes | 274,877,906,880 bytes |
| SHA-512/224 | `derive::<Sha512_224>` | 28 bytes | 128 bytes | 120,259,084,260 bytes |
| SHA-512/256 | `derive::<Sha512_256>` | 32 bytes | 128 bytes | 137,438,953,440 bytes |

No PBKDF2-HMAC-SHA3: SHA-3 is not on `Digest` yet (see [SHA-3](sha3.md)).

## Usage

```rust
use cryptors::{pbkdf2::{self, Error}, sha2::Sha256};

// RFC 7914, section 11: 1 iteration of HMAC-SHA-256, 64 bytes of key.
let mut key = [0; 64];
pbkdf2::derive::<Sha256>(b"passwd", b"salt", 1, &mut key).unwrap();
assert_eq!(key[..8], [0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f]);

// A password hash: a random salt, stored with the key and the count, and many iterations.
let salt = [0x42; 16]; // in a program: 16 random bytes, new for each password
let mut stored = [0; 32];
pbkdf2::derive::<Sha256>(b"correct horse", &salt, 600_000, &mut stored).unwrap();

// A shorter key is the start of a longer one, so ask for what you need.
let mut short = [0; 16];
pbkdf2::derive::<Sha256>(b"correct horse", &salt, 600_000, &mut short).unwrap();
assert_eq!(short, stored[..16]);

// No iterations and no key are errors, not panics; the buffer is left untouched.
assert_eq!(pbkdf2::derive::<Sha256>(b"correct horse", &salt, 0, &mut short), Err(Error::InvalidIterations));
assert_eq!(pbkdf2::derive::<Sha256>(b"correct horse", &salt, 1, &mut []), Err(Error::InvalidLength));
```

`derive(password, salt, iterations, &mut key)` takes a password and salt of any length (empty included), a `u32` count,
and the caller's key buffer of one byte to `2^32 - 1` blocks, so nothing is allocated.

`examples/pbkdf2.rs` checks RFC 7914's vector, then enrolls and checks a password as a login does (random salt, 600,000
iterations of HMAC-SHA-256): `cargo run --release --example pbkdf2`.

## Security

PBKDF2 is not broken: it relies on HMAC being a PRF. MD5 and SHA-1 are for older formats only; their collisions do not
break HMAC, but avoid them in new designs. PBKDF2's only defence is the work factor: it needs almost no memory, so it
runs at full speed on a GPU or an ASIC, unlike scrypt (RFC 7914) and Argon2 (RFC 9106). This crate has neither; prefer
them where you can. Where a standard asks for PBKDF2, use HMAC-SHA-256 or HMAC-SHA-512.

- **Use a random salt, new for each password.** It is not secret; store it with the key. RFC 8018 asks for at least 64
  bits (section 4.1), NIST SP 800-132 for at least 128; 16 random bytes are enough.
- **Use as many iterations as you can afford.** RFC 8018's minimum of 1,000 (section 4.2) is far too few today; OWASP's
  password storage guidance, at the time of writing, asks for 600,000 with HMAC-SHA-256 and 210,000 with HMAC-SHA-512.
  Store the count with the salt and raise it as hardware gets faster.
- **Ask for one block.** An attacker needs only the first block to test a guess; the owner pays for all of them. For
  more key material, derive HashLen bytes and expand them with [HKDF](hkdf.md).
- **Long passwords are shortened.** HMAC hashes a key longer than the hash's block (64 bytes, or 128 for SHA-384 and
  SHA-512), so such a password gives the same key as its hash, and two passwords with the same hash share a key.
- **Compare keys without stopping at the first difference.** The crate has no public function for it;
  `examples/pbkdf2.rs` ORs all the differences.
- **Zeroization is best effort.** The password-keyed `Hmac` (worth as much as the password) is overwritten on return.
  Not wiped: the hash functions' stack values, the digests (each `U(j)`), and the caller's password and key buffers.

Control flow and addresses depend only on the lengths and the iteration count, never on a password byte. Unlike ECDH,
neither an inspection of the compiled code nor a timing measurement backs this.

## Testing

```sh
cargo test pbkdf2::   # RFC 6070 and 7914, Wycheproof, and vectors from Python, Go and OpenSSL for all eight hashes
```

- **RFC 6070** (HMAC-SHA-1, without its 16,777,216-iteration case) and **RFC 7914 section 11** (HMAC-SHA-256, with the
  80,000-iteration case).
- **Project Wycheproof**: 59 of its 298 PBKDF2 vectors for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (all those
  under 4096 iterations and one in five of the rest, to keep the debug-build test fast).
- **All eight hashes, 216 vectors** from Python's `hashlib`, reproduced by Go's `crypto/pbkdf2` and OpenSSL 3.6:
  passwords of 0, 1, HashLen, one block, one block + 1 and 2 blocks + 3 bytes; salts on both sides of the point where
  `salt | INT(i)` spills into a second block; keys of 1, HashLen − 1, HashLen, HashLen + 1, 2 × HashLen, 3 × HashLen + 5
  and 300 bytes; 1 to 1000 iterations; NUL bytes in the password and the salt.
- **The block number**: 65,538 blocks (2 MiB of SHA-256, 1.25 MiB of SHA-1) use three of the counter's four bytes, so
  a one-byte, 16-bit or little-endian counter fails, as does one that wraps at 8 or 16 bits.
- **The limits**: zero iterations and an empty key are refused with the buffer untouched; the `2^32 - 1`-block ceiling
  is checked on the numbers, since no test can allocate it.
- **Mutation check**: each of 21 deliberate breaks of `src/pbkdf2/kdf.rs` (a missing or extra iteration, the counter,
  the salt, the password, the XOR, the limits) is caught by at least one test.

HMAC is tested in its own module; see [HMAC](hmac.md).

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release pbkdf2:: -- --ignored --nocapture --test-threads=1
cd bench/pbkdf2cmp && go test -v                # Go's crypto/pbkdf2, on its crypto/sha1, crypto/sha256 and crypto/sha512 as shipped
```

Two workloads each for SHA-1, SHA-256 and SHA-512, same inputs on both sides, each key the password of the next:

- **Password hash**: a key of one hash output, 100,000 iterations, 10 derivations per pass; millions of iterations/s.
- **One iteration**: keying HMAC plus two of its calls, 200,000 derivations per pass; operations per second.

One warm-up pass, best of five timed passes. Both sides print the same last key; the Go side checks known answers first.
PBKDF2 has no backend of its own and uses its hash's (FEAT_SHA1, FEAT_SHA256 and FEAT_SHA512 here), so `-tags purego`
is not run: see [SHA-256](sha256.md) and [SHA-512](sha512.md) for the hashes.

Apple M1 Pro, Go 1.27.1, medians of three interleaved runs, higher is better:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| PBKDF2-HMAC-SHA-1, 100,000 iterations | **13.07 M/s** | 8.88 M/s |
| PBKDF2-HMAC-SHA-256, 100,000 iterations | **12.66 M/s** | 8.93 M/s |
| PBKDF2-HMAC-SHA-512, 100,000 iterations | **4.38 M/s** | 3.64 M/s |
| PBKDF2-HMAC-SHA-1, one iteration | **5.46 M/s** | 2.00 M/s |
| PBKDF2-HMAC-SHA-256, one iteration | **5.80 M/s** | 2.07 M/s |
| PBKDF2-HMAC-SHA-512, one iteration | **2.35 M/s** | 978 k/s |

Run-to-run spread was within 3%, but the machine was not idle (load average 5), so the last digit means little.

- **Many iterations:** 1.2 to 1.5 times Go's rate. Both sides make two compression calls per iteration; cryptors starts
  each from the two states saved by `Hmac::new` and XORs into the caller's buffer (not profiled further).
- **One iteration:** 2.4 to 2.8 times. Setup dominates: keying HMAC and the first two calls, with no allocation here.

No x86 figures yet: Rosetta 2 timings say nothing about real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
