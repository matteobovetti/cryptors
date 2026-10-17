# HKDF

HKDF ([RFC 5869](https://www.rfc-editor.org/info/rfc5869)) turns a secret that is not yet fit to be a key, such as an
[ECDH](ecdh.md) shared secret, into as many keys as a protocol needs, each bound to its purpose. TLS 1.3, QUIC, HPKE and
Signal use it. `Hkdf<D>` is built on the crate's [HMAC](hmac.md) and is generic over any `D: Digest`; it implements
neither `Digest` nor `BlockCipher`.

Two steps, Extract once per secret and Expand once per key (HashLen is the hash's output length):

- **Extract**: `PRK = HMAC(salt, IKM)`, HashLen bytes. The salt is optional and not secret; no salt means HashLen zero
  bytes, the same as an empty salt.
- **Expand**: `T(i) = HMAC(PRK, T(i - 1) | info | i)` from an empty `T(0)`, cut to the requested length. `info` names
  the output's purpose. `i` is one byte, so output is at most 255 blocks.

| Hash | `D` | HashLen | Block | Longest output (255 × HashLen) |
|------|-----|---------|-------|--------------------------------|
| MD5 | `Md5` | 16 bytes | 64 bytes | 4080 bytes |
| SHA-1 | `Sha1` | 20 bytes | 64 bytes | 5100 bytes |
| SHA-224 | `Sha224` | 28 bytes | 64 bytes | 7140 bytes |
| SHA-256 | `Sha256` | 32 bytes | 64 bytes | 8160 bytes |
| SHA-384 | `Sha384` | 48 bytes | 128 bytes | 12240 bytes |
| SHA-512 | `Sha512` | 64 bytes | 128 bytes | 16320 bytes |
| SHA-512/224 | `Sha512_224` | 28 bytes | 128 bytes | 7140 bytes |
| SHA-512/256 | `Sha512_256` | 32 bytes | 128 bytes | 8160 bytes |

No HKDF-SHA3: SHA-3 is not on `Digest` yet (see [SHA-3](sha3.md)).

## Usage

```rust
use cryptors::hkdf::{Error, Hkdf};
use cryptors::sha2::Sha256;

// RFC 5869, Appendix A.1.
let ikm = [0x0b; 22];
let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

// One call: Extract, then Expand into the buffer.
let mut okm = [0; 42];
Hkdf::<Sha256>::derive(&salt, &ikm, &info, &mut okm).unwrap();
assert_eq!(okm[..8], [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a]);

// Or extract once, then expand one key per purpose.
let hkdf = Hkdf::<Sha256>::extract(&salt, &ikm);
let mut client = [0; 16];
let mut server = [0; 16];
hkdf.expand(b"client write key", &mut client).unwrap();
hkdf.expand(b"server write key", &mut server).unwrap();
assert_ne!(client, server);

// An already uniformly random key of at least HashLen bytes can skip Extract.
let next = Hkdf::<Sha256>::from_prk(&okm[..32]).unwrap();
assert!(matches!(Hkdf::<Sha256>::from_prk(&okm[..31]), Err(Error::InvalidPrkLength)));

// More than 255 blocks is an error, not a panic; the buffer is left untouched.
let mut too_long = vec![0; Hkdf::<Sha256>::MAX_OUTPUT_LEN + 1];
assert_eq!(next.expand(b"", &mut too_long), Err(Error::InvalidLength));
```

`examples/hkdf.rs` checks the vector above, then derives one key per direction from an X25519 exchange, with both public
keys in `info`: `cargo run --release --example hkdf`.

## Security

HKDF is not broken: it relies on HMAC being a PRF and has its own analysis (Krawczyk, CRYPTO 2010). MD5 and SHA-1 are
for older protocols only; their collisions do not break HMAC, but do not pick them for new designs. Grover's algorithm at
most halves a key's security (128 of SHA-256's 256 bits).

- **Use a salt if you have one.** It is not secret and can be reused, but must not be attacker-chosen or depend on the
  IKM (section 3.4); HashLen random bytes is ideal. No salt is still sound, with weaker guarantees (section 3.1).
- **Extract secrets, expand keys.** Non-uniform secrets (Diffie-Hellman outputs above all) must go through `extract`.
  Skip it only for a key that is already uniformly random (section 3.3); `from_prk` rejects one shorter than HashLen
  (`Error::InvalidPrkLength`).
- **Bind each key with `info`.** Different `info` gives independent keys. After a key exchange, put both public keys in
  `info` (or the salt), per RFC 7748, section 6.1. `info` must not depend on the IKM (section 3.2).
- **Length does not separate keys.** With the same PRK and `info`, a shorter output is a prefix of a longer one. The
  maximum is 255 × HashLen bytes; more returns `Error::InvalidLength` and writes nothing. Empty output is allowed.
- **Not for passwords.** HKDF adds no work factor; use a password-based KDF such as [PBKDF2](pbkdf2.md).
- **Zeroization is best effort.** The PRK (held as an HMAC key) and HMAC's padded-key copies are zeroed on drop, and
  `Debug` does not print them. Not wiped: the hash functions' stack values, the returned digests (including output
  blocks), copies left by moving an `Hkdf`, and the caller's output buffer.
- **Constant time, unverified.** Control flow and memory addresses depend only on input and output lengths, never on a
  secret. Unlike ECDH, the compiled code has not been inspected and no timing measurement backs this.

## Testing

```sh
cargo test hkdf::   # RFC 5869, and vectors from Go and OpenSSL for all eight hashes
```

- **RFC 5869 Appendix A**: all seven cases (SHA-256 and SHA-1), run through `extract`, `expand`, `derive` and `from_prk`.
- **Go `crypto/hkdf` and OpenSSL 3.6**, agreeing, for all eight hashes:
  - salts and `from_prk` keys around one block (HashLen, one block, one block + 1);
  - the 255-block limit: longest output, one byte over (refused, nothing written), and prefixes ending at the first and
    last block edges, down to empty;
  - 1000-byte IKM and `info` for SHA-256 and SHA-512.
- **API**: empty salt gives a PRK of HashLen zeros, `from_prk` length bounds, drop zeroes the whole `Hkdf`, `Debug`
  shows no secret.
- **Mutation check**: 11 deliberate breaks of `src/hkdf/kdf.rs` are each caught by at least one test.

HMAC is tested in its own module; see [HMAC](hmac.md).

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release hkdf:: -- --ignored --nocapture --test-threads=1
cd bench/hkdfcmp && go test -v                  # Go's crypto/hkdf, on its crypto/sha256 and crypto/sha512 as shipped
```

Two workloads each for SHA-256 and SHA-512, same inputs on both sides:

- **Long Expand**: RFC 5869 A.1's PRK to the longest output (8160 or 16320 bytes), 4096 times per pass.
- **Short key**: Extract and Expand from a 32-byte secret to a 32-byte key, 200,000 times per pass, each key seeding the
  next.

One warm-up pass, then the best of five timed passes; both sides print the same check bytes. HKDF has no backend of
its own and uses its hash's (FEAT_SHA256 and FEAT_SHA512 here). `-tags purego` is not run; see [SHA-256](sha256.md) and
[SHA-512](sha512.md) for the hashes.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, higher is better:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| HKDF-SHA256, Expand to 8160 bytes | **356 MiB/s** | 247 MiB/s |
| HKDF-SHA256, Extract and Expand to a 32-byte key | **3.10 M/s** | 1.45 M/s |
| HKDF-SHA512, Expand to 16320 bytes | **274 MiB/s** | 221 MiB/s |
| HKDF-SHA512, Extract and Expand to a 32-byte key | **1.28 M/s** | 660 k/s |

Run-to-run spread was within 2%, but the machine was not idle (load average 3 to 5), so the last digit means little.

No x86 figures yet: Rosetta 2 timings say nothing about real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
