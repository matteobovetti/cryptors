# HPKE

HPKE (Hybrid Public Key Encryption) encrypts messages to a public key with no prior exchange: a KEM gives both sides a
shared secret, a KDF turns it into AEAD keys, and the AEAD encrypts. TLS Encrypted Client Hello, MLS and Oblivious
HTTP build on it. A protocol rather than a primitive, it implements neither `Digest` nor `BlockCipher`. A `Suite` is a
`Kem`, a `Kdf` and an `Aead`; keys belong to one KEM; a context is a `Sender` or a `Recipient`.

| KEM | Type | Identifier | Private key | Public and encapsulated key | Shared secret | Built on |
|-----|------|------------|-------------|-----------------------------|---------------|----------|
| DHKEM(P-256, HKDF-SHA256) | `Kem::P256HkdfSha256` | `0x0010` | 32 bytes | 65 bytes | 32 bytes | `ecdh::P256` |
| DHKEM(P-384, HKDF-SHA384) | `Kem::P384HkdfSha384` | `0x0011` | 48 bytes | 97 bytes | 48 bytes | `ecdh::P384` |
| DHKEM(P-521, HKDF-SHA512) | `Kem::P521HkdfSha512` | `0x0012` | 66 bytes | 133 bytes | 64 bytes | `ecdh::P521` |
| DHKEM(X25519, HKDF-SHA256) | `Kem::X25519HkdfSha256` | `0x0020` | 32 bytes | 32 bytes | 32 bytes | `ecdh::X25519` |

| KDF or AEAD | Type | Identifier | Sizes | Built on |
|-------------|------|------------|-------|----------|
| HKDF-SHA256 | `Kdf::HkdfSha256` | `0x0001` | 32-byte hash and exporter secret | `hkdf` on `hmac` and `sha2` |
| HKDF-SHA384 | `Kdf::HkdfSha384` | `0x0002` | 48 bytes | the same |
| HKDF-SHA512 | `Kdf::HkdfSha512` | `0x0003` | 64 bytes | the same |
| AES-128-GCM | `Aead::Aes128Gcm` | `0x0001` | 16-byte key, 12-byte nonce, 16-byte tag | `aes`, with an AES-GCM private to the crate |
| AES-256-GCM | `Aead::Aes256Gcm` | `0x0002` | 32-byte key, 12-byte nonce, 16-byte tag | the same |
| Export-only | `Aead::ExportOnly` | `0xFFFF` | no encryption at all, exports only | |

Standards: [RFC 9180](https://www.rfc-editor.org/info/rfc9180) (HPKE), [RFC 5869](https://www.rfc-editor.org/info/rfc5869)
(HKDF), [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) (GCM). Curves are those of [ECDH](ecdh.md); the KDF
is the crate's [HKDF](hkdf.md) on its [HMAC](hmac.md). AES-GCM is internal; the crate has no public modes of operation yet.

- **Suites and modes:** any KEM, KDF and AEAD, in all four modes: Base (sender anonymous), PSK (sender holds a
  pre-shared key), Auth (sender holds a known private key) and AuthPSK (both). Suites are negotiated by identifier, so
  the parts are values, not types: `Suite::from_ids` takes the identifiers, and a key of the wrong KEM is `KemMismatch`
  at run time.
- **Not implemented:** ChaCha20-Poly1305, X448, post-quantum and hybrid KEMs (the crate has [ML-KEM](mlkem.md), but not
  as an HPKE KEM).
- **Keys** are encoded as in ECDH (uncompressed NIST points, 32 bytes for X25519). Public keys and `enc` are validated
  when parsed into a `PublicKey`; the all-zero X25519 secret from a small-order point is refused.
- **Contexts** use a base nonce XORed with a 96-bit counter and stop after `2^96 - 1` messages. Both sides can export
  secrets of up to 255 hash lengths.
- **Randomness comes from the caller**, since the standard library has no stable secure RNG (see [Rand](rand.md)).
  Key pairs come from `Kem::derive_key_pair` on random bytes; every sender setup derives its ephemeral key pair
  from `ikm_e` (RFC 9180, section 7.1.3), which also lets the RFC's vectors be checked through the sender's setup.

## Usage

```rust
use cryptors::hpke::{Aead, Kdf, Kem, PublicKey, RecipientMode, SenderMode, Suite};

fn main() -> Result<(), cryptors::hpke::Error> {
    // The recipient makes a key pair and publishes its public key.
    // In real use the input comes from a cryptographically secure random source.
    let suite = Suite::new(Kem::P256HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let sk_r = Kem::P256HkdfSha256.derive_key_pair(&[0x11; 32])?;
    let published = sk_r.public_key().as_bytes().to_vec();

    // The sender parses the key (invalid points are refused here) and seals two messages.
    let pk_r = PublicKey::from_bytes(Kem::P256HkdfSha256, &published)?;
    let (enc, mut sender) = suite.setup_sender(&pk_r, b"example v1", SenderMode::Base, &[0x22; 32])?;
    let first = sender.seal(b"message 1", b"attack at dawn")?;
    let second = sender.seal(b"message 2", b"bring coffee")?;

    // The recipient, from `enc` and the same `info`, opens them in order.
    let mut recipient = suite.setup_recipient(&enc, &sk_r, b"example v1", RecipientMode::Base)?;
    assert_eq!(recipient.open(b"message 1", &first)?, b"attack at dawn");
    assert_eq!(recipient.open(b"message 2", &second)?, b"bring coffee");
    assert_eq!(sender.export(b"reply key", 16)?, recipient.export(b"reply key", 16)?);

    // One message in PSK mode, with the single-shot functions and X25519.
    let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes256Gcm);
    let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&[0x33; 32])?;
    let (psk, psk_id) = (&[0x44; 32][..], &b"key 7"[..]);
    let (enc, ct) = suite.seal(sk_r.public_key(), b"", b"", b"hi", SenderMode::Psk { psk, psk_id }, &[0x55; 32])?;
    assert_eq!(suite.open(&enc, &sk_r, b"", b"", &ct, RecipientMode::Psk { psk, psk_id })?, b"hi");
    Ok(())
}
```

Real keys and setups need `Kem::private_key_len` random bytes (the private key size in the table above):

```rust
use cryptors::hpke::Kem;
use std::{fs::File, io::Read};

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any source of secure random bytes will do
let mut ikm = vec![0u8; Kem::P384HkdfSha384.private_key_len()];
rng.read_exact(&mut ikm)?;
let sk_r = Kem::P384HkdfSha384.derive_key_pair(&ikm)?;
// Read fresh bytes the same way for the `ikm_e` of every setup_sender.
```

`examples/hpke.rs` checks one RFC 9180 vector, then runs every KEM in every mode with keys from `/dev/urandom`:
`cargo run --release --example hpke`.

## Security

HPKE is not broken. RFC 9180 (section 9.1) cites proofs of confidentiality against active attackers, and of sender
authentication in the PSK, Auth and AuthPSK modes, given sound parts; none here has a known practical attack. None of
the KEMs resists a large quantum computer.

- **The randomness is the caller's.** `ikm_e` must be fresh, uniformly random, at least `Kem::private_key_len` bytes,
  and used once per sender setup: a repeated one reuses an AES-GCM key and nonce (breaking confidentiality and
  integrity), a guessable one lets anyone decrypt Base and PSK modes. The same goes for `derive_key_pair` input and
  PSKs, which need at least 32 bytes of entropy. A password is not enough: HKDF does not slow guessing, and
  non-key-committing AES-GCM makes it cheaper (RFC 9180, section 9.5). The crate refuses inputs and PSKs shorter than
  32 bytes or than a private key (the RFC only says "should not").
- **A context is a sequence; nonces must never repeat.** Each message is opened once, in order. A failed `open` keeps
  expecting the same message; a lost or reordered one makes the context useless. `Sender` and `Recipient` are not
  `Clone`; a context refuses its `2^96`th message.
- **Base mode authenticates nobody.** PSK modes prove the sender has the PSK, Auth modes a private key. A wrong key, PSK
  or sender shows as `Error::Open` on the first message, not at setup. Auth is open to key-compromise impersonation: the
  recipient's private key can forge messages from any sender (section 9.1.1); sign `(enc, ct)` where that matters.
- **No forward secrecy for the recipient:** a later leak of its private key (plus the PSK, in PSK modes) decrypts every
  past message. The sender side is forward secret.
- **No replay protection, no length hiding.** A message can be delivered to two contexts; a ciphertext is the plaintext
  length plus 16 bytes. `info`, associated data and exporter context bind only what they contain.
- **Constant-time by construction, less verified than ECDH.** No branch or address depends on a secret in HPKE, ECDH's
  arithmetic or GHASH. Hardware GHASH uses constant-time instructions; scalar GHASH uses masked integer multiplies (no
  key tables), relying on constant-time 64-bit multiplication, as on current aarch64 and x86-64 cores. Tags are
  compared in constant time. Known exceptions:
  - AES's scalar backend (CPUs without AES instructions) uses key- and data-dependent table lookups, see [AES](aes.md).
  - `DeriveKeyPair` on a NIST curve takes longer when it rejects a candidate (about 2^-32 on P-256, far less elsewhere);
    this reveals nothing about the final key.
  - Only the aarch64 GHASH loop was inspected in compiled form; no timing measurement backs any of this.
- **Secrets are wiped on drop, best effort.** Private keys and context secrets (AES round keys, GHASH key and powers,
  base nonce, exporter secret, key-schedule intermediates) are zeroed on drop and hidden from `Debug`; a plaintext that
  fails its tag is zeroed before it is freed. Out of reach: stack and register copies, moved-from copies, and bytes
  returned to the caller.

## Testing

```sh
cargo test -- hpke:: gcm::   # RFC 9180's vectors, Go's, interop with Go both ways, the failures, and AES-GCM's backends
```

- **RFC 9180:** the 72 vectors of its test-vector file in this crate's scope, DHKEM(P-256), DHKEM(P-521) and
  DHKEM(X25519) in four modes each (the file has none for P-384 or HKDF-SHA384). They include Appendix A.1, A.3, A.4,
  A.6 and A.7, checked against the RFC text: encryptions at sequence numbers 0, 1, 2, 4, 255 and 256, exports, and KEM
  and key-schedule intermediates.
- **Go:** `crypto/hpke` vectors add 1000 random-length messages and 1000 exports (every length up to 999 bytes) per
  suite. Interop runs both ways over the 36 shared suites (four KEMs, three KDFs, three AEADs), P-384 and HKDF-SHA384
  included; `bench/hpkecmp` opens cryptors' output with Go. Go has Base mode only.
- **Failures:** in each mode, `open` fails after a change to any ciphertext byte, `enc`, associated data, `info`, PSK,
  PSK id, sender key, recipient key or mode, and when opening out of order or twice. Also covered: the `2^96 - 1` limit,
  PSK rules, small-order X25519 points, NIST keys off the curve / compressed / at infinity / wrong length (as public
  keys and as `enc`), invalid private keys, keys of another KEM, short inputs, the export limit, unknown identifiers,
  `Debug`.
- **Building blocks:** AES-GCM against its specification's test cases and Go values for 301 short and 9 long messages,
  on every GHASH backend, with every sealed byte flipped. Each hardware GHASH backend against scalar, around 16-block
  group boundaries and at every alignment. Scalar GHASH against SP 800-38D's bit-by-bit algorithm on dense operands.
  ECDH (with Wycheproof), HKDF and HMAC have their own tests.

The x86-64 GHASH backend passes under Rosetta 2 (PCLMULQDQ) but has not run on an x86 CPU:
`cargo test --target x86_64-apple-darwin -- hpke:: gcm::`.

Mutation check: of 43 deliberate breaks in a scratch copy, all but two failed a test: wiping a plaintext with a bad tag
(not observable) and an export-length check the KDF repeats. `seal` refusing a message over the AES-GCM limit is not
tested (it would take 64 GiB); the limit itself is.

## Benchmarking

```sh
# cryptors: HPKE, then the parts of its AES-GCM alone. One test thread, so the benchmarks don't compete with each other
# for the CPU.
cargo test --release -- hpke:: gcm:: --ignored --nocapture --test-threads=1
cd bench/hpkecmp && go test -v                       # Go's crypto/hpke as shipped, with its assembly
cd bench/hpkecmp && go test -tags purego -v          # Go's portable code, with no assembly
```

Method (both sides, Base mode, same keys, `info` and messages; best of five passes after a warm-up):

- **Setup:** `SetupBaseS` plus `SetupBaseR` with the KEM's own KDF and AES-128-GCM, repeated per pass 1000 times
  (X25519), 400 (P-256), 100 (P-384), 50 (P-521).
- **Seal/open:** 64 MiB as 1024 messages of 64 KiB through one context, DHKEM(X25519), HKDF-SHA256, each AEAD.
- **Cross-check:** Go's ephemeral keys come from `crypto/rand` (included in its setup time), so ciphertexts differ. Both
  sides print a recipient export for a fixed `enc` per KEM; all runs matched.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs. Setup in microseconds (lower is better), messages in MiB/s
(higher is better):

| Workload | cryptors | Go stdlib | Go portable (`purego`) |
|----------|----------|-----------|------------------------|
| Setup, DHKEM(X25519), HKDF-SHA256 | **97.8** | 114.7 | 127.7 |
| Setup, DHKEM(P-256), HKDF-SHA256 | 265.3 | **102.5** | 268.5 |
| Setup, DHKEM(P-384), HKDF-SHA384 | 900.5 | **782.4** | 797.3 |
| Setup, DHKEM(P-521), HKDF-SHA512 | 2301.5 | **2179.6** | 2193.0 |
| Seal, AES-128-GCM | **5613** | 5359 | 97 |
| Open, AES-128-GCM | 5738 | **6318** | 97 |
| Seal, AES-256-GCM | 4676 | **4798** | 87 |
| Open, AES-256-GCM | 4690 | **5320** | 88 |

Run-to-run spread: within 1.2%, except Go's AES-128-GCM seal (3%).

AES-GCM parts alone, same 64 KiB messages (cryptors only):

| Part | MiB/s |
|------|-------|
| GHASH, `aarch64` backend (PMULL) | 13165 |
| GHASH, `scalar` backend (`ctmul64`) | 562 |
| AES-128 in counter mode (FEAT_AES) | 12034 |
| AES-128-GCM seal, `aarch64` GHASH / `scalar` GHASH | 5586 / 530 |
| AES-128-GCM open, `aarch64` GHASH / `scalar` GHASH | 5753 / 537 |

Spread: 0.5% or less, except counter mode alone, where two of five runs came out 10% low.

- **Seal/open** processes each 1 KiB of a message once (copy, encrypt, hash) while it is in L1. Counter mode encrypts
  one block per AES call and GHASH reduces in general-purpose registers: two loops the CPU overlaps only as far as its
  reorder window allows.
- **Setup** is dominated by the KEM (three curve multiplications, eighteen HMAC tags and one AES key expansion per side)
  and follows [ECDH](ecdh.md)'s numbers.

Not done yet, would make it faster:

- One loop running the AES rounds of a group of blocks side by side, then their GHASH.
- GHASH reduction in vector registers (PMULL by the GCM polynomial constant) instead of moving to general-purpose
  registers every 16 blocks.
- A multi-block AES entry point for counter mode. Where AES instructions are not in the target baseline (x86-64, Linux
  on aarch64), counter mode goes through the run-time dispatcher once per block, not inlined.
- For setup, the NIST-curve items listed under ECDH.

No x86 figures yet: Rosetta 2 timings say nothing about x86 CPUs. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners, using PCLMULQDQ and PMULL where
available; there AES is not in the target baseline, so the per-block dispatch above applies.
