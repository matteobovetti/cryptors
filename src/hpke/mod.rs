//! From-scratch implementation of Hybrid Public Key Encryption (HPKE, RFC
//! 9180): encryption of messages to the holder of a private key, by anyone who
//! knows the public key. A key encapsulation mechanism (KEM) gives the sender
//! and the recipient a shared secret, a key derivation function (KDF) turns it
//! into the keys of an authenticated cipher (AEAD), and the AEAD encrypts the
//! messages. It is the public-key encryption under TLS Encrypted Client Hello,
//! MLS and Oblivious HTTP.
//!
//! | Part | Algorithm | Identifier | Sizes | Built on |
//! |------|-----------|------------|-------|----------|
//! | KEM | DHKEM(P-256, HKDF-SHA256) | `0x0010` | private key 32, public and encapsulated key 65, shared secret 32 bytes | [`ecdh::P256`](crate::ecdh::P256) |
//! | KEM | DHKEM(P-384, HKDF-SHA384) | `0x0011` | 48, 97, 48 bytes | [`ecdh::P384`](crate::ecdh::P384) |
//! | KEM | DHKEM(P-521, HKDF-SHA512) | `0x0012` | 66, 133, 64 bytes | [`ecdh::P521`](crate::ecdh::P521) |
//! | KEM | DHKEM(X25519, HKDF-SHA256) | `0x0020` | 32, 32, 32 bytes | [`ecdh::X25519`](crate::ecdh::X25519) |
//! | KDF | HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 | `0x0001` to `0x0003` | exporter secret 32, 48, 64 bytes | [`hkdf`](crate::hkdf) and [`hmac`](crate::hmac), on [`sha2`](crate::sha2) |
//! | AEAD | AES-128-GCM, AES-256-GCM | `0x0001`, `0x0002` | key 16 or 32, nonce 12, tag 16 bytes | [`aes`](crate::aes), with a GCM private to the crate |
//! | AEAD | export-only | `0xFFFF` | no encryption | |
//!
//! Every combination of the three is a [`Suite`], of a [`Kem`], a [`Kdf`] and
//! an [`Aead`]. The keys are [`PrivateKey`] and [`PublicKey`], which belong to
//! one KEM each. A sender's [`Suite::setup_sender`] gives a [`Sender`], a
//! recipient's [`Suite::setup_recipient`] a [`Recipient`], and the
//! [`SenderMode`] and [`RecipientMode`] they take carry the inputs of the mode.
//! [`Error`] says what failed. Nothing here implements
//! [`Digest`](crate::Digest) or [`BlockCipher`](crate::BlockCipher): HPKE is a
//! protocol built on them, not a primitive. X448, ChaCha20-Poly1305, ML-KEM and
//! the hybrid KEMs are not implemented.
//!
//! # How it works
//!
//! The sender runs the KEM on the recipient's public key `pk_r`: it makes an
//! ephemeral key pair, does a Diffie-Hellman exchange with `pk_r`, and hashes
//! the result with both public keys into a shared secret. The ephemeral public
//! key is the encapsulated key `enc`, which goes to the recipient with the
//! messages. The recipient does the same exchange from the other side, with
//! its private key and `enc`, and gets the same secret. On the NIST curves a
//! public key is an uncompressed point and the Diffie-Hellman output its
//! x-coordinate; on X25519 both are 32 bytes (RFC 9180 section 7.1).
//!
//! Each side then runs the key schedule (section 5.1) on the shared secret, on
//! `info`, a public string that binds the result to its use, and on the inputs
//! of the mode. It gives a context: an AEAD key, a base nonce and an exporter
//! secret. The modes differ in what else goes into it, and so in what the
//! recipient learns about the sender:
//!
//! | Mode | Value | The recipient also learns that the sender holds |
//! |------|-------|-------------------------------------------------|
//! | Base | `0x00` | nothing: anyone with `pk_r` can be the sender |
//! | PSK | `0x01` | a pre-shared key, which goes into the key schedule |
//! | Auth | `0x02` | the private key of a known public key `pk_s`: a second exchange, between the sender's key and `pk_r`, goes into the KEM |
//! | AuthPSK | `0x03` | both |
//!
//! A context carries a sequence of messages one way. [`Sender::seal`]
//! encrypts each under the next nonce, the base nonce XORed with a counter,
//! and [`Recipient::open`] has to take them in the same order; after `2^96 - 1`
//! messages a context refuses to go on. Both sides can also
//! [`export`](Sender::export) secrets of any length up to 255 hash lengths
//! from the context, for a reply or for another protocol. For a single message,
//! [`Suite::seal`] and [`Suite::open`] do the setup and the message in one
//! call.
//!
//! # Using it
//!
//! The recipient makes a key pair with [`Kem::derive_key_pair`] and publishes
//! [`PrivateKey::public_key`]. A sender turns the bytes it has into a
//! [`PublicKey`] with [`PublicKey::from_bytes`], which is where an invalid
//! point is refused, and sets up a context to it; the recipient sets up its own
//! from the `enc` it receives.
//!
//! - **Every secret that HPKE would draw at random comes from the caller.** The
//!   crate has no random number generator. A sender's setup takes `ikm_e`,
//!   from which it derives the ephemeral key pair (`DeriveKeyPair(ikm_e)`, RFC
//!   9180 section 7.1.3): it must be fresh, uniformly random bytes from a
//!   cryptographically secure source, at least
//!   [`Kem::private_key_len`] of them, never used twice or for anything
//!   else. A key pair needs the same, given to `derive_key_pair`, and so does
//!   a pre-shared key, of at least 32 bytes. Nothing else is random, so the same
//!   inputs always give the same `enc` and the same context: that is how the
//!   test vectors of RFC 9180, which publish their `ikmE`, are checked through
//!   [`Suite::setup_sender`] itself, and it is why a repeated `ikm_e` is fatal,
//!   as two contexts would encrypt under the same key and nonces.
//! - **A context is a sequence.** The recipient opens messages in the order
//!   they were sealed, each once; a message that is lost or reordered makes the
//!   context useless, and a failed [`open`](Recipient::open) leaves it
//!   expecting the same message. The types are not `Clone`, because two copies
//!   of a sender would seal two messages under one nonce.
//! - **Base mode says nothing about the sender.** Anyone with the public key
//!   can send. The PSK modes prove a shared key, the Auth modes a private key;
//!   their checks surface as an [`Error::Open`] on the first message, not at
//!   setup.
//! - **A key belongs to one KEM.** A suite refuses keys of another with
//!   [`Error::KemMismatch`]. The KEM can be chosen at run time, from the
//!   identifiers on the wire, with [`Suite::from_ids`].
//!
//! A private key and every secret of a context (the AEAD key, the GHASH key,
//! the base nonce, the exporter secret and the intermediate values of the key
//! schedule) are overwritten with zeros when dropped, and `Debug` does not show
//! them. As for [`ecdh`](crate::ecdh), that is best effort: the working values
//! of the arithmetic, on the stack and in registers while a secret is in use,
//! are not overwritten, nor is the copy that moving a value can leave behind,
//! nor the bytes handed back to the caller (plaintexts, exports, serialized
//! keys).
//!
//! None of the four KEMs resists a large quantum computer, and neither does
//! HPKE with them: the post-quantum KEMs of HPKE (ML-KEM and its hybrids) are
//! not here.
//!
//! # Implementation
//!
//! HPKE itself is a few hundred lines of key schedule over three primitives,
//! and the work is in those:
//!
//! | Part | Implementation |
//! |------|----------------|
//! | KEM | [`ecdh`](crate::ecdh) for the four curves, its validation of public keys and its refusal of the point at infinity; `DeriveKeyPair` by the rejection sampling of RFC 9180 section 7.1.3 on the NIST curves |
//! | KDF | [`hkdf`](crate::hkdf), on [`hmac`](crate::hmac) and the crate's SHA-2: each pseudorandom key is keyed into HMAC once, and every expansion from it reuses that; the hash is chosen once per key schedule, from the suite |
//! | AEAD | AES-GCM private to the crate, on the crate's AES: counter mode and GHASH, 1 KiB at a time |
//!
//! GHASH, the multiplication in GF(2^128) that authenticates every 16 bytes,
//! has three backends picked at run time:
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8 crypto extensions (`aes`: FEAT_AES, which Rust reports together with FEAT_PMULL) | `PMULL`, `PMULL2` |
//! | `x86` | PCLMULQDQ and SSSE3 | `PCLMULQDQ`, `PSHUFB` |
//! | `scalar` | nothing -- always available | integer multiplications of masked operands (BearSSL's `ctmul64`) |
//!
//! The hardware backends multiply sixteen blocks by `H^16` down to `H` and
//! reduce once, so that the multiplications do not wait on a reduction between
//! blocks; `scalar` multiplies one block at a time, and is 23 times slower on
//! an Apple M1 Pro.
//!
//! ## Trust
//!
//! The tests check every in-scope vector of RFC 9180's test-vector file, 72 of
//! them over three KEMs (the file has none for P-384), and through them the
//! values that Appendix A prints for its suites A.1, A.3, A.4, A.6 and A.7,
//! which were compared with the RFC's text. They add Go's own vectors (a
//! thousand messages and a thousand exports per suite), and interoperation with
//! Go's `crypto/hpke` both ways in all 36 suites the two have in common,
//! P-384 and HKDF-SHA384 included. GHASH's backends are checked against
//! `scalar`, and `scalar` against the bit-by-bit algorithm of NIST SP 800-38D;
//! AES-GCM against the test cases of its specification and values from Go.
//! ECDH, HKDF and HMAC have their own tests, Wycheproof's among ECDH's.
//!
//! ## Side channels
//!
//! No secret is used as a memory address or as a branch condition, in HPKE's
//! own code or in the primitives: ECDH's arithmetic is written that way (see
//! its documentation, and what checks that claim and what does not), GHASH
//! multiplies with instructions that take the same time for every operand or,
//! in `scalar`, with integer multiplications instead of tables, and tags are
//! compared in constant time. The exceptions are of two kinds. AES runs on the
//! crate's [`aes`](crate::aes), whose scalar backend, the one on CPUs without
//! AES instructions, does look up tables at secret positions. And
//! `DeriveKeyPair` on a NIST curve tries again when a candidate is out of
//! range, which takes longer, but a rejection is rare (about 2^-32 for P-256,
//! far less for the others) and says nothing about the key finally derived.
//!
//! # Example
//!
//! ```
//! use cryptors::hpke::{Aead, Kdf, Kem, PublicKey, RecipientMode, SenderMode, Suite};
//!
//! // The recipient makes a key pair and publishes its public key. In real use
//! // the input comes from a cryptographically secure random source.
//! let suite = Suite::new(Kem::P256HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
//! let sk_r = Kem::P256HkdfSha256.derive_key_pair(&[0x11; 32])?;
//! let published = sk_r.public_key().as_bytes().to_vec();
//!
//! // The sender receives the bytes (this is where an invalid point is refused),
//! // and seals two messages, with fresh random bytes for the setup.
//! let pk_r = PublicKey::from_bytes(Kem::P256HkdfSha256, &published)?;
//! let (enc, mut sender) = suite.setup_sender(&pk_r, b"example v1", SenderMode::Base, &[0x22; 32])?;
//! let first = sender.seal(b"message 1", b"attack at dawn")?;
//! let second = sender.seal(b"message 2", b"bring coffee")?;
//!
//! // The recipient, from `enc` and the same `info`, opens them in order.
//! let mut recipient = suite.setup_recipient(&enc, &sk_r, b"example v1", RecipientMode::Base)?;
//! assert_eq!(recipient.open(b"message 1", &first)?, b"attack at dawn");
//! assert_eq!(recipient.open(b"message 2", &second)?, b"bring coffee");
//! assert_eq!(sender.export(b"reply key", 16)?, recipient.export(b"reply key", 16)?);
//!
//! // One message in the PSK mode, with the single-shot functions and X25519.
//! let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes256Gcm);
//! let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&[0x33; 32])?;
//! let (psk, psk_id) = (&[0x44; 32][..], &b"key 7"[..]);
//! let (enc, ct) = suite.seal(sk_r.public_key(), b"", b"", b"hi", SenderMode::Psk { psk, psk_id }, &[0x55; 32])?;
//! let pt = suite.open(&enc, &sk_r, b"", b"", &ct, RecipientMode::Psk { psk, psk_id })?;
//! assert_eq!(pt, b"hi");
//!
//! // Opened with another PSK, it fails, as it would if anything else changed.
//! let wrong = RecipientMode::Psk { psk: &[0x45; 32], psk_id };
//! assert!(suite.open(&enc, &sk_r, b"", b"", &ct, wrong).is_err());
//! # Ok::<(), cryptors::hpke::Error>(())
//! ```
//!
//! `examples/hpke.rs` runs every KEM in every mode, with keys and entropy read
//! from `/dev/urandom`: `cargo run --release --example hpke`.

mod context;
mod error;
mod kem;
mod secret;
mod suite;

pub use context::{Mode, Recipient, RecipientMode, Sender, SenderMode};
pub use error::Error;
pub use kem::{PrivateKey, PublicKey};
pub use suite::{Aead, Kdf, Kem, Suite};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;
