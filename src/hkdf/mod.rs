//! From-scratch implementation of HKDF, the HMAC-based Extract-and-Expand Key
//! Derivation Function (RFC 5869): it takes a secret that is not fit to be a
//! key yet, such as the shared secret of a Diffie-Hellman exchange, and turns
//! it into as many keys as a protocol needs, each bound to what it is for. It
//! works with every hash of the crate that implements
//! [`Digest`](crate::Digest).
//!
//! | Hash | Type | HashLen | Block | Longest output (255 × HashLen) |
//! |------|------|---------|-------|--------------------------------|
//! | MD5 | `Hkdf<Md5>` | 16 bytes | 64 bytes | 4080 bytes |
//! | SHA-1 | `Hkdf<Sha1>` | 20 bytes | 64 bytes | 5100 bytes |
//! | SHA-224 | `Hkdf<Sha224>` | 28 bytes | 64 bytes | 7140 bytes |
//! | SHA-256 | `Hkdf<Sha256>` | 32 bytes | 64 bytes | 8160 bytes |
//! | SHA-384 | `Hkdf<Sha384>` | 48 bytes | 128 bytes | 12240 bytes |
//! | SHA-512 | `Hkdf<Sha512>` | 64 bytes | 128 bytes | 16320 bytes |
//! | SHA-512/224 | `Hkdf<Sha512_224>` | 28 bytes | 128 bytes | 7140 bytes |
//! | SHA-512/256 | `Hkdf<Sha512_256>` | 32 bytes | 128 bytes | 8160 bytes |
//!
//! The type is [`Hkdf`], generic over the hash, and what can go wrong is an
//! [`Error`]. SHA-3 exposes free functions rather than implementing `Digest`,
//! so there is no HKDF-SHA3 yet.
//!
//! # How it works
//!
//! HKDF is two functions built on HMAC (RFC 2104), a keyed hash: whoever does
//! not know `K` cannot tell `HMAC(K, m)` from random bytes, for any `m`.
//! HashLen is the length of one output of the hash.
//!
//! **Extract** (RFC 5869 section 2.2) turns the input keying material (IKM)
//! into a pseudorandom key (PRK) of HashLen bytes: `PRK = HMAC(salt, IKM)`. The
//! IKM may hold plenty of entropy without having it spread evenly over its
//! bytes: a Diffie-Hellman secret is the coordinate of a point, and only about
//! half of the numbers below the prime are one. Keyed with the salt, HMAC
//! concentrates that entropy into a key that is uniformly random for all
//! practical purposes.
//! The salt is optional and not secret. Without one it is HashLen zero bytes,
//! and an empty salt is the same key: HMAC pads its key with zeros to the
//! block of the hash.
//!
//! **Expand** (section 2.3) turns the PRK into output keying material (OKM) of
//! the length asked for, one hash output at a time:
//! `T(i) = HMAC(PRK, T(i - 1) | info | i)`, from an empty `T(0)`, and the
//! output is `T(1) | T(2) | ...` cut to that length. `info` says what the
//! output is for. The counter `i` is a single byte, which is where the limit of
//! 255 blocks, 255 × HashLen bytes, comes from.
//!
//! The two steps are separate because their jobs are. Extract needs a salt and
//! makes one key; Expand needs that key and makes many, each named by its
//! `info`. A protocol extracts once for each new secret and expands once for
//! each key, and a secret that is a uniformly random key already, such as the
//! output of an earlier Expand, can skip Extract (section 3.3). The key
//! schedule of TLS 1.3 uses both: each stage extracts from its new input, with
//! a salt expanded from the stage before, and expands its traffic keys from
//! the result.
//!
//! # Using it
//!
//! [`Hkdf::extract`] runs Extract and returns an [`Hkdf`] that holds the PRK,
//! and [`Hkdf::expand`] then fills a buffer with the output for one `info`, as
//! many times as there are keys to derive. [`Hkdf::derive`] does both in one
//! call, and [`Hkdf::from_prk`] starts from a PRK the caller already has. The
//! output goes into a buffer of the caller's, of any length up to
//! [`Hkdf::<D>::MAX_OUTPUT_LEN`](Hkdf::MAX_OUTPUT_LEN), none included; a longer
//! one is [`Error::InvalidLength`], and is left as it was.
//!
//! - **Use a salt if there is one.** It need not be secret and can be reused,
//!   but it must not be chosen by an attacker, and it should not depend on the
//!   IKM (section 3.4). HashLen random bytes are ideal. Without a salt HKDF is
//!   still sound, with weaker guarantees (section 3.1).
//! - **Extract the IKM, expand the PRK.** A secret that is not uniformly
//!   random, a Diffie-Hellman shared secret above all, goes through
//!   [`Hkdf::extract`]. [`Hkdf::from_prk`] is for a key that already is one,
//!   and refuses a key shorter than HashLen, the shortest a PRK can be
//!   ([`Error::InvalidPrkLength`]).
//! - **Bind each key to its purpose with `info`.** Two keys derived with
//!   different `info` are independent, so a key for one direction, one
//!   algorithm or one protocol cannot stand in for another. After a key
//!   exchange, `info` (or the salt) is also where both public keys go, as
//!   RFC 7748 (section 6.1) recommends.
//! - **The length does not separate keys.** The same PRK and `info` always give
//!   the same bytes, and a shorter output is the start of a longer one: a
//!   16-byte and a 32-byte key derived with the same `info` share their first
//!   16 bytes.
//! - **HKDF does not stretch passwords.** It is fast on purpose and adds no
//!   work factor, so a password run through it is as easy to guess as the
//!   password itself. A password-based KDF such as PBKDF2 is for that.
//! - **MD5 and SHA-1 are there for older protocols.** Their collisions do not
//!   break HMAC, which does not need collision resistance, but neither should
//!   be chosen for a new design.
//!
//! An `Hkdf` holds the PRK as a key of HMAC, which is overwritten with zeros
//! when it is dropped, and its `Debug` output does not show it. That is best
//! effort: the hash functions' working values on the stack are not
//! overwritten, nor are the digests they return (`T(i)` among them, which
//! generic code over `Digest` can read but not overwrite), nor the copy that
//! moving an `Hkdf` can leave behind where it was. The output is written to the
//! caller's buffer, and wiping that is the caller's job.
//!
//! # Implementation
//!
//! HKDF has no backend of its own. It is a handful of HMAC calls, the work is
//! in the hash, and the hash picks its backend at run time as it always does
//! (FEAT_SHA256 for SHA-256 on an Apple M1, say). An `Hkdf` keeps HMAC keyed
//! with the PRK, so the key is prepared once, hashed first if it is longer than
//! a block and then padded, and reused for every block of every Expand. Each
//! block is written straight into the caller's buffer, and the next block reads
//! the previous one back from there, so Expand allocates nothing per block and
//! keeps no copy of the output.
//!
//! The HMAC is, for now, a private one in `src/hkdf/hmac.rs`, which stands in
//! for the crate's own HMAC module until it lands. `Digest` hashes a whole
//! message in one call, so this HMAC hashes the padded key again for every
//! message, twice: four calls of the compression function per block of output,
//! where an HMAC that keeps the state of the hash after the padded key needs
//! two.
//!
//! The module is safe Rust. The one `unsafe` it relies on is the volatile write
//! that wipes a key when it is dropped, which the compiler would otherwise
//! delete as a store nobody reads.
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it: the seven test cases of RFC 5869 (Appendix A, for SHA-256 and SHA-1),
//! through every function of the API, and for all eight hashes, vectors from
//! Go's `crypto/hkdf` and OpenSSL 3.6, which agree with each other. Those cover
//! salts and PRKs on both sides of the length at which HMAC starts hashing its
//! key, the longest output and one byte more, and an IKM and an `info` of 1000
//! bytes each.
//!
//! ## Side channels
//!
//! Nothing that depends on a secret is used as a memory address or as a branch
//! condition. What HKDF and HMAC do, and every address they touch, depends only
//! on the lengths of the salt, the IKM, the PRK, the `info` and the output, and
//! never on their contents; nothing compares a secret byte with anything. The
//! SHA-2 functions underneath have the same property (see
//! [`sha2`](crate::sha2)). Unlike for ECDH, the compiled code has not been
//! inspected for it, and no timing measurement backs it up. The lengths
//! themselves are not hidden, and nothing here is protected against attacks
//! that read power consumption or inject faults.
//!
//! # Example
//!
//! ```
//! use cryptors::{hkdf::{Error, Hkdf}, sha2::Sha256};
//!
//! // RFC 5869, Appendix A.1.
//! let ikm = [0x0b; 22];
//! let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
//! let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
//!
//! let mut okm = [0; 42];
//! Hkdf::<Sha256>::derive(&salt, &ikm, &info, &mut okm)?;
//! assert_eq!(
//!     okm,
//!     [
//!         0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
//!         0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
//!         0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
//!     ]
//! );
//!
//! // Extract once, then expand one key per purpose, each with its own `info`.
//! let hkdf = Hkdf::<Sha256>::extract(&salt, &ikm);
//! let mut client = [0; 16];
//! let mut server = [0; 16];
//! hkdf.expand(b"client write key", &mut client)?;
//! hkdf.expand(b"server write key", &mut server)?;
//! assert_eq!(client[..4], [0x46, 0x33, 0x22, 0x97]);
//! assert_ne!(client, server);
//!
//! // A key that is uniformly random already, such as one block of output, can
//! // skip Extract.
//! let next = Hkdf::<Sha256>::from_prk(&okm[..32])?;
//!
//! // HKDF-SHA256 has 255 blocks of 32 bytes to give, and asking for more is an
//! // error, not a panic.
//! let mut too_long = vec![0; Hkdf::<Sha256>::MAX_OUTPUT_LEN + 1];
//! assert_eq!(next.expand(b"", &mut too_long), Err(Error::InvalidLength));
//! # Ok::<(), Error>(())
//! ```

mod hmac;
mod kdf;

pub use kdf::{Error, Hkdf};
