//! From-scratch implementation of HMAC, the keyed-hash message authentication
//! code (FIPS 198-1, which adopts RFC 2104): a short tag computed from a secret
//! key and a message, which only the holders of the key can produce or check.
//! It works over every hash in the crate that implements
//! [`Digest`](crate::Digest).
//!
//! | HMAC with | `D` | Block (`B`) | Tag (`L`) | Shortest truncated tag | Test vectors |
//! |-----------|-----|-------------|-----------|------------------------|--------------|
//! | MD5 | [`Md5`](crate::md5::Md5) | 64 bytes | 16 bytes | 10 bytes | RFC 2202 |
//! | SHA-1 | [`Sha1`](crate::sha1::Sha1) | 64 bytes | 20 bytes | 10 bytes | RFC 2202 |
//! | SHA-224 | [`Sha224`](crate::sha2::Sha224) | 64 bytes | 28 bytes | 14 bytes | RFC 4231 |
//! | SHA-256 | [`Sha256`](crate::sha2::Sha256) | 64 bytes | 32 bytes | 16 bytes | RFC 4231 |
//! | SHA-384 | [`Sha384`](crate::sha2::Sha384) | 128 bytes | 48 bytes | 24 bytes | RFC 4231 |
//! | SHA-512 | [`Sha512`](crate::sha2::Sha512) | 128 bytes | 64 bytes | 32 bytes | RFC 4231 |
//! | SHA-512/224 | [`Sha512_224`](crate::sha2::Sha512_224) | 128 bytes | 28 bytes | 14 bytes | none published; Go and OpenSSL |
//! | SHA-512/256 | [`Sha512_256`](crate::sha2::Sha512_256) | 128 bytes | 32 bytes | 16 bytes | none published; Go and OpenSSL |
//!
//! [`Hmac<D>`](Hmac) holds a key and computes the tags of as many messages as
//! needed; [`hmac()`] is the one-call form; a tag that does not check out is a
//! [`VerifyError`]. SHA-3 does not implement `Digest` yet (its
//! extendable-output functions do not fit the trait), so there is no HMAC-SHA3.
//!
//! # How it works
//!
//! HMAC hashes twice, under two forms of the key:
//!
//! ```text
//! HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))
//! ```
//!
//! `K0` is the key followed by zeros up to the block length `B` of the hash,
//! or, for a key longer than a block, the digest of the key followed by zeros
//! (FIPS 198-1, section 4, steps 1 to 3). `ipad` and `opad` are the bytes
//! `0x36` and `0x5c` repeated `B` times. The inner hash mixes the key into the
//! message, and the outer hash hides the inner result under a second form of
//! the key. That second hash is what `H(K || m)` lacks: with any of these
//! Merkle-Damgard hashes, the digest of `K || m` is the hash's state at the
//! end, so whoever holds it can carry on and compute the digest of `K || m ||
//! padding || x` without the key (length extension). The tag of one message
//! under HMAC gives no such start on the tag of another.
//!
//! `K0 ^ ipad` and `K0 ^ opad` are one block each, and the state of the hash
//! after each of them depends on the key alone. FIPS 198-1, section 6, allows
//! computing those two states once, when the key is set, and starting every
//! tag from them; this crate does that. A tag then costs the hashing of the
//! message, padded, and of one more short input, the inner digest, padded. For
//! a 64-byte message that is three runs of the compression function with a
//! 64-byte block, and two with a 128-byte block.
//!
//! A protocol may send only the leftmost bytes of the tag (section 5). How few
//! is a matter for the protocol: NIST's floor is 32 bits (SP 800-107 Rev. 1,
//! section 5.3.3), and RFC 2104 (section 5) recommends at least half the
//! output and at least 80 bits.
//!
//! # Using it
//!
//! Build an [`Hmac`] from the key with [`Hmac::new`], compute tags with
//! [`Hmac::mac`] (or [`Hmac::mac_parts`], for a message in several pieces), and
//! check a received tag with [`Hmac::verify`], or [`Hmac::verify_truncated`]
//! for a protocol that sends truncated tags.
//!
//! - **Compare tags with `verify`, never with `==`.** `verify` goes through
//!   every byte of the tag whatever it finds, so the time it takes does not
//!   show how many leading bytes of a forged tag were right. `==` stops at the
//!   first difference, and that is enough to forge a tag one byte at a time.
//! - **The length of the tag is the protocol's.** `verify` accepts only a full
//!   tag, `L` bytes. `verify_truncated` accepts any length from
//!   [`Hmac::MIN_TAG_LEN`] to `L`: half the output, rounded up, and no fewer
//!   than 10 bytes, the two bounds of RFC 2104. That takes in the truncations
//!   protocols use, such as HMAC-SHA-256-128 in IPsec (RFC 4868) and
//!   HMAC-SHA1-80 in SRTP. Neither ever accepts an empty tag. A tag's length is
//!   not authenticated: the protocol has to fix it, and the caller has to hold
//!   the tag to it, or a forger will send the shortest tag accepted.
//! - **The key should be random and at least `L` bytes long** (RFC 2104,
//!   section 3). Any length works, including zero, but a shorter key is
//!   weaker, and a key longer than a block is hashed down to `L` bytes first,
//!   so it is worth no more than one of `L` bytes. HMAC is fast by design,
//!   which is the wrong property for a password: turn a password into a key
//!   with a password-hashing construction such as PBKDF2, which is on the
//!   crate's list and not yet here.
//! - **Key once, tag many.** [`Hmac::new`] hashes the two padded keys, which
//!   is two runs of the compression function, and every tag after that starts
//!   from the result. [`hmac()`] does both for each call.
//! - **A message in pieces needs no joining.** [`Hmac::mac_parts`] gives the
//!   tag of the concatenation of its parts, and feeds them to the hash one
//!   after the other, from the caller's memory.
//!
//! An `Hmac` holds the two states of the hash, which are worth as much as the
//! key: from either, a forger could tag any message. They are overwritten with
//! zeros when the `Hmac` is dropped, and its `Debug` output does not show
//! them. So are the states a tag is computed in, and the block that holds the
//! padded key while `new` hashes it. That is best effort: the working values
//! of the compression functions (on the stack and in registers while a block
//! is hashed), the digest of a key longer than a block, and the copy that
//! moving an `Hmac` (into a `Box` or a `Vec`, say) can leave behind where it
//! was are not overwritten.
//!
//! HMAC is not broken with any of the hashes above. Its security rests on the
//! compression function of the hash behaving like a keyed random function,
//! not on collision resistance, so the collision attacks that broke MD5 and
//! SHA-1 as hashes do not carry over, and no practical forgery of HMAC-MD5 or
//! HMAC-SHA-1 is known. Neither belongs in a new design all the same: RFC 6151
//! says so for HMAC-MD5, MD5 has never been a NIST-approved hash, and NIST is
//! retiring SHA-1 by the end of 2030. A large quantum computer would not
//! change the picture much: Grover's algorithm searches keys in about the
//! square root of the steps, so a 256-bit key keeps about 128 bits.
//!
//! # Implementation
//!
//! HMAC has no backends of its own: it runs on the hash's compression
//! function, through the same run-time selection as the hash's `digest`, so
//! HMAC-SHA-256 uses the SHA-256 instructions wherever SHA-256 does.
//!
//! | Step | When | What it hashes |
//! |------|------|----------------|
//! | Keying, [`Hmac::new`] | once per key | the key, if it is longer than a block; then `K0 ^ ipad` and `K0 ^ opad`, one block each, and the two states are kept |
//! | Inner hash | every tag | from the first state: the message, straight from the caller's memory, and its padding |
//! | Outer hash | every tag | from the second state: the inner digest and its padding, one block for every hash here |
//! | Verification | every check | a tag, as above, and a comparison of every byte |
//!
//! - **The hashes take the message a piece at a time.** [`Digest::digest`](crate::Digest::digest)
//!   takes one slice. Inside the crate, the eight hashes also have an
//!   incremental form, which takes the message in pieces, keeps the bytes of an
//!   unfinished block, and can be copied at any point to carry on from there;
//!   whole blocks go to the compression function from the caller's slice
//!   without being copied. It is not public, and generic code reaches it
//!   through a hidden constant of the `Digest` trait, so `Hmac<D>` works for
//!   any `D: Digest`.
//! - **A hash from outside the crate gets the one-shot path.** A type that
//!   implements `Digest` elsewhere has no incremental form. `Hmac` then keeps
//!   the padded keys themselves, and for each tag copies the padded key and
//!   the message into one buffer, hashes it with `digest`, and wipes the
//!   buffer. That is correct but slower, and needs the message twice in memory.
//! - **No `unsafe` of its own.** What wipes the states is the volatile write in
//!   `src/wipe.rs`, which views the bytes 16 at a time so that wiping a state
//!   costs a few percent of a tag.
//!
//! ## Trust
//!
//! The tests check the tags against sources that share no code with this one:
//! the vectors of RFC 4231 and RFC 2202, and for every hash, including
//! SHA-512/224 and SHA-512/256, which no RFC covers, tags from Go's
//! `crypto/hmac` and OpenSSL 3.6, which agree with each other, for keys around
//! the block length and messages around the padding boundary. Every vector
//! goes through every way of computing a tag, and through the one-shot path as
//! well as the streaming one. Under HMAC, the incremental form of each hash
//! has to give the hash's one-shot digest for messages around every block and
//! padding boundary, split at every byte, and for a long message in pieces of
//! uneven sizes.
//!
//! ## Side channels
//!
//! What HMAC does with a key or a message depends on their lengths and on
//! nothing else. The hashes here have no table indexed by the data and no
//! branch on it, the padded keys are made with XORs, and the comparison of a
//! tag goes through every byte and ORs the differences together, with the one
//! branch on the result. The comparison's accumulator goes through
//! `core::hint::black_box`, so that the compiler cannot reason about it and
//! stop at the first difference, which is a request, not a guarantee. The
//! assembly that `rustc` produced for `aarch64` and `x86_64` was inspected: the
//! comparison's only conditional jumps are its loop, over the public length of
//! the tag, and the check of the lengths before it. That is one compiler's
//! output for two targets, with no timing measurement on real hardware behind
//! it.
//!
//! What is not hidden is public by nature: the length of the key, of the
//! message and of a received tag, and whether a tag was rejected for its
//! length or its contents. Nothing here is protected against attacks that read
//! power consumption or inject faults.
//!
//! # Example
//!
//! ```
//! use cryptors::{hmac::{self, Hmac, VerifyError}, sha2::Sha256};
//!
//! // RFC 4231, test case 2. `new` hashes the padded key once; every tag reuses
//! // the result.
//! let mac = Hmac::<Sha256>::new(b"Jefe");
//! let tag: [u8; 32] = mac.mac(b"what do ya want for nothing?");
//! assert_eq!(
//!     tag,
//!     [
//!         0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
//!         0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
//!         0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
//!     ]
//! );
//!
//! // The receiver checks the tag in constant time, never with `==`.
//! assert_eq!(mac.verify(b"what do ya want for nothing?", &tag), Ok(()));
//! assert_eq!(
//!     mac.verify(b"what do ya want for everything?", &tag),
//!     Err(VerifyError::Mismatch)
//! );
//!
//! // A protocol that sends the first 128 bits has its own check, which still
//! // refuses anything shorter than half the tag.
//! assert_eq!(mac.verify_truncated(b"what do ya want for nothing?", &tag[..16]), Ok(()));
//! assert_eq!(
//!     mac.verify_truncated(b"what do ya want for nothing?", &tag[..8]),
//!     Err(VerifyError::WrongLength)
//! );
//!
//! // A message in several pieces has the tag of the pieces put together.
//! assert_eq!(mac.mac_parts(&[b"what do ya ", b"want for nothing?"]), tag);
//!
//! // And for a single message, the key and the hash in one call.
//! assert_eq!(hmac::hmac::<Sha256>(b"Jefe", b"what do ya want for nothing?"), tag);
//! ```
//!
//! A real key is random bytes, from a source of your own; the standard library
//! has no secure one that is stable (this one only compiles, as there is no
//! source that works on every platform):
//!
//! ```no_run
//! use cryptors::{hmac::Hmac, sha2::Sha256};
//! use std::{fs::File, io::Read};
//!
//! # fn main() -> std::io::Result<()> {
//! let mut key = [0u8; 32];
//! File::open("/dev/urandom")?.read_exact(&mut key)?;
//! let mac = Hmac::<Sha256>::new(&key);
//! // Store or share `key`; send `mac.mac(message)` along with each message.
//! # Ok(())
//! # }
//! ```
//!
//! HMAC is defined only for a hash whose output fits in its block, and holds
//! blocks of up to 144 bytes. A `Digest` that breaks either rule fails the
//! build, not a run (`cargo check`, which stops before code generation, does
//! not see it):
//!
//! ```compile_fail,E0080
//! use cryptors::{Digest, hmac::Hmac};
//!
//! /// A "hash" with a 64-byte output and a 32-byte block.
//! struct Wide;
//!
//! impl Digest for Wide {
//!     const BLOCK_LEN: usize = 32;
//!     const OUTPUT_LEN: usize = 64;
//!     type Output = [u8; 64];
//!     fn digest(_: &[u8]) -> [u8; 64] {
//!         [0; 64]
//!     }
//! }
//!
//! let _ = Hmac::<Wide>::new(b"key").mac(b"message");
//! ```

mod mac;

pub use mac::{Hmac, VerifyError, hmac};
