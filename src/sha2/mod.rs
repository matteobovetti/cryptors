//! From-scratch implementation of the SHA-2 family (FIPS 180-4): six hash
//! functions built from two algorithms, one working on 32-bit words and one on
//! 64-bit words.
//!
//! | Function | Type | Output | Block | Word |
//! |----------|------|--------|-------|------|
//! | SHA-224 | [`Sha224`] | 28 bytes | 64 bytes | 32 bits |
//! | SHA-256 | [`Sha256`] | 32 bytes | 64 bytes | 32 bits |
//! | SHA-384 | [`Sha384`] | 48 bytes | 128 bytes | 64 bits |
//! | SHA-512 | [`Sha512`] | 64 bytes | 128 bytes | 64 bits |
//! | SHA-512/224 | [`Sha512_224`] | 28 bytes | 128 bytes | 64 bits |
//! | SHA-512/256 | [`Sha512_256`] | 32 bytes | 128 bytes | 64 bits |
//!
//! All six implement [`Digest`](crate::Digest).
//!
//! # How they work
//!
//! The two algorithms are the same construction at two sizes. The message is
//! padded to a multiple of the block size, then every block is mixed into a
//! running state of eight words by a compression function made of rounds:
//! 64 rounds over 64-byte blocks of 32-bit words for SHA-256, 80 rounds over
//! 128-byte blocks of 64-bit words for SHA-512. The padding is a `0x80` byte,
//! zeros, and the message length in bits, as a 64-bit integer for the first
//! and a 128-bit integer for the second.
//!
//! Within each algorithm, the functions differ only in their starting state and
//! in how much of the final state they output. SHA-256 starts from one set of
//! initial words and outputs all eight of them (32 bytes); SHA-224 starts from
//! a different set and outputs only the first seven (28 bytes). SHA-512 outputs
//! all eight of its words (64 bytes); SHA-384 starts from a different set and
//! outputs the first six (48 bytes). SHA-512/224 and SHA-512/256 are two of the
//! SHA-512/t functions of FIPS 180-4: each starts from an initial state that
//! the standard derives by running SHA-512 over the function's own name, and
//! outputs the first `t` bits of the final state.
//!
//! None of the shorter functions is a truncated digest of the bigger one: each
//! starts from its own state, so for the same input they produce unrelated
//! outputs.
//!
//! None of the six is broken. Like every Merkle-Damgard hash, though, they
//! allow length extension: knowing `sha256(m)` and the length of `m` is enough
//! to compute `sha256(m || padding || x)` without knowing `m`, because the
//! digest *is* the final state. Do not build a keyed MAC as
//! `sha256(key || message)`; use HMAC. The functions that withhold part of the
//! final state make it harder: SHA-224 hides the last 32 bits of the state,
//! SHA-384 hides 128, SHA-512/256 hides 256 and SHA-512/224 hides 288, and an
//! attacker has to guess those first. For SHA-224 that still leaves extension
//! possible; for the other three the guess is far beyond reach.
//!
//! The amount of work, and every memory access, depends only on the length of
//! the message and never on its contents.
//!
//! # Backends
//!
//! Hashing one message is inherently serial -- block `n + 1` cannot start
//! until block `n` has finished -- so a single digest can only be sped up by
//! making the compression function itself cheaper. Where a CPU has
//! instructions for exactly that, the crate uses them, picking between the
//! interchangeable backends automatically at runtime.
//!
//! ## SHA-224 and SHA-256
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8 crypto extensions (`sha2`, a.k.a. FEAT_SHA256) | `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` |
//! | `x86` | x86 SHA extensions (SHA-NI) with SSSE3 and SSE4.1 | `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` |
//! | `x86_avx2` | AVX2, BMI1 and BMI2 | AVX2 for the message schedule of two blocks at once; `rorx` and `andn` in the rounds |
//! | `scalar` | nothing -- always available | plain integer code; on x86-64 with BMI1 and BMI2, a second build of it using `rorx` and `andn` |
//!
//! ## SHA-384, SHA-512, SHA-512/224 and SHA-512/256
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8.2 SHA-512 extension (FEAT_SHA512, which Rust reports as `sha3`) | `SHA512H`, `SHA512H2`, `SHA512SU0`, `SHA512SU1` |
//! | `scalar` | nothing -- always available | plain integer code; on x86-64 with BMI1 and BMI2, a second build of it using `rorx` and `andn` |
//!
//! A few recent x86-64 CPUs have SHA-512 instructions of their own
//! (`VSHA512RNDS2`, `VSHA512MSG1` and `VSHA512MSG2`). The crate does not use
//! them: no machine this crate is tested on has them, and a backend that
//! nothing has executed should not be producing digests. On x86-64 these four
//! functions always run the `scalar` backend.
//!
//! ## Trust
//!
//! `scalar` is the one we trust to be correct, and it is the one used on any
//! CPU without the instructions above. The tests check that each of the other
//! backends produces the same output as it, byte for byte.
//!
//! # Example
//!
//! ```
//! use cryptors::{Digest, sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_256}};
//!
//! let digest: [u8; 32] = Sha256::digest(b"abc");
//! assert_eq!(
//!     Sha256::hex_digest(b"abc"),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//! assert_eq!(digest[0], 0xba);
//!
//! let short: [u8; 28] = Sha224::digest(b"abc");
//! assert_eq!(short[0], 0x23);
//!
//! // The 64-bit functions have longer blocks and digests, and a `Digest`
//! // works the same way whichever one it is.
//! let digest: [u8; 64] = Sha512::digest(b"abc");
//! assert_eq!(
//!     Sha512::hex_digest(b"abc"),
//!     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
//!      2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
//! );
//! assert_eq!(digest[0], 0xdd);
//!
//! assert_eq!(Sha384::digest(b"abc").len(), 48);
//!
//! // SHA-512/256 has the length of SHA-256's output but is its own function,
//! // not a shorter SHA-512 digest.
//! assert_eq!(
//!     Sha512_256::hex_digest(b"abc"),
//!     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
//! );
//! ```

mod sha256;
mod sha512;

/// Whether this CPU has BMI1 and BMI2, which the `scalar` backend of each
/// algorithm needs for its `rorx`/`andn` build (and SHA-256's AVX2 backend
/// needs for its rounds). Kept here because both algorithms ask the same
/// question.
#[cfg(target_arch = "x86_64")]
#[inline]
fn has_bmi() -> bool {
    // On a target that already has both in its baseline (`-C target-cpu=x86-64-v3`,
    // for instance) this folds away at compile time.
    (cfg!(target_feature = "bmi1") && cfg!(target_feature = "bmi2"))
        || (std::arch::is_x86_feature_detected!("bmi1")
            && std::arch::is_x86_feature_detected!("bmi2"))
}

pub use sha256::{Sha224, Sha256};
pub use sha512::{Sha384, Sha512, Sha512_224, Sha512_256};
