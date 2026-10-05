//! From-scratch SHA-224 and SHA-256 implementation (FIPS 180-4), the two
//! 32-bit members of the SHA-2 family.
//!
//! Both are the same algorithm. The message is padded to a multiple of 64
//! bytes, then every 64-byte block is mixed into a running state of eight
//! 32-bit words by a compression function made of 64 rounds. SHA-256 starts
//! from one set of initial words and outputs all eight of them (32 bytes);
//! SHA-224 starts from a different set and outputs only the first seven
//! (28 bytes). SHA-224 is therefore *not* a truncated SHA-256 digest: the two
//! produce unrelated outputs for the same input.
//!
//! Neither function is broken. Like every Merkle-Damgard hash, though, they
//! allow length extension: knowing `sha256(m)` and the length of `m` is enough
//! to compute `sha256(m || padding || x)` without knowing `m`. Do not build a
//! keyed MAC as `sha256(key || message)`; use HMAC. SHA-224 withholds the last
//! 32 bits of the state, so an attacker has to guess those first.
//!
//! The amount of work, and every memory access, depends only on the length of
//! the message and never on its contents.
//!
//! # Backends
//!
//! Hashing one message is inherently serial -- block `n + 1` cannot start
//! until block `n` has finished -- so a single digest can only be sped up by
//! making the compression function itself cheaper. Both common CPU families
//! have instructions for exactly that, and the crate picks between four
//! interchangeable backends automatically at runtime:
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8 crypto extensions (`sha2`, a.k.a. FEAT_SHA256) | `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` |
//! | `x86` | x86 SHA extensions (SHA-NI) with SSSE3 and SSE4.1 | `SHA256RNDS2`, `SHA256MSG1`, `SHA256MSG2` |
//! | `x86_avx2` | AVX2, BMI1 and BMI2 | AVX2 for the message schedule of two blocks at once; `rorx` and `andn` in the rounds |
//! | `scalar` | nothing -- always available | plain integer code; on x86-64 with BMI1 and BMI2, a second build of it using `rorx` and `andn` |
//!
//! `scalar` is the one we trust to be correct, and it is the one used on any
//! CPU without the instructions above. The tests check that each of the other
//! backends produces the same output as it, byte for byte.
//!
//! # Example
//!
//! ```
//! use cryptors::{Digest, sha2::{Sha224, Sha256}};
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
//! ```

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod digest;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_avx2;

use digest::K;

pub use digest::{Sha224, Sha256};
