//! From-scratch SHA-1 implementation (RFC 3174). It's broken as a security
//! hash -- only use it for learning or legacy checksums.
//!
//! There are three interchangeable backends, picked automatically at runtime:
//!
//! | Backend | Requires | Relative speed |
//! |---------|----------|----------------|
//! | [`aarch64`] | ARMv8 crypto extensions (`sha2` / FEAT_SHA1) | ~2.8x |
//! | [`x86`] | x86 SHA extensions (SHA-NI) | hardware-dependent |
//! | [`scalar`] | nothing -- always available | 1x (reference) |
//!
//! `scalar` is the one we trust to be correct; the test `matches_scalar_backend`
//! checks the hardware backends produce the same output as it.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod digest;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86;

use digest::K;

pub use digest::{digest, hex_digest};
