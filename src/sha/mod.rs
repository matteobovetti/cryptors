//! From-scratch SHA-1 implementation (RFC 3174). Cryptographically broken; study/legacy-checksum only.
//!
//! Three interchangeable compression backends are selected automatically:
//!
//! | Backend | Requires | Relative speed |
//! |---------|----------|----------------|
//! | [`aarch64`] | ARMv8 crypto extensions (`sha2` / FEAT_SHA1) | ~2.8x |
//! | [`x86`] | x86 SHA extensions (SHA-NI) | hardware-dependent |
//! | [`scalar`] | nothing -- always available | 1x (reference) |
//!
//! The scalar backend is the correctness reference; the hardware backends are
//! differential-tested against it by `matches_scalar_backend`.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod scalar;
mod sha1;
#[cfg(target_arch = "x86_64")]
mod x86;

use sha1::K;

pub use sha1::{digest, hex_digest};
