//! The 32-bit members of the SHA-2 family: SHA-224 and SHA-256. The parent
//! module documents the whole family and its backends; this one is laid out
//! like its sibling `sha512`, with a `digest` module holding the public types
//! and the backend dispatcher, and one module per backend.

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
