//! The 64-bit members of the SHA-2 family: SHA-384, SHA-512, SHA-512/224 and
//! SHA-512/256. The parent module documents the whole family and its
//! backends; this one is laid out like its sibling `sha256`, with a `digest`
//! module holding the public types and the backend dispatcher, and one module
//! per backend.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod digest;
mod scalar;

use digest::K;

pub use digest::{Sha384, Sha512, Sha512_224, Sha512_256};
