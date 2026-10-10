//! AES-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags, over the
//! crate's AES through [`BlockCipher`](crate::BlockCipher).
//!
//! **Internal.** This module is private to the crate. It exists for
//! [`hpke`](crate::hpke), whose AEADs are AES-128-GCM and AES-256-GCM, and is
//! meant to become, or to be superseded by, a public AEAD module once the crate
//! has modes of operation for its block ciphers.
//!
//! # How it works
//!
//! GCM is counter mode for secrecy and GHASH for integrity. A 96-bit nonce `N`
//! makes the pre-counter block `J0 = N || 1`. The plaintext is XORed with the
//! encryptions of `N || 2`, `N || 3`, ... (GCTR), and the tag is the encryption
//! of `J0` XORed with GHASH of the associated data, the ciphertext and their
//! lengths. GHASH multiplies its running value by the hash key
//! `H = AES_K(0^128)` in GF(2^128) once per 16-byte block.
//!
//! Sealing and opening go through the message 1 KiB at a time, each chunk
//! copied, encrypted (or decrypted) and hashed while it is in the L1 cache.
//! Opening therefore has the plaintext before it has checked the tag, which
//! SP 800-38D allows (section 7); a plaintext whose tag does not match is
//! overwritten with zeros and never returned.
//!
//! # Backends
//!
//! The counter mode is the crate's AES, on whichever of its backends the CPU
//! supports. GHASH has its own three, picked automatically at runtime:
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8 crypto extensions (`aes`: FEAT_AES, which Rust reports together with FEAT_PMULL) | `PMULL`, `PMULL2` |
//! | `x86` | PCLMULQDQ and SSSE3 | `PCLMULQDQ`, `PSHUFB` |
//! | `scalar` | nothing -- always available | integer multiplications of masked operands (BearSSL's `ctmul64`) |
//!
//! The two hardware backends multiply sixteen blocks by `H^16` down to `H`,
//! four carry-less products each, add the products and reduce
//! once, so that the multiplications of one block do not wait on the reduction
//! of the one before. `scalar` multiplies one block at a time. All three share
//! the reduction.
//!
//! `scalar` is the one we trust to be correct, and it computes the powers of
//! `H` the others start from. The tests check each of the other backends
//! against it, on lengths around the groups of sixteen and at every alignment.
//!
//! # Side channels
//!
//! No backend uses the data or the key as a memory address or as the
//! condition of a branch: `scalar` multiplies masked integers instead of
//! looking up tables of multiples of `H`, which is constant-time wherever
//! 64-bit multiplication is, as on current aarch64 and x86-64 cores, and the
//! carry-less multiply instructions take the same time for every operand. The
//! tag is compared in constant time. The block cipher is the crate's AES, so
//! GCM inherits its properties: on CPUs with AES instructions it does not
//! index memory by secrets, and on the scalar backend it does (see
//! [`crate::aes`]).

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod aead;
mod ghash;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86;

pub(crate) use aead::{Gcm, NONCE_LEN, NotAuthentic, TooLong};

#[cfg(test)]
mod tests {
    use crate::Digest;
    use crate::sha2::Sha256;

    /// The bytes of a hex string, which may be broken over lines.
    pub(super) fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `len` bytes derived from `label` and `i`: SHA-256(`label` || `i` || `j`)
    /// for `j` = 0, 1, ..., each counter as four big-endian bytes, cut to
    /// length. Simple enough to reproduce in any language, which is how the
    /// values from Go in these tests were made.
    pub(super) fn stream(label: &[u8], i: u32, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 32);
        for j in 0u32.. {
            if out.len() >= len {
                break;
            }
            let mut input = label.to_vec();
            input.extend_from_slice(&i.to_be_bytes());
            input.extend_from_slice(&j.to_be_bytes());
            out.extend_from_slice(&Sha256::digest(&input));
        }
        out.truncate(len);
        out
    }
}
