//! AES using ARMv8's crypto extensions (FEAT_AES).
//!
//! `AESE` XORs in a round key and then does SubBytes and ShiftRows, and `AESMC`
//! does MixColumns. `AESD` does the same for the inverse cipher (it XORs in a
//! round key, then does InvShiftRows and InvSubBytes) and `AESIMC` is the
//! inverse of `AESMC`. So a block takes 10, 12 or 14 `AESE`, with one `AESMC`
//! after each but the last, instead of the table lookups of the scalar version,
//! and no part of it is indexed by the data.
//!
//! Rust reports the `aes` feature only on a CPU that has FEAT_PMULL as well, so
//! on a core with the AES instructions and without PMULL this backend is not
//! used, and the scalar one runs.
//!
//! The key schedule uses the same instructions for its S-box (see `sub_word`),
//! so no secret byte is looked up in a table anywhere on this backend.
//!
//! This code only runs via `super::cipher`, which checks the `aes` CPU feature
//! is present before calling it.

use core::arch::aarch64::*;

use super::schedule::{Schedule, inverse_keys, key_expansion};

/// Loads a 16-byte block or round key.
#[target_feature(enable = "aes")]
#[inline]
fn load(bytes: &[u8; 16]) -> uint8x16_t {
    // SAFETY: `bytes` is 16 bytes, so the 16-byte load is in bounds, and NEON
    // loads of bytes have no alignment requirement.
    unsafe { vld1q_u8(bytes.as_ptr()) }
}

/// Stores a vector as a 16-byte block.
#[target_feature(enable = "aes")]
#[inline]
fn store(v: uint8x16_t) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is 16 bytes, so the 16-byte store is in bounds.
    unsafe { vst1q_u8(bytes.as_mut_ptr(), v) };
    bytes
}

/// `SubWord()` with the hardware S-box. `AESE` with an all-zero key is
/// SubBytes followed by ShiftRows. If the word is copied into all four
/// columns, ShiftRows moves identical bytes onto each other and changes
/// nothing, so any column of the result is the word with the S-box applied.
#[target_feature(enable = "aes")]
#[inline]
fn sub_word(word: u32) -> u32 {
    let columns = vreinterpretq_u8_u32(vdupq_n_u32(word));
    let substituted = vaeseq_u8(columns, vdupq_n_u8(0));
    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(substituted))
}

/// `InvMixColumns()` on a round key.
#[target_feature(enable = "aes")]
#[inline]
fn inv_mix_columns(key: &[u8; 16]) -> [u8; 16] {
    store(vaesimcq_u8(load(key)))
}

/// Expands `key` into the round keys of both directions.
///
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::cipher` is the only caller, and it checks this already.
#[target_feature(enable = "aes")]
pub(super) unsafe fn expand_key<const K: usize, const N: usize>(key: &[u8; K]) -> Schedule<N> {
    let enc = key_expansion::<K, N>(key, |word| sub_word(word));
    let dec = inverse_keys(&enc, |key| inv_mix_columns(key));
    Schedule { enc, dec }
}

/// Encrypts one block with the round keys `keys` of the cipher.
///
/// Each `AESE` XORs in the round key it is given and then does the substitution
/// and the row shift; each `AESMC` then mixes the columns. Round `r` is
/// therefore split across two instructions, with key `r - 1` going in before
/// the substitution and `AESMC` coming after it, and the last round, which has
/// no MixColumns, ends with a plain XOR of the final key.
///
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::cipher` is the only caller, and it checks this already. Nothing else
/// needs checking: the block and every key are 16-byte arrays.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let mut state = load(block);
    for key in &keys[..N - 2] {
        state = vaesmcq_u8(vaeseq_u8(state, load(key)));
    }
    state = vaeseq_u8(state, load(&keys[N - 2]));
    state = veorq_u8(state, load(&keys[N - 1]));
    store(state)
}

/// Decrypts one block with the round keys `keys` of the equivalent inverse
/// cipher, in the same shape as `encrypt`: `AESD` for the substitution and
/// `AESIMC` for the mixing.
///
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::cipher` is the only caller, and it checks this already. Nothing else
/// needs checking: the block and every key are 16-byte arrays.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let mut state = load(block);
    for key in &keys[..N - 2] {
        state = vaesimcq_u8(vaesdq_u8(state, load(key)));
    }
    state = vaesdq_u8(state, load(&keys[N - 2]));
    state = veorq_u8(state, load(&keys[N - 1]));
    store(state)
}
