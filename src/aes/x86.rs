//! AES using Intel/AMD's AES instruction set (AES-NI).
//!
//! `AESENC` does a whole round of encryption in one instruction (SubBytes,
//! ShiftRows, MixColumns and AddRoundKey), and `AESENCLAST` the last round,
//! which has no MixColumns. `AESDEC` and `AESDECLAST` are the same two for the
//! equivalent inverse cipher. So a block takes 10, 12 or 14 instructions here,
//! instead of the table lookups of the scalar version, and no part of it is
//! indexed by the data.
//!
//! The key schedule uses the same instructions for its S-box (see `sub_word`),
//! so no secret byte is looked up in a table anywhere on this backend.
//!
//! This code only runs via `super::cipher`, which checks the `aes` CPU feature
//! is present before calling it.
//!
//! On a CPU without that feature the file is still compiled, but nothing
//! executes it. The `matches_scalar_backend` test in the cipher module is what
//! checks it against `super::scalar`, and it only does so where the CPU
//! reports AES-NI.

use core::arch::x86_64::*;

use super::schedule::{Schedule, inverse_keys, key_expansion};

/// Loads a 16-byte block or round key.
#[target_feature(enable = "aes")]
#[inline]
fn load(bytes: &[u8; 16]) -> __m128i {
    // SAFETY: `bytes` is 16 bytes, so the 16-byte load is in bounds, and the
    // unaligned form of the load has no alignment requirement.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

/// Stores a vector as a 16-byte block.
#[target_feature(enable = "aes")]
#[inline]
fn store(v: __m128i) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is 16 bytes, so the 16-byte store is in bounds, and the
    // unaligned form of the store has no alignment requirement.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), v) };
    bytes
}

/// `SubWord()` with the hardware S-box. `AESENCLAST` with an all-zero key is
/// SubBytes followed by ShiftRows. If the word is copied into all four
/// columns, ShiftRows moves identical bytes onto each other and changes
/// nothing, so any column of the result is the word with the S-box applied.
#[target_feature(enable = "aes")]
#[inline]
fn sub_word(word: u32) -> u32 {
    let columns = _mm_set1_epi32(word as i32);
    let substituted = _mm_aesenclast_si128(columns, _mm_setzero_si128());
    _mm_cvtsi128_si32(substituted) as u32
}

/// `InvMixColumns()` on a round key.
#[target_feature(enable = "aes")]
#[inline]
fn inv_mix_columns(key: &[u8; 16]) -> [u8; 16] {
    store(_mm_aesimc_si128(load(key)))
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
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::cipher` is the only caller, and it checks this already. Nothing else
/// needs checking: the block and every key are 16-byte arrays.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let mut state = _mm_xor_si128(load(block), load(&keys[0]));
    for key in &keys[1..N - 1] {
        state = _mm_aesenc_si128(state, load(key));
    }
    state = _mm_aesenclast_si128(state, load(&keys[N - 1]));
    store(state)
}

/// Decrypts one block with the round keys `keys` of the equivalent inverse
/// cipher, in the same shape as `encrypt`.
///
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::cipher` is the only caller, and it checks this already. Nothing else
/// needs checking: the block and every key are 16-byte arrays.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let mut state = _mm_xor_si128(load(block), load(&keys[0]));
    for key in &keys[1..N - 1] {
        state = _mm_aesdec_si128(state, load(key));
    }
    state = _mm_aesdeclast_si128(state, load(&keys[N - 1]));
    store(state)
}
