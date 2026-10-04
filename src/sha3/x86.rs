//! Multi-buffer Keccak-f\[1600\] for x86-64, via AVX2 and SSE2.
//!
//! No x86 CPU has a Keccak instruction, and vectorizing a *single* sponge
//! does not pay: the 25-lane state and 5-wide rows do not divide into 4-lane
//! registers, so the shuffling costs more than the parallelism returns.
//!
//! Independent messages are a different matter. Every operation Keccak
//! performs is lane-wise -- XOR, and-not, and a rotate by an amount fixed per
//! state lane -- so `W` messages placed one per 64-bit vector lane advance
//! together with no cross-lane traffic at all, and one permutation does the
//! work of `W`.
//!
//! x86 has no rotate-by-immediate for vectors, so each `rotl` below is a
//! shift pair plus an OR. Every rotation Keccak asks for is between 1 and 62
//! (only state lane 0 rotates by zero, and it is handled without a rotate),
//! so neither shift is ever by 0 or 64.
//!
//! # Architecture compatibility
//!
//! This backend is x86-64-only. [`permute2`] needs SSE2, which every x86-64
//! CPU has; [`permute4`] needs AVX2. Both are `unsafe` and gated with
//! `#[target_feature]`, so callers must check for AVX2 at run time and fall
//! back to [`permute2`], or to the scalar backend, on CPUs without it.

use core::arch::x86_64::*;

/// The five operations of [`keccak_round`] on four messages at once.
macro_rules! avx2_xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_xor_si256($a, $b), _mm256_xor_si256($c, $d)),
            $e,
        )
    };
}
macro_rules! avx2_rotl {
    ($v:expr, $r:expr) => {{
        let v = $v;
        _mm256_or_si256(
            _mm256_slli_epi64::<{ $r }>(v),
            _mm256_srli_epi64::<{ 64 - $r }>(v),
        )
    }};
}
macro_rules! avx2_rax1 {
    ($a:expr, $b:expr) => {
        _mm256_xor_si256($a, avx2_rotl!($b, 1))
    };
}
macro_rules! avx2_xar {
    ($a:expr, $b:expr, $r:expr) => {
        avx2_rotl!(_mm256_xor_si256($a, $b), $r)
    };
}
macro_rules! avx2_xor {
    ($a:expr, $b:expr) => {
        _mm256_xor_si256($a, $b)
    };
}
/// `_mm256_andnot_si256(b, c)` is `!b & c`, exactly what the contract wants.
macro_rules! avx2_bcax {
    ($a:expr, $b:expr, $c:expr) => {
        _mm256_xor_si256($a, _mm256_andnot_si256($b, $c))
    };
}
macro_rules! avx2_rc {
    ($v:expr) => {
        _mm256_set1_epi64x($v as i64)
    };
}

/// Applies Keccak-f\[1600\] to four independent states at once, one message
/// per 64-bit lane.
///
/// `state` is transposed -- `state[lane][slot]` holds state lane `lane` of
/// message `slot` -- so each `state[lane]` is exactly one 256-bit register.
///
/// # Safety
///
/// The caller must make sure the `avx2` CPU feature is available.
/// `super::digest::sponge_many` is the only caller, and it checks this
/// already. The loads and stores below are all of a fixed-size array, so they
/// are in bounds by construction.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn permute4(state: &mut [[u64; 4]; 25]) {
    let mut wide = [_mm256_setzero_si256(); 25];
    for (slot, lane) in wide.iter_mut().zip(state.iter()) {
        // SAFETY: `lane` is a `[u64; 4]`, exactly the 32 bytes loaded.
        *slot = unsafe { _mm256_loadu_si256(lane.as_ptr().cast()) };
    }

    keccak_rounds!(
        avx2_xor5, avx2_rax1, avx2_xar, avx2_xor, avx2_bcax, wide, avx2_rc
    );

    for (lane, &slot) in state.iter_mut().zip(wide.iter()) {
        // SAFETY: `lane` is a `[u64; 4]`, exactly the 32 bytes stored.
        unsafe { _mm256_storeu_si256(lane.as_mut_ptr().cast(), slot) };
    }
}

/// The same five operations on two messages at once.
macro_rules! sse2_xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        _mm_xor_si128(
            _mm_xor_si128(_mm_xor_si128($a, $b), _mm_xor_si128($c, $d)),
            $e,
        )
    };
}
macro_rules! sse2_rotl {
    ($v:expr, $r:expr) => {{
        let v = $v;
        _mm_or_si128(
            _mm_slli_epi64::<{ $r }>(v),
            _mm_srli_epi64::<{ 64 - $r }>(v),
        )
    }};
}
macro_rules! sse2_rax1 {
    ($a:expr, $b:expr) => {
        _mm_xor_si128($a, sse2_rotl!($b, 1))
    };
}
macro_rules! sse2_xar {
    ($a:expr, $b:expr, $r:expr) => {
        sse2_rotl!(_mm_xor_si128($a, $b), $r)
    };
}
macro_rules! sse2_xor {
    ($a:expr, $b:expr) => {
        _mm_xor_si128($a, $b)
    };
}
macro_rules! sse2_bcax {
    ($a:expr, $b:expr, $c:expr) => {
        _mm_xor_si128($a, _mm_andnot_si128($b, $c))
    };
}
macro_rules! sse2_rc {
    ($v:expr) => {
        _mm_set1_epi64x($v as i64)
    };
}

/// Applies Keccak-f\[1600\] to two independent states at once, one message
/// per 64-bit lane.
///
/// # Safety
///
/// `sse2` is part of the x86-64 baseline, so this is always callable on this
/// target. The loads and stores below are all of a fixed-size array, so they
/// are in bounds by construction.
#[target_feature(enable = "sse2")]
pub(super) unsafe fn permute2(state: &mut [[u64; 2]; 25]) {
    let mut wide = [_mm_setzero_si128(); 25];
    for (slot, lane) in wide.iter_mut().zip(state.iter()) {
        // SAFETY: `lane` is a `[u64; 2]`, exactly the 16 bytes loaded.
        *slot = unsafe { _mm_loadu_si128(lane.as_ptr().cast()) };
    }

    keccak_rounds!(
        sse2_xor5, sse2_rax1, sse2_xar, sse2_xor, sse2_bcax, wide, sse2_rc
    );

    for (lane, &slot) in state.iter_mut().zip(wide.iter()) {
        // SAFETY: `lane` is a `[u64; 2]`, exactly the 16 bytes stored.
        unsafe { _mm_storeu_si128(lane.as_mut_ptr().cast(), slot) };
    }
}
