//! Four- and eight-lane MD5 compression using x86 SSE2 and AVX2.
//!
//! There is no MD5 instruction on x86 (see the module docs in `super`), so this
//! is not a one-instruction-per-round backend like `crate::sha::x86`. Instead
//! each vector register holds the same state word of 4 (SSE2) or 8 (AVX2)
//! *different* messages, and the ordinary MD5 step runs on all of them at once
//! -- that many digests for the price of one dependency chain.
//!
//! The two functions are the same algorithm at two widths. They are written out
//! separately rather than abstracted behind a trait, because the intrinsics
//! must be named concretely for `#[target_feature]` to apply; the 64-step round
//! table they share lives in `md5_schedule!` and is not duplicated.
//!
//! Unlike `super::aarch64`, these do not interleave several independent lane
//! groups per step. That trick is worth a large factor on NEON, but x86 has
//! only 16 vector registers, so even one group's 16 message words already
//! spill, and whether a second group pays for itself cannot be answered without
//! the hardware to measure it on. The widths here are therefore just the
//! natural register widths.
//!
//! NOTE: this backend was developed on an aarch64 host. [`compress4`] has been
//! executed and differential-tested against `super::scalar` under Rosetta 2,
//! which emulates up to SSE4.2; [`compress8`] is compile-verified only, because
//! Rosetta 2 does not emulate AVX2. The `matches_scalar_backend` test in
//! `super::digest` is what establishes correctness; it runs on CI's native
//! x86_64 runners with `--nocapture` and logs whether the eight-lane path was
//! reached, so the CI log for a given run answers the question for that
//! runner's CPU.

use core::arch::x86_64::*;

use super::T;

/// The four nonlinear functions, RFC 1321 section 3.4, at 128-bit width.
///
/// `_mm_andnot_si128(p, q)` yields `!p & q`, which gives `F` directly and `G`
/// after swapping operands. `I` needs an explicit complement of `z`; the
/// all-ones vector is a constant, so it is materialized once.
macro_rules! nonlinear4 {
    (F, $x:expr, $y:expr, $z:expr) => {
        _mm_or_si128(_mm_and_si128($x, $y), _mm_andnot_si128($x, $z))
    };
    (G, $x:expr, $y:expr, $z:expr) => {
        _mm_or_si128(_mm_and_si128($z, $x), _mm_andnot_si128($z, $y))
    };
    (H, $x:expr, $y:expr, $z:expr) => {
        _mm_xor_si128(_mm_xor_si128($x, $y), $z)
    };
    (I, $x:expr, $y:expr, $z:expr) => {
        _mm_xor_si128($y, _mm_or_si128($x, _mm_xor_si128($z, _mm_set1_epi32(-1))))
    };
}

/// One MD5 step across all four lanes.
///
/// `$a + m + T` is hoisted into its own statement: none of those three depend
/// on the register the previous step wrote, so that add stays off the serial
/// dependency chain, leaving only the nonlinear function, one add, the rotate
/// and the final add on it.
macro_rules! step4 {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:literal, $i:literal) => {
        // SAFETY: `$x` is one element of the caller's `[[u32; 4]; 16]`, i.e. a
        // `[u32; 4]` -- exactly 16 bytes, one vector wide.
        let x = unsafe { _mm_loadu_si128($x.as_ptr().cast()) };
        let acc = _mm_add_epi32(_mm_add_epi32($a, x), _mm_set1_epi32(T[$i] as i32));
        let acc = _mm_add_epi32(acc, nonlinear4!($f, $b, $c, $d));
        let rot = _mm_or_si128(
            _mm_slli_epi32::<$s>(acc),
            _mm_srli_epi32::<{ 32 - $s }>(acc),
        );
        $a = _mm_add_epi32(rot, $b);
    };
}

/// Compresses one 64-byte block in each of four lanes into `state`.
///
/// Both arrays are lane-transposed: `state[k][lane]` is state word `k` of
/// message `lane`, and `m[word][lane]` is message word `word` of message
/// `lane`. `super::digest::group_digest` produces that layout.
///
/// # Safety
///
/// The caller must ensure the `sse2` target feature is available on this CPU.
/// `super::digest::digest_many` is the only caller and checks this (it is part of
/// the x86-64 baseline). No other invariants are required: both arguments are
/// fixed-size arrays, so every vector load and store below is in bounds by
/// construction.
#[target_feature(enable = "sse2")]
pub(super) unsafe fn compress4(state: &mut [[u32; 4]; 4], m: &[[u32; 4]; 16]) {
    // SAFETY: each `state[k]` is a `[u32; 4]`, exactly one vector wide.
    let (a0, b0, c0, d0) = unsafe {
        (
            _mm_loadu_si128(state[0].as_ptr().cast()),
            _mm_loadu_si128(state[1].as_ptr().cast()),
            _mm_loadu_si128(state[2].as_ptr().cast()),
            _mm_loadu_si128(state[3].as_ptr().cast()),
        )
    };
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    md5_schedule!(step4, a, b, c, d, m);

    // SAFETY: as above -- four in-bounds one-vector stores.
    unsafe {
        _mm_storeu_si128(state[0].as_mut_ptr().cast(), _mm_add_epi32(a0, a));
        _mm_storeu_si128(state[1].as_mut_ptr().cast(), _mm_add_epi32(b0, b));
        _mm_storeu_si128(state[2].as_mut_ptr().cast(), _mm_add_epi32(c0, c));
        _mm_storeu_si128(state[3].as_mut_ptr().cast(), _mm_add_epi32(d0, d));
    }
}

/// The four nonlinear functions, RFC 1321 section 3.4, at 256-bit width.
/// Identical to [`nonlinear4`] with the 256-bit intrinsics.
macro_rules! nonlinear8 {
    (F, $x:expr, $y:expr, $z:expr) => {
        _mm256_or_si256(_mm256_and_si256($x, $y), _mm256_andnot_si256($x, $z))
    };
    (G, $x:expr, $y:expr, $z:expr) => {
        _mm256_or_si256(_mm256_and_si256($z, $x), _mm256_andnot_si256($z, $y))
    };
    (H, $x:expr, $y:expr, $z:expr) => {
        _mm256_xor_si256(_mm256_xor_si256($x, $y), $z)
    };
    (I, $x:expr, $y:expr, $z:expr) => {
        _mm256_xor_si256(
            $y,
            _mm256_or_si256($x, _mm256_xor_si256($z, _mm256_set1_epi32(-1))),
        )
    };
}

/// One MD5 step across all eight lanes. Identical to [`step4`] at 256 bits.
macro_rules! step8 {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:literal, $i:literal) => {
        // SAFETY: `$x` is one element of the caller's `[[u32; 8]; 16]`, i.e. a
        // `[u32; 8]` -- exactly 32 bytes, one vector wide.
        let x = unsafe { _mm256_loadu_si256($x.as_ptr().cast()) };
        let acc = _mm256_add_epi32(_mm256_add_epi32($a, x), _mm256_set1_epi32(T[$i] as i32));
        let acc = _mm256_add_epi32(acc, nonlinear8!($f, $b, $c, $d));
        let rot = _mm256_or_si256(
            _mm256_slli_epi32::<$s>(acc),
            _mm256_srli_epi32::<{ 32 - $s }>(acc),
        );
        $a = _mm256_add_epi32(rot, $b);
    };
}

/// Compresses one 64-byte block in each of eight lanes into `state`.
///
/// The 256-bit counterpart of [`compress4`]; see it for the array layout.
///
/// # Safety
///
/// The caller must ensure the `avx2` target feature is available on this CPU.
/// `super::digest::digest_many` is the only caller and checks this. No other
/// invariants are required: both arguments are fixed-size arrays, so every
/// vector load and store below is in bounds by construction.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn compress8(state: &mut [[u32; 8]; 4], m: &[[u32; 8]; 16]) {
    // SAFETY: each `state[k]` is a `[u32; 8]`, exactly one vector wide.
    let (a0, b0, c0, d0) = unsafe {
        (
            _mm256_loadu_si256(state[0].as_ptr().cast()),
            _mm256_loadu_si256(state[1].as_ptr().cast()),
            _mm256_loadu_si256(state[2].as_ptr().cast()),
            _mm256_loadu_si256(state[3].as_ptr().cast()),
        )
    };
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    md5_schedule!(step8, a, b, c, d, m);

    // SAFETY: as above -- four in-bounds one-vector stores.
    unsafe {
        _mm256_storeu_si256(state[0].as_mut_ptr().cast(), _mm256_add_epi32(a0, a));
        _mm256_storeu_si256(state[1].as_mut_ptr().cast(), _mm256_add_epi32(b0, b));
        _mm256_storeu_si256(state[2].as_mut_ptr().cast(), _mm256_add_epi32(c0, c));
        _mm256_storeu_si256(state[3].as_mut_ptr().cast(), _mm256_add_epi32(d0, d));
    }
}
