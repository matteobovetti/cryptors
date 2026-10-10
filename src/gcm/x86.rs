//! GHASH on x86's carry-less multiplication, `PCLMULQDQ`.
//!
//! `PCLMULQDQ` multiplies one 64-bit half of a register by one of another, the
//! halves chosen by its immediate, as polynomials over GF(2), giving the
//! 128-bit product. The structure is that of the aarch64 backend: four
//! products per block (schoolbook), sixteen blocks multiplied by `H^16` down to
//! `H` and added, then one reduction in general-purpose registers by the same
//! [`reduce`] as the scalar backend. SSSE3's byte shuffle reverses a block.
//!
//! No data is used as an address or a branch condition. This code only runs via
//! `super::ghash`, which checks the `pclmulqdq` and `ssse3` CPU features are
//! present before calling it.

use core::arch::x86_64::*;

use super::ghash::{AGGREGATE, Powers, reduce};

/// Loads a block as GHASH reads it: the 128-bit big-endian integer, with its
/// low half in the low 64 bits of the register.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn load(block: &[u8; 16]) -> __m128i {
    // SAFETY: `block` is 16 bytes, so the 16-byte load is in bounds, and
    // `loadu` has no alignment requirement.
    let bytes = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
    // Byte `i` of the result is byte `15 - i` of the block.
    let reverse = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    _mm_shuffle_epi8(bytes, reverse)
}

/// Loads two 64-bit words into the two halves of a register, in order.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn load_pair(words: &[u64; 2]) -> __m128i {
    // SAFETY: `words` is two `u64`s, so the 16-byte load is in bounds, and
    // `loadu` has no alignment requirement.
    unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
}

/// The two 64-bit halves of a register, `[low, high]`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn halves(v: __m128i) -> [u64; 2] {
    [
        _mm_cvtsi128_si64(v) as u64,
        _mm_cvtsi128_si64(_mm_unpackhi_epi64(v, v)) as u64,
    ]
}

/// The product of `x` and a power `h` of `H`, as the three parts `[lo, mid,
/// hi]` of `lo + mid 2^64 + hi 2^128`: four multiplications, schoolbook. The
/// immediate's bit 0 picks the half of `x`, bit 4 that of `h`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn product(x: __m128i, h: __m128i) -> [__m128i; 3] {
    [
        _mm_clmulepi64_si128::<0x00>(x, h),
        _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x, h),
            _mm_clmulepi64_si128::<0x10>(x, h),
        ),
        _mm_clmulepi64_si128::<0x11>(x, h),
    ]
}

/// The sum of two products, part by part.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn add(a: [__m128i; 3], b: [__m128i; 3]) -> [__m128i; 3] {
    [
        _mm_xor_si128(a[0], b[0]),
        _mm_xor_si128(a[1], b[1]),
        _mm_xor_si128(a[2], b[2]),
    ]
}

/// Reduces a sum of products to `[hi, lo]`, as four words for [`reduce`].
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn finish([lo, mid, hi]: [__m128i; 3]) -> [u64; 2] {
    let ([lo0, lo1], [mid0, mid1], [hi0, hi1]) = (halves(lo), halves(mid), halves(hi));
    reduce([lo0, lo1 ^ mid0, hi0 ^ mid1, hi1])
}

/// `y` as a register: `[lo, hi]`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn running(y: &[u64; 2]) -> __m128i {
    _mm_set_epi64x(y[0] as i64, y[1] as i64)
}

/// GHASH of `blocks` into `y` (`[hi, lo]`), with the powers `H^1` to
/// `H^AGGREGATE`, in the structure of the aarch64 backend: whole groups
/// unrolled with the powers in registers, the last group, if shorter, through
/// a loop.
///
/// # Safety
///
/// The caller must make sure the `pclmulqdq` and `ssse3` CPU features are
/// available. `super::ghash` is the only caller, and it checks this already.
#[target_feature(enable = "pclmulqdq,ssse3")]
pub(super) unsafe fn update(powers: &Powers, y: &mut [u64; 2], blocks: &[[u8; 16]]) {
    // H^k is `h[k - 1]`.
    let h: [__m128i; AGGREGATE] = core::array::from_fn(|i| load_pair(&powers.0[i]));
    let times = |x: __m128i, k: usize| product(x, h[k - 1]);

    let (groups, rest) = blocks.as_chunks::<AGGREGATE>();
    for group in groups {
        // Block `j` is multiplied by H^(AGGREGATE - j).
        let p: [[__m128i; 3]; AGGREGATE] = core::array::from_fn(|j| {
            let mut x = load(&group[j]);
            if j == 0 {
                x = _mm_xor_si128(x, running(y));
            }
            times(x, AGGREGATE - j)
        });
        let sum = p.into_iter().reduce(|a, b| add(a, b));
        *y = finish(sum.expect("a group is not empty"));
    }

    if !rest.is_empty() {
        let n = rest.len();
        let zero = _mm_setzero_si128();
        let mut sum = [zero; 3];
        for (j, block) in rest.iter().enumerate() {
            let mut x = load(block);
            if j == 0 {
                x = _mm_xor_si128(x, running(y));
            }
            sum = add(sum, times(x, n - j));
        }
        *y = finish(sum);
    }
}
