//! GHASH on Armv8's carry-less multiplication, `PMULL` (FEAT_PMULL, which
//! Rust reports together with FEAT_AES as the `aes` feature).
//!
//! `PMULL` multiplies the low 64-bit lanes of two vectors as polynomials over
//! GF(2), giving the 128-bit product, and `PMULL2` the high lanes. A product of
//! two 128-bit blocks is four of them, schoolbook: the low halves, the high
//! halves, and the two crossings. Sixteen blocks at a time are multiplied
//! by `H^16` down to `H`, the products added, and the sum reduced once, in
//! general-purpose registers, by the same [`reduce`] as the scalar backend. The
//! sixteen products are independent of one another, so the multiplications of
//! one block overlap those of the next instead of waiting on a reduction.
//! Karatsuba's three products instead of four measured 15% slower here (an
//! Apple M1 Pro), as it adds a shuffle and an XOR on the path of every block.
//!
//! No data is used as an address or a branch condition: the instructions take
//! the same time whatever their operands.
//!
//! This code only runs via `super::ghash`, which checks the `aes` CPU feature
//! is present before calling it.

use core::arch::aarch64::*;

use super::ghash::{AGGREGATE, Powers, reduce};

/// Loads a block as GHASH reads it: the 128-bit big-endian integer, with its
/// low half in lane 0 and its high half in lane 1.
#[target_feature(enable = "aes")]
#[inline]
fn load(block: &[u8; 16]) -> uint64x2_t {
    // SAFETY: `block` is 16 bytes, so the 16-byte load is in bounds, and NEON
    // loads of bytes have no alignment requirement.
    let bytes = unsafe { vld1q_u8(block.as_ptr()) };
    // Reversing the bytes of each half and then swapping the halves reverses
    // the whole block, which read as two little-endian lanes is the big-endian
    // integer.
    let reversed = vrev64q_u8(bytes);
    vreinterpretq_u64_u8(vextq_u8::<8>(reversed, reversed))
}

/// Loads two 64-bit words into the two lanes of a vector, in order.
#[target_feature(enable = "aes")]
#[inline]
fn load_pair(words: &[u64; 2]) -> uint64x2_t {
    // SAFETY: `words` is two `u64`s, so the 16-byte load is in bounds, and it
    // is aligned for them.
    unsafe { vld1q_u64(words.as_ptr()) }
}

/// The carry-less product of the low lanes of `a` and `b` (`PMULL`).
#[target_feature(enable = "aes")]
#[inline]
fn mul_low(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(b)))
}

/// The carry-less product of the high lanes of `a` and `b` (`PMULL2`).
#[target_feature(enable = "aes")]
#[inline]
fn mul_high(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    vreinterpretq_u64_p128(vmull_high_p64(
        vreinterpretq_p64_u64(a),
        vreinterpretq_p64_u64(b),
    ))
}

/// The product of `x` and a power `h` of `H`, as the three parts `[lo, mid,
/// hi]` of `lo + mid 2^64 + hi 2^128`: four multiplications, schoolbook.
#[target_feature(enable = "aes")]
#[inline]
fn product(x: uint64x2_t, h: uint64x2_t) -> [uint64x2_t; 3] {
    // `h` with its lanes exchanged, for the two crossed products.
    let h_swapped = vextq_u64::<1>(h, h);
    [
        mul_low(x, h),
        veorq_u64(mul_low(x, h_swapped), mul_high(x, h_swapped)),
        mul_high(x, h),
    ]
}

/// The sum of two products, part by part.
#[target_feature(enable = "aes")]
#[inline]
fn add(a: [uint64x2_t; 3], b: [uint64x2_t; 3]) -> [uint64x2_t; 3] {
    [
        veorq_u64(a[0], b[0]),
        veorq_u64(a[1], b[1]),
        veorq_u64(a[2], b[2]),
    ]
}

/// Reduces a sum of products to `[hi, lo]`, as four words for [`reduce`].
#[target_feature(enable = "aes")]
#[inline]
fn finish([lo, mid, hi]: [uint64x2_t; 3]) -> [u64; 2] {
    reduce([
        vgetq_lane_u64::<0>(lo),
        vgetq_lane_u64::<1>(lo) ^ vgetq_lane_u64::<0>(mid),
        vgetq_lane_u64::<0>(hi) ^ vgetq_lane_u64::<1>(mid),
        vgetq_lane_u64::<1>(hi),
    ])
}

/// `y` as a vector: `[lo, hi]`.
#[target_feature(enable = "aes")]
#[inline]
fn running(y: &[u64; 2]) -> uint64x2_t {
    vcombine_u64(vcreate_u64(y[1]), vcreate_u64(y[0]))
}

/// GHASH of `blocks` into `y` (`[hi, lo]`), with the powers `H^1` to `H^16`.
///
/// For a group of `n` blocks, `Y = (Y ^ X1) H^n ^ X2 H^(n-1) ^ ... ^ Xn H`:
/// the running value goes into the first block only, and the `n` products are
/// independent. Whole groups of sixteen are unrolled, with the powers in
/// registers; the last group, if shorter, goes through a loop.
///
/// # Safety
///
/// The caller must make sure the `aes` CPU feature is available.
/// `super::ghash` is the only caller, and it checks this already.
#[target_feature(enable = "aes")]
pub(super) unsafe fn update(powers: &Powers, y: &mut [u64; 2], blocks: &[[u8; 16]]) {
    // H^k is `h[k - 1]`.
    let h: [uint64x2_t; AGGREGATE] = core::array::from_fn(|i| load_pair(&powers.0[i]));
    let times = |x: uint64x2_t, k: usize| product(x, h[k - 1]);

    let (groups, rest) = blocks.as_chunks::<AGGREGATE>();
    for group in groups {
        // Block `j` is multiplied by H^(AGGREGATE - j).
        let p: [[uint64x2_t; 3]; AGGREGATE] = core::array::from_fn(|j| {
            let mut x = load(&group[j]);
            if j == 0 {
                x = veorq_u64(x, running(y));
            }
            times(x, AGGREGATE - j)
        });
        let sum = p.into_iter().reduce(|a, b| add(a, b));
        *y = finish(sum.expect("a group is not empty"));
    }

    if !rest.is_empty() {
        let n = rest.len();
        let zero = vdupq_n_u64(0);
        let mut sum = [zero; 3];
        for (j, block) in rest.iter().enumerate() {
            let mut x = load(block);
            if j == 0 {
                x = veorq_u64(x, running(y));
            }
            sum = add(sum, times(x, n - j));
        }
        *y = finish(sum);
    }
}
