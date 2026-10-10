//! GHASH's multiplication in portable code: three 64-by-64-bit carry-less
//! products (Karatsuba), each made from integer multiplications, which is the
//! `ctmul64` design of Thomas Pornin's BearSSL.
//!
//! It is always compiled, it is the fallback on any CPU without carry-less
//! multiply instructions, and it is the reference that every other backend is
//! tested against. It also computes the powers of `H` that those backends
//! start from.
//!
//! The usual fast software GHASH multiplies with tables of multiples of `H`,
//! looked up at positions given by the value being hashed, which is secret.
//! This one never indexes memory or branches on data, and is constant-time
//! wherever 64-bit multiplication is, as on current aarch64 and x86-64 cores.

use super::ghash::{reduce, words};
use crate::wipe::wipe;

/// The hash key `H`, in the forms that a multiplication by it uses.
pub(super) struct Key {
    /// `[h_hi, h_lo, h_hi ^ h_lo]`: the two halves and the third operand of
    /// Karatsuba.
    words: [u64; 3],
    /// The same three, each bit-reversed, for the high halves of the products.
    reversed: [u64; 3],
}

impl Key {
    /// `h` is `[hi, lo]`, the layout of [`words`].
    pub(super) fn new(h: [u64; 2]) -> Self {
        let words = [h[0], h[1], h[0] ^ h[1]];
        Self {
            words,
            reversed: words.map(u64::reverse_bits),
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        wipe(&mut self.words);
        wipe(&mut self.reversed);
    }
}

/// The low 64 bits of the carry-less product of `x` and `y`, from integer
/// multiplications.
///
/// An integer product adds its partial products where a carry-less one XORs
/// them, and the carries are the difference. Each operand is split into four,
/// `x0` keeping the bits at positions 0, 4, 8, ..., `x1` those at 1, 5, 9, ...,
/// and so on. The partial products of `xi * yj` then all land at positions
/// `i + j` modulo 4, with three free bits above each to take its carries. A
/// position collects at most 16 partial products, and only above bit 59, so a
/// carry that does not fit in the gap leaves the word altogether. Keeping the
/// positions of each class from the right four products gives the bits, and
/// so the parities, of the carry-less product.
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// The 256-bit carry-less product of `y` and `H`, as `[v0, v1, v2, v3]` with
/// `v3` the most significant word, before [`reduce`].
///
/// Karatsuba: the products of the low halves, the high halves and the XORs of
/// the halves. The low 64 bits of each come from [`bmul64`] directly, and the
/// high 64 from the bit-reversed operands, since reversing both factors
/// reverses their product: the low half of that, reversed again and shifted
/// down one, is the high half wanted.
fn product(y: [u64; 2], key: &Key) -> [u64; 4] {
    let [y_hi, y_lo] = y;
    let y_mid = y_hi ^ y_lo;
    let [h_hi, h_lo, h_mid] = key.words;
    let [h_hi_rev, h_lo_rev, h_mid_rev] = key.reversed;

    let lo = bmul64(y_lo, h_lo);
    let hi = bmul64(y_hi, h_hi);
    let mid = bmul64(y_mid, h_mid) ^ lo ^ hi;
    let lo_high = bmul64(y_lo.reverse_bits(), h_lo_rev);
    let hi_high = bmul64(y_hi.reverse_bits(), h_hi_rev);
    let mid_high = bmul64(y_mid.reverse_bits(), h_mid_rev) ^ lo_high ^ hi_high;
    let lo_high = lo_high.reverse_bits() >> 1;
    let hi_high = hi_high.reverse_bits() >> 1;
    let mid_high = mid_high.reverse_bits() >> 1;

    [lo, lo_high ^ mid, hi ^ mid_high, hi_high]
}

/// `y * H` in GF(2^128) (SP 800-38D section 6.3), `y` as `[hi, lo]`.
pub(super) fn mul(y: [u64; 2], key: &Key) -> [u64; 2] {
    reduce(product(y, key))
}

/// GHASH of `blocks` into `y`: one multiplication per block.
pub(super) fn update(key: &Key, y: &mut [u64; 2], blocks: &[[u8; 16]]) {
    for block in blocks {
        let (hi, lo) = words(block);
        *y = mul([y[0] ^ hi, y[1] ^ lo], key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcm::tests::stream;

    /// Algorithm 1 of SP 800-38D, bit by bit as the standard writes it, on
    /// 128-bit integers whose most significant bit is the first bit of the
    /// block. Not constant-time: a reference for the tests only.
    fn mul_reference(x: u128, y: u128) -> u128 {
        const R: u128 = 0xe1 << 120;
        let (mut z, mut v) = (0u128, y);
        for i in 0..128 {
            if (x >> (127 - i)) & 1 == 1 {
                z ^= v;
            }
            v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
        }
        z
    }

    #[test]
    fn multiplication_matches_algorithm_1() {
        // The spec vectors multiply by only a few hash keys, at random-looking
        // values, whose integer products rarely collect many carries in one
        // place. Dense operands (all ones, every fourth bit, ...) are where a
        // gap in `bmul64` that is one bit too narrow would show.
        let dense: [u128; 7] = [
            0,
            1,
            1 << 127,
            u128::MAX,
            0x1111_1111_1111_1111_1111_1111_1111_1111,
            0x8888_8888_8888_8888_8888_8888_8888_8888,
            0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
        ];
        let derived = (0..64u32).map(|i| {
            let bytes: [u8; 16] = stream(b"ghash operand", i, 16).try_into().unwrap();
            u128::from_be_bytes(bytes)
        });
        let operands: Vec<u128> = dense.into_iter().chain(derived).collect();
        for &x in &operands {
            for &h in &operands {
                let key = Key::new([(h >> 64) as u64, h as u64]);
                let [hi, lo] = mul([(x >> 64) as u64, x as u64], &key);
                let ours = (u128::from(hi) << 64) | u128::from(lo);
                assert_eq!(ours, mul_reference(x, h), "{x:032x} * {h:032x}");
            }
        }
    }

    /// Dropping the key must leave none of it behind.
    #[test]
    fn dropping_wipes_the_key() {
        let key = Key::new([0x7777_7777_7777_7777, 0x1234_5678_9abc_def0]);
        // SAFETY: a key is six `u64`s, with no padding.
        let (before, after) = unsafe { crate::wipe::bytes_around_drop(key) };
        assert!(before.iter().any(|&b| b != 0), "no key to wipe");
        assert!(after.iter().all(|&b| b == 0), "the key survives the drop");
    }
}
