//! Arithmetic modulo `2^255 - 19`, the field of Curve25519, for X25519.
//!
//! A number is five limbs of 51 bits: `x = l0 + l1 * 2^51 + ... + l4 * 2^204`.
//! Five limbs of 51 bits cover 255 bits, which is the size of the prime, and
//! they leave 13 bits of headroom in each 64-bit word, so the sum of five
//! products of limbs fits in a `u128` and the carries can wait until the end of
//! a multiplication. The prime is `2^255 - 19`, so a carry out of the top limb
//! is a multiple of `2^255`, which is `19` modulo the prime: it folds back into
//! the lowest limb with one multiplication by 19, and that is all the reduction
//! there is.
//!
//! Limbs are not kept below `2^51`. A *weakly reduced* number has every limb
//! below `2^51 + 2^13`, which is what `mul`, `square`, `sub` and `mul_small`
//! return, and sums of two such numbers (below `2^53`) can go straight into
//! the next operation. `mul` and `square` accept limbs up to `2^54`. Only
//! `to_bytes` produces the one canonical representative below the prime.
//!
//! None of it depends on the value of a number: every function does the same
//! operations whatever its inputs are, and there is no table.

use super::ct;
use core::ops::{Add, Mul, Sub};

const LOW_51_BITS: u64 = (1 << 51) - 1;

/// A number modulo `2^255 - 19`, in five limbs of about 51 bits.
#[derive(Clone, Copy)]
pub(super) struct Fe([u64; 5]);

/// `a * b` as a `u128`.
#[inline(always)]
fn m(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}

impl Fe {
    pub(super) const ZERO: Fe = Fe([0; 5]);
    pub(super) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// The number whose little-endian encoding is `bytes`. The top bit of the
    /// last byte is ignored, as RFC 7748 asks of a `u` coordinate. A value
    /// from `2^255 - 19` to `2^255 - 1` is accepted as it is, and means the
    /// same as the value minus the prime.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Fe {
        // The limbs start at bits 0, 51, 102, 153 and 204, which are bit 0 of
        // byte 0 and bits 3, 6, 1 and 4 of bytes 6, 12, 19 and 25. Each is read
        // from an 8-byte word at a byte at or before its start and shifted
        // down; the last one starts at byte 24 and shifts by 12, because a word
        // at byte 25 would run past the end.
        let load = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
        Fe([
            load(0) & LOW_51_BITS,
            (load(6) >> 3) & LOW_51_BITS,
            (load(12) >> 6) & LOW_51_BITS,
            (load(19) >> 1) & LOW_51_BITS,
            // This one also drops the top bit of the encoding.
            (load(24) >> 12) & LOW_51_BITS,
        ])
    }

    /// The canonical little-endian encoding: the one representative of the
    /// number that is below the prime.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut limbs = Fe::weak_reduce(self.0).0;

        // Every limb is below 2^51 + 2^13 (the first a little more), so the
        // number h is below 2^255 + 2^218, which is under 2p, and it is
        // `h - q * p` for a q of 0 or 1. q is 1 exactly when `h + 19` carries
        // out of bit 255, which a chain of carries through the limbs finds out.
        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;

        // `h - q * (2^255 - 19) = h + 19 * q - q * 2^255`: add 19 * q, carry
        // it through, and discard what comes out of the top (the `q * 2^255`).
        limbs[0] += 19 * q;
        limbs[1] += limbs[0] >> 51;
        limbs[0] &= LOW_51_BITS;
        limbs[2] += limbs[1] >> 51;
        limbs[1] &= LOW_51_BITS;
        limbs[3] += limbs[2] >> 51;
        limbs[2] &= LOW_51_BITS;
        limbs[4] += limbs[3] >> 51;
        limbs[3] &= LOW_51_BITS;
        limbs[4] &= LOW_51_BITS;

        // Pack 5 * 51 = 255 bits into 32 bytes.
        let mut out = [0u8; 32];
        let word = |lo: u64, hi: u64, shift: u32| lo | (hi << shift);
        out[0..8].copy_from_slice(&word(limbs[0], limbs[1], 51).to_le_bytes());
        out[8..16].copy_from_slice(&word(limbs[1] >> 13, limbs[2], 38).to_le_bytes());
        out[16..24].copy_from_slice(&word(limbs[2] >> 26, limbs[3], 25).to_le_bytes());
        out[24..32].copy_from_slice(&word(limbs[3] >> 39, limbs[4], 12).to_le_bytes());
        out
    }

    /// Brings every limb below `2^51 + 2^13` (the first below `2^51 + 19 * 2^13`)
    /// by carrying each limb's excess into the next, and the top one's, times
    /// 19, into the first. Any 64-bit limbs will do.
    #[inline(always)]
    fn weak_reduce(mut limbs: [u64; 5]) -> Fe {
        // The carries are below 2^13, so adding them cannot overflow.
        let c0 = limbs[0] >> 51;
        let c1 = limbs[1] >> 51;
        let c2 = limbs[2] >> 51;
        let c3 = limbs[3] >> 51;
        let c4 = limbs[4] >> 51;

        limbs[0] &= LOW_51_BITS;
        limbs[1] &= LOW_51_BITS;
        limbs[2] &= LOW_51_BITS;
        limbs[3] &= LOW_51_BITS;
        limbs[4] &= LOW_51_BITS;

        limbs[0] += c4 * 19;
        limbs[1] += c0;
        limbs[2] += c1;
        limbs[3] += c2;
        limbs[4] += c3;
        Fe(limbs)
    }

    /// Carries five columns of a product, each a sum of products of limbs, into
    /// weakly reduced limbs.
    ///
    /// Columns below `2^115` give carries below `2^64`, so each carry fits a
    /// `u64`, which the casts tell the compiler (it then adds a 64-bit number
    /// to a 128-bit one, not two of 128 bits). The product of two numbers with
    /// limbs below `2^54` has columns of five terms of `19 * 2^108` at most.
    #[inline(always)]
    fn carry_columns([c0, mut c1, mut c2, mut c3, mut c4]: [u128; 5]) -> Fe {
        c1 += u128::from((c0 >> 51) as u64);
        let l0 = (c0 as u64) & LOW_51_BITS;
        c2 += u128::from((c1 >> 51) as u64);
        let l1 = (c1 as u64) & LOW_51_BITS;
        c3 += u128::from((c2 >> 51) as u64);
        let l2 = (c2 as u64) & LOW_51_BITS;
        c4 += u128::from((c3 >> 51) as u64);
        let l3 = (c3 as u64) & LOW_51_BITS;
        // The top column is five products of limbs, none of them multiplied by
        // 19, so below 5 * 2^108, plus the carry out of the column before it
        // (below 2^62). Its own carry is then below 5 * 2^57 + 2^14, and 19
        // times that plus the 51 bits of `l0` is below 2^64 (it is below 2^63.6).
        let carry = (c4 >> 51) as u64;
        let l4 = (c4 as u64) & LOW_51_BITS;

        let l0 = l0 + carry * 19;
        // One more carry from the first limb into the second, so that no limb
        // is above 2^51 + 2^13.
        Fe([l0 & LOW_51_BITS, l1 + (l0 >> 51), l2, l3, l4])
    }

    /// `self * k` for a small `k` (below `2^20`, or the limbs of the result
    /// outgrow the bounds above).
    pub(super) fn mul_small(&self, k: u64) -> Fe {
        let l = &self.0;
        Fe::carry_columns([m(l[0], k), m(l[1], k), m(l[2], k), m(l[3], k), m(l[4], k)])
    }

    /// `self * self`, with the 15 distinct products of limbs a square has in
    /// place of the 25 of a general product.
    #[inline(always)]
    pub(super) fn square(&self) -> Fe {
        let [a0, a1, a2, a3, a4] = self.0;

        // Products that reach past the top limb wrap around with a factor of
        // 19 (2^255 = 19), and the cross products appear twice.
        let a3_19 = 19 * a3;
        let a4_19 = 19 * a4;
        let c0 = m(a0, a0) + 2 * (m(a1, a4_19) + m(a2, a3_19));
        let c1 = m(a3, a3_19) + 2 * (m(a0, a1) + m(a2, a4_19));
        let c2 = m(a1, a1) + 2 * (m(a0, a2) + m(a4, a3_19));
        let c3 = m(a4, a4_19) + 2 * (m(a0, a3) + m(a1, a2));
        let c4 = m(a2, a2) + 2 * (m(a0, a4) + m(a1, a3));
        Fe::carry_columns([c0, c1, c2, c3, c4])
    }

    /// `self^(2^k)`, for `k` of at least 1.
    #[inline(always)]
    fn square_repeatedly(&self, k: u32) -> Fe {
        let mut x = self.square();
        for _ in 1..k {
            x = x.square();
        }
        x
    }

    /// `self^(p - 2) = self^(2^255 - 21)`, the inverse of a non-zero number and
    /// zero for zero. The exponent is a constant, so this takes 254 squarings
    /// and 11 products by the same route for every input.
    pub(super) fn invert(&self) -> Fe {
        // The chain builds z^(2^k - 1) for growing k: 5, 10, 20, 40, 50, 100,
        // 200 and 250 ones in a row, and finishes with z^(2^255 - 32) * z^11.
        let z = *self;
        let z2 = z.square();
        let z9 = z * z2.square_repeatedly(2);
        let z11 = z2 * z9;
        let z_5 = z9 * z11.square(); // z^(2^5 - 1)
        let z_10 = z_5.square_repeatedly(5) * z_5;
        let z_20 = z_10.square_repeatedly(10) * z_10;
        let z_40 = z_20.square_repeatedly(20) * z_20;
        let z_50 = z_40.square_repeatedly(10) * z_10;
        let z_100 = z_50.square_repeatedly(50) * z_50;
        let z_200 = z_100.square_repeatedly(100) * z_100;
        let z_250 = z_200.square_repeatedly(50) * z_50;
        z_250.square_repeatedly(5) * z11
    }

    /// `a` where `mask` is all ones and `b` where it is all zeros.
    #[inline(always)]
    pub(super) fn select(mask: u64, a: &Fe, b: &Fe) -> Fe {
        Fe(core::array::from_fn(|i| ct::select(mask, a.0[i], b.0[i])))
    }
}

impl Add for Fe {
    type Output = Fe;

    /// The limbs add up, with no carry: two weakly reduced numbers give limbs
    /// below `2^53`, which `mul` and `square` take.
    #[inline(always)]
    fn add(self, rhs: Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl Sub for Fe {
    type Output = Fe;

    /// `self - rhs`, with `rhs`'s limbs below `2^54`. To keep each limb from going
    /// below zero, 16 times the prime is added first: `16 * (2^255 - 19)` in
    /// these limbs is `16 * (2^51 - 19)` for the first and `16 * (2^51 - 1)` for
    /// the others.
    #[inline(always)]
    fn sub(self, rhs: Fe) -> Fe {
        Fe::weak_reduce([
            (self.0[0] + 36028797018963664) - rhs.0[0],
            (self.0[1] + 36028797018963952) - rhs.0[1],
            (self.0[2] + 36028797018963952) - rhs.0[2],
            (self.0[3] + 36028797018963952) - rhs.0[3],
            (self.0[4] + 36028797018963952) - rhs.0[4],
        ])
    }
}

impl Mul for Fe {
    type Output = Fe;

    /// The product, for limbs below `2^54`.
    #[inline(always)]
    fn mul(self, rhs: Fe) -> Fe {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;

        // Column i of the product gathers a_j * b_k with j + k = i, and the
        // columns j + k = i + 5 as well, times 19 (2^255 = 19).
        let (b1_19, b2_19, b3_19, b4_19) = (19 * b1, 19 * b2, 19 * b3, 19 * b4);
        let c0 = m(a0, b0) + m(a4, b1_19) + m(a3, b2_19) + m(a2, b3_19) + m(a1, b4_19);
        let c1 = m(a1, b0) + m(a0, b1) + m(a4, b2_19) + m(a3, b3_19) + m(a2, b4_19);
        let c2 = m(a2, b0) + m(a1, b1) + m(a0, b2) + m(a4, b3_19) + m(a3, b4_19);
        let c3 = m(a3, b0) + m(a2, b1) + m(a1, b2) + m(a0, b3) + m(a4, b4_19);
        let c4 = m(a4, b0) + m(a3, b1) + m(a2, b2) + m(a1, b3) + m(a0, b4);
        Fe::carry_columns([c0, c1, c2, c3, c4])
    }
}

#[cfg(test)]
mod tests {
    use super::super::field::{Fe as Generic, Modulus};
    use super::*;
    use crate::{Digest, sha2::Sha512};

    /// `2^255 - 19` in the generic Montgomery field, which this module is
    /// checked against.
    struct Prime;
    impl Modulus<4> for Prime {
        const P: [u64; 4] = [
            0xffff_ffff_ffff_ffed,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ];
    }
    type Reference = Generic<Prime, 4>;

    /// The value of a number of this module in the reference field: the sum of
    /// its limbs times powers of `2^51`, whatever the size of its limbs.
    fn reference(x: &Fe) -> Reference {
        let radix = Reference::from_limbs([1 << 51, 0, 0, 0]);
        // Horner's rule, from the top limb down. A limb is below 2^64 and the
        // prime is above 2^254, so each is a valid element.
        x.0.iter().rev().fold(Reference::ZERO, |acc, &limb| {
            acc * radix + Reference::from_limbs([limb, 0, 0, 0])
        })
    }

    /// The canonical little-endian bytes of a reference number.
    fn canonical(x: &Reference) -> [u8; 32] {
        let mut out = [0; 32];
        x.write_be_bytes(&mut out);
        out.reverse();
        out
    }

    /// Checks that `x` and the reference number are the same number, through the
    /// canonical bytes of both.
    fn assert_same(x: &Fe, expected: &Reference, what: &str) {
        assert_eq!(x.to_bytes(), canonical(expected), "{what}");
    }

    /// Bytes to try: pseudo-random ones from a hash, and the edges of the
    /// encoding, where the carries and the reduction are.
    fn samples() -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for i in 0u32..120 {
            let digest = Sha512::digest(&i.to_le_bytes());
            out.push(digest[..32].try_into().unwrap());
            out.push(digest[32..].try_into().unwrap());
        }
        let le = |value: &[u8]| {
            let mut bytes = [0u8; 32];
            bytes[..value.len()].copy_from_slice(value);
            bytes
        };
        let all_ones = [0xff; 32];
        let mut p_minus_1 = [0xff; 32];
        p_minus_1[0] = 0xec;
        p_minus_1[31] = 0x7f;
        let mut p = p_minus_1;
        p[0] = 0xed;
        let mut p_plus_1 = p_minus_1;
        p_plus_1[0] = 0xee;
        let mut two_255_minus_1 = [0xff; 32];
        two_255_minus_1[31] = 0x7f;
        out.extend([
            [0; 32],
            le(&[1]),
            le(&[2]),
            le(&[19]),
            le(&[9]),
            p_minus_1,
            p,
            p_plus_1,
            two_255_minus_1,
            all_ones,
            // 2^51 and 2^51 - 1: a limb on either side of its carry.
            le(&[0, 0, 0, 0, 0, 0, 8]),
            le(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7]),
        ]);
        out
    }

    fn generic_from_bytes(bytes: &[u8; 32]) -> Reference {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        limbs[3] &= 0x7fff_ffff_ffff_ffff;
        Reference::from_limbs_below_double(limbs)
    }

    #[test]
    fn bytes_round_trip_and_reduce() {
        for bytes in samples() {
            let x = Fe::from_bytes(&bytes);
            assert_same(&x, &generic_from_bytes(&bytes), &format!("{bytes:02x?}"));
        }
        // Values below the prime come back as they went in (with the top bit
        // cleared), and values from the prime up come back reduced.
        let mut below = [0xff; 32];
        below[0] = 0xec;
        below[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&below).to_bytes(), below);
        let mut p = below;
        p[0] = 0xed;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0; 32]);
        p[0] = 0xee;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), Fe::ONE.to_bytes());
    }

    #[test]
    fn arithmetic_matches_the_generic_field() {
        let samples = samples();
        for (i, a) in samples.iter().enumerate() {
            let (x, rx) = (Fe::from_bytes(a), generic_from_bytes(a));
            assert_same(&x.square(), &rx.square(), "square");
            assert_same(&x.invert(), &rx.invert(), "invert");
            for k in [0u64, 1, 2, 121_665, (1 << 20) - 1] {
                let rk = Reference::from_limbs([k, 0, 0, 0]);
                assert_same(&x.mul_small(k), &(rx * rk), "mul_small");
            }
            // Pair each with a few others, rather than with all of them.
            for b in samples.iter().skip(i % 7).step_by(11) {
                let (y, ry) = (Fe::from_bytes(b), generic_from_bytes(b));
                assert_same(&(x * y), &(rx * ry), "mul");
                assert_same(&(x + y), &(rx + ry), "add");
                assert_same(&(x - y), &(rx - ry), "sub");
            }
        }
    }

    /// The operations promise to take limbs up to a bound: 2^54 for a product,
    /// and 2^54 for the subtrahend. Run them at the bound, where a carry that
    /// the analysis missed would show.
    #[test]
    fn limbs_at_the_documented_bounds() {
        let max = (1u64 << 54) - 1;
        let patterns = [
            [max; 5],
            [max, 0, max, 0, max],
            [0, max, 0, max, 0],
            [max, max, max, max, 0],
            [0, 0, 0, 0, max],
            [max, 0, 0, 0, 0],
        ];
        for a in patterns {
            for b in patterns {
                let (x, y) = (Fe(a), Fe(b));
                let (rx, ry) = (reference(&x), reference(&y));
                assert_same(&(x * y), &(rx * ry), &format!("{a:x?} * {b:x?}"));
                assert_same(&(x - y), &(rx - ry), &format!("{a:x?} - {b:x?}"));
            }
            let x = Fe(a);
            assert_same(&x.square(), &(reference(&x) * reference(&x)), "square");
            assert_same(
                &x.mul_small(121_665),
                &(reference(&x) * Reference::from_limbs([121_665, 0, 0, 0])),
                "mul_small",
            );
        }
        // The results of one operation are fit to be the inputs of the next.
        let mut x = Fe([max; 5]);
        let mut rx = reference(&x);
        for _ in 0..50 {
            x = (x * x) + (x * x);
            rx = rx * rx + rx * rx;
            assert!(x.0.iter().all(|&limb| limb < (1 << 54)), "{:x?}", x.0);
            assert_same(&x, &rx, "chain");
        }
    }

    #[test]
    fn select_picks_by_the_mask() {
        let (a, b) = (Fe([1, 2, 3, 4, 5]), Fe([6, 7, 8, 9, 10]));
        assert_eq!(Fe::select(u64::MAX, &a, &b).0, a.0);
        assert_eq!(Fe::select(0, &a, &b).0, b.0);
    }
}
