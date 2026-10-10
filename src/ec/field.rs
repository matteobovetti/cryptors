//! Arithmetic modulo a prime: the primes of the NIST curves and of Curve25519,
//! and the orders of the NIST curves, which are primes too.
//!
//! A number is kept as `N` little-endian 64-bit limbs in Montgomery form: the
//! number `x` is stored as `x * R mod p`, with `R = 2^(64 * N)`. Adding and
//! subtracting work on the stored values as they are, and a product is
//! Montgomery's reduction of the product of the stored values, which divides
//! out one factor of `R` and leaves the result in the same form. That replaces
//! the division by `p` of an ordinary modular product with shifts by whole
//! limbs, and the same few functions then serve a prime of any size and shape.
//!
//! Everything here is branch-free and indexes memory only by public values,
//! with two exceptions: parsing an encoded number rejects one that is not below
//! `p` as soon as it sees it (it is called on public numbers, and on private keys
//! and nonces that were checked to be in range, so for those the branch always goes
//! the same way), and the inversion follows the bits of `p - 2`, which is a
//! constant.
//!
//! The constants a field needs (`R mod p`, `R^2 mod p` and `-p^-1 mod 2^64`) are
//! computed from the prime at compile time, and so are the curve constants that
//! other modules convert to Montgomery form with `Fe::from_limbs`.

use super::ct;
use core::marker::PhantomData;
use core::ops::{Add, Mul, Sub};

/// The prime of a field.
pub(crate) trait Modulus<const N: usize>: 'static {
    /// The prime, as `N` little-endian limbs. It must be odd, and its top limb
    /// must not be zero.
    const P: [u64; N];
}

/// `a + b + carry` as a limb and a carry.
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow` as a limb and a borrow (0 or 1).
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, (t >> 127) as u64)
}

/// `acc + a * b + carry` as a limb and a carry. It cannot overflow: the sum is
/// at most `(2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1) = 2^128 - 1`.
#[inline(always)]
const fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = acc as u128 + a as u128 * b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// `a + b` as limbs and a carry out of the top one.
#[inline(always)]
const fn add_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut sum = [0; N];
    let mut carry = 0;
    let mut i = 0;
    while i < N {
        let (limb, c) = adc(a[i], b[i], carry);
        sum[i] = limb;
        carry = c;
        i += 1;
    }
    (sum, carry)
}

/// `a - b` as limbs and a borrow out of the top one, which is 1 exactly when
/// `a < b`.
#[inline(always)]
const fn sub_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut diff = [0; N];
    let mut borrow = 0;
    let mut i = 0;
    while i < N {
        let (limb, b_out) = sbb(a[i], b[i], borrow);
        diff[i] = limb;
        borrow = b_out;
        i += 1;
    }
    (diff, borrow)
}

/// `a` where `mask` is all ones and `b` where it is all zeros.
#[inline(always)]
const fn select_limbs<const N: usize>(mask: u64, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = ct::select(mask, a[i], b[i]);
        i += 1;
    }
    out
}

/// `(a + b) mod p` for `a` and `b` below `p`.
#[inline(always)]
const fn add_mod<const N: usize>(a: &[u64; N], b: &[u64; N], p: &[u64; N]) -> [u64; N] {
    let (sum, carry) = add_limbs(a, b);
    let (reduced, borrow) = sub_limbs(&sum, p);
    // `sum - p` is the answer when the sum did not fit in `N` limbs (it is then
    // at least `p`) or when it did and is at least `p`.
    select_limbs(ct::mask(carry | (borrow ^ 1)), &reduced, &sum)
}

/// `(a - b) mod p` for `a` and `b` below `p`.
#[inline(always)]
const fn sub_mod<const N: usize>(a: &[u64; N], b: &[u64; N], p: &[u64; N]) -> [u64; N] {
    let (diff, borrow) = sub_limbs(a, b);
    // If `a < b` the difference wrapped around 2^(64 * N); adding `p` brings
    // it back to the right residue.
    let mask = ct::mask(borrow);
    let mut addend = [0; N];
    let mut i = 0;
    while i < N {
        addend[i] = p[i] & mask;
        i += 1;
    }
    add_limbs(&diff, &addend).0
}

/// Montgomery's product (the CIOS method): `a * b / R mod p`, for `a` and `b`
/// below `p`. `inv` is `-p^-1 mod 2^64`.
///
/// Each of the `N` rounds adds `a * b[i]` to the accumulator, then adds the
/// multiple of `p` that makes its lowest limb zero, and drops that limb. After
/// the last round the accumulator is `(a * b + m * p) / R` for some `m` below
/// `R`, which is below `2p`, and a final conditional subtraction brings it into
/// range.
#[inline(always)]
const fn mont_mul<const N: usize>(a: &[u64; N], b: &[u64; N], p: &[u64; N], inv: u64) -> [u64; N] {
    // `t[N]` and `t[N + 1]` hold the two limbs that the accumulator can grow
    // by while a round is in progress.
    let mut t = [0u64; N];
    let mut hi = 0u64;
    let mut i = 0;
    while i < N {
        // t += a * b[i]
        let mut carry = 0;
        let mut j = 0;
        while j < N {
            let (limb, c) = mac(t[j], a[j], b[i], carry);
            t[j] = limb;
            carry = c;
            j += 1;
        }
        let (top, over) = adc(hi, carry, 0);

        // t = (t + m * p) / 2^64, with m chosen so that the low limb vanishes.
        let m = t[0].wrapping_mul(inv);
        let (_, mut carry) = mac(t[0], m, p[0], 0);
        let mut j = 1;
        while j < N {
            let (limb, c) = mac(t[j], m, p[j], carry);
            t[j - 1] = limb;
            carry = c;
            j += 1;
        }
        let (limb, c) = adc(top, carry, 0);
        t[N - 1] = limb;
        hi = over + c;
        i += 1;
    }

    // The accumulator is `hi * 2^(64 * N) + t`, below `2p`. Subtract `p` if it
    // is at least `p`: always when `hi` is set, otherwise when `t >= p`.
    let (reduced, borrow) = sub_limbs(&t, p);
    select_limbs(ct::mask(hi | (borrow ^ 1)), &reduced, &t)
}

/// `-p^-1 mod 2^64`, for odd `p0`, the lowest limb of the prime.
const fn neg_inv(p0: u64) -> u64 {
    // For odd `p0`, `p0 * p0 = 1 mod 8`, so `x = p0` is an inverse to 3 bits.
    // Each step of Newton's iteration doubles the number of correct bits, and
    // five of them take 3 to 96.
    let mut x = p0;
    let mut i = 0;
    while i < 5 {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

/// `2^(64 * N * k) mod p`, by doubling 1 that many times.
const fn power_of_r<const N: usize>(p: &[u64; N], k: usize) -> [u64; N] {
    let mut x = [0; N];
    x[0] = 1;
    let mut i = 0;
    while i < 64 * N * k {
        x = add_mod(&x, &x, p);
        i += 1;
    }
    x
}

/// The number of bits in `p`.
const fn bit_len<const N: usize>(p: &[u64; N]) -> usize {
    let mut i = N;
    while i > 0 {
        i -= 1;
        if p[i] != 0 {
            return 64 * i + (64 - p[i].leading_zeros() as usize);
        }
    }
    0
}

/// An element of the field of integers modulo `M::P`.
pub(crate) struct Fe<M: Modulus<N>, const N: usize> {
    /// `x * R mod p`, below `p`.
    limbs: [u64; N],
    modulus: PhantomData<M>,
}

impl<M: Modulus<N>, const N: usize> Clone for Fe<M, N> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: Modulus<N>, const N: usize> Copy for Fe<M, N> {}

impl<M: Modulus<N>, const N: usize> Fe<M, N> {
    /// `-p^-1 mod 2^64`.
    const INV: u64 = neg_inv(M::P[0]);
    /// `R mod p`: the number 1 in Montgomery form.
    const R: [u64; N] = power_of_r(&M::P, 1);
    /// `R^2 mod p`: multiplying by it converts to Montgomery form.
    const R2: [u64; N] = power_of_r(&M::P, 2);
    /// `p - 2`, the exponent of the inversion.
    const P_MINUS_2: [u64; N] = {
        let mut two = [0; N];
        two[0] = 2;
        sub_limbs(&M::P, &two).0
    };

    /// The length in bytes of the big-endian encoding of an element.
    pub(crate) const BYTES: usize = bit_len(&M::P).div_ceil(8);

    pub(crate) const ZERO: Self = Self {
        limbs: [0; N],
        modulus: PhantomData,
    };

    pub(crate) const ONE: Self = Self {
        limbs: Self::R,
        modulus: PhantomData,
    };

    /// The element with the value `limbs`, which must be below `p`. Usable in
    /// constants: a value that is out of range fails to compile.
    pub(crate) const fn from_limbs(limbs: [u64; N]) -> Self {
        let (_, borrow) = sub_limbs(&limbs, &M::P);
        assert!(borrow == 1, "value is not below the modulus");
        Self {
            limbs: mont_mul(&limbs, &Self::R2, &M::P, Self::INV),
            modulus: PhantomData,
        }
    }

    /// The element congruent to `limbs`, which must be below `2 * p`.
    #[cfg(test)]
    pub(crate) fn from_limbs_below_double(limbs: [u64; N]) -> Self {
        let (reduced, borrow) = sub_limbs(&limbs, &M::P);
        Self::from_limbs(select_limbs(ct::mask(borrow ^ 1), &reduced, &limbs))
    }

    /// The element with the value of the big-endian encoding `bytes`, or
    /// `None` if `bytes` is not exactly `BYTES` long or encodes a number that
    /// is not below `p`. The encoding is public, so this does not hide which.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let mut limbs = [0u64; N];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        let (_, borrow) = sub_limbs(&limbs, &M::P);
        if borrow == 0 {
            return None;
        }
        Some(Self::from_limbs(limbs))
    }

    /// The element congruent to the big-endian number `bytes`, which has at
    /// most `BYTES` bytes, or `None` if the number is not below `2 * p`. That
    /// is the case of a number whose bit length is the prime's: one conditional
    /// subtraction reduces it. How long the number is is public; its value is
    /// not revealed.
    pub(crate) fn from_be_bytes_below_double(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > Self::BYTES {
            return None;
        }
        let mut limbs = [0u64; N];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        let (reduced, borrow) = sub_limbs(&limbs, &M::P);
        let value = select_limbs(ct::mask(borrow ^ 1), &reduced, &limbs);
        // Still not below `p`: the number was at least `2 * p`.
        let (_, still_above) = sub_limbs(&value, &M::P);
        if still_above == 0 {
            return None;
        }
        Some(Self::from_limbs(value))
    }

    /// Writes the value as a big-endian number of exactly `BYTES` bytes.
    pub(crate) fn write_be_bytes(&self, out: &mut [u8]) {
        assert_eq!(out.len(), Self::BYTES);
        let mut one = [0; N];
        one[0] = 1;
        // Montgomery's product by 1 divides out the factor of `R`.
        let value = mont_mul(&self.limbs, &one, &M::P, Self::INV);
        for (i, byte) in out.iter_mut().rev().enumerate() {
            *byte = (value[i / 8] >> (8 * (i % 8))) as u8;
        }
    }

    /// 1 if the element is zero and 0 otherwise.
    #[inline(always)]
    pub(crate) fn is_zero(&self) -> u64 {
        let mut acc = 0;
        for limb in self.limbs {
            acc |= limb;
        }
        ct::is_zero(acc)
    }

    /// 1 if the elements are equal and 0 otherwise.
    #[inline(always)]
    pub(crate) fn eq(&self, other: &Self) -> u64 {
        let mut acc = 0;
        for (a, b) in self.limbs.iter().zip(&other.limbs) {
            acc |= a ^ b;
        }
        ct::is_zero(acc)
    }

    /// `a` where `mask` is all ones and `b` where it is all zeros.
    #[inline(always)]
    pub(crate) fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Self {
            limbs: select_limbs(mask, &a.limbs, &b.limbs),
            modulus: PhantomData,
        }
    }

    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        *self * *self
    }

    /// `-self`.
    #[cfg(test)]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO - *self
    }

    /// `self^(p - 2)`, which is the inverse of a non-zero element and zero for
    /// zero.
    ///
    /// The exponent is a constant, so this follows its bits with a four-bit
    /// window: neither the loop nor the table index depends on `self`.
    pub(crate) fn invert(&self) -> Self {
        let mut table = [Self::ONE; 16];
        for i in 1..16 {
            table[i] = table[i - 1] * *self;
        }

        let mut acc = Self::ONE;
        let mut started = false;
        for limb in Self::P_MINUS_2.iter().rev() {
            for shift in (0..16).rev() {
                let nibble = ((limb >> (4 * shift)) & 0xf) as usize;
                if started {
                    for _ in 0..4 {
                        acc = acc.square();
                    }
                }
                if nibble != 0 {
                    acc = if started {
                        acc * table[nibble]
                    } else {
                        table[nibble]
                    };
                    started = true;
                }
            }
        }
        acc
    }
}

impl<M: Modulus<N>, const N: usize> Add for Fe<M, N> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            limbs: add_mod(&self.limbs, &rhs.limbs, &M::P),
            modulus: PhantomData,
        }
    }
}

impl<M: Modulus<N>, const N: usize> Sub for Fe<M, N> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self {
            limbs: sub_mod(&self.limbs, &rhs.limbs, &M::P),
            modulus: PhantomData,
        }
    }
}

impl<M: Modulus<N>, const N: usize> Mul for Fe<M, N> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Self {
            limbs: mont_mul(&self.limbs, &rhs.limbs, &M::P, Self::INV),
            modulus: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2^64 - 59, the largest prime below 2^64: one limb, so every result can
    /// be checked against `u128` arithmetic.
    struct Small;
    impl Modulus<1> for Small {
        const P: [u64; 1] = [0xffff_ffff_ffff_ffc5];
    }

    /// NIST P-256: 4 limbs, with the top bit set.
    struct P256;
    impl Modulus<4> for P256 {
        const P: [u64; 4] = [
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_ffff_0000_0001,
        ];
    }

    /// 2^255 - 19: 4 limbs, with the top bit clear.
    struct P25519;
    impl Modulus<4> for P25519 {
        const P: [u64; 4] = [
            0xffff_ffff_ffff_ffed,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ];
    }

    /// NIST P-521, 2^521 - 1: 9 limbs, the top one of 9 bits.
    struct P521;
    impl Modulus<9> for P521 {
        const P: [u64; 9] = [
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_0000_01ff,
        ];
    }

    fn hex(s: &str, len: usize) -> Vec<u8> {
        let s = format!("{s:0>width$}", width = 2 * len);
        (0..len)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn fe<M: Modulus<N>, const N: usize>(s: &str) -> Fe<M, N> {
        Fe::from_be_bytes(&hex(s, Fe::<M, N>::BYTES)).expect("in range")
    }

    fn to_hex<M: Modulus<N>, const N: usize>(x: Fe<M, N>) -> String {
        let mut out = vec![0; Fe::<M, N>::BYTES];
        x.write_be_bytes(&mut out);
        out.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The constants are derived from the prime, so check them against their
    /// definitions.
    #[test]
    fn montgomery_constants() {
        // -p^-1 * p = -1 mod 2^64.
        assert_eq!(
            Fe::<P256, 4>::INV.wrapping_mul(P256::P[0]),
            u64::MAX,
            "INV is not -p^-1"
        );
        assert_eq!(Fe::<Small, 1>::INV.wrapping_mul(Small::P[0]), u64::MAX);

        // With one limb, R = 2^64 and R^2 can be had from u128 arithmetic.
        let p = u128::from(Small::P[0]);
        let r = (1u128 << 64) % p;
        assert_eq!(u128::from(Fe::<Small, 1>::R[0]), r);
        assert_eq!(u128::from(Fe::<Small, 1>::R2[0]), r * r % p);

        assert_eq!(Fe::<P256, 4>::BYTES, 32);
        assert_eq!(Fe::<P25519, 4>::BYTES, 32);
        assert_eq!(Fe::<P521, 9>::BYTES, 66);
        assert_eq!(Fe::<Small, 1>::BYTES, 8);
    }

    #[test]
    fn small_prime_matches_u128() {
        let p = u128::from(Small::P[0]);
        let values: [u64; 9] = [
            0,
            1,
            2,
            3,
            0x1234_5678_9abc_def0,
            Small::P[0] / 2,
            Small::P[0] / 2 + 1,
            Small::P[0] - 2,
            Small::P[0] - 1,
        ];
        for &a in &values {
            for &b in &values {
                let (x, y) = (Fe::<Small, 1>::from_limbs([a]), Fe::from_limbs([b]));
                let expect = |v: u128| format!("{:016x}", v as u64);
                assert_eq!(to_hex(x + y), expect((u128::from(a) + u128::from(b)) % p));
                assert_eq!(
                    to_hex(x - y),
                    expect((u128::from(a) + p - u128::from(b)) % p)
                );
                assert_eq!(to_hex(x * y), expect(u128::from(a) * u128::from(b) % p));
            }
            let x = Fe::<Small, 1>::from_limbs([a]);
            assert_eq!(
                to_hex(x.neg()),
                format!("{:016x}", ((p - u128::from(a)) % p) as u64)
            );
            if a != 0 {
                assert_eq!(to_hex(x * x.invert()), "0000000000000001", "{a:#x}");
            }
        }
        assert_eq!(Fe::<Small, 1>::ZERO.invert().is_zero(), 1);
    }

    /// P256_VECTORS: (a, b, a + b, a - b, a * b, 1 / a), from Python integers.
    const P256_VECTORS: [[&str; 6]; 6] = [
        [
            "9dddd895dad9719fe044d51eeca8d84ace2a3387345250f82bac8d5016a49962",
            "1675734fb47b4c019caa8ad2fd7b98c01649444aa0e28fc4e305990f847cca67",
            "b4534be58f54bda17cef5ff1ea24710ae47377d1d534e0bd0eb2265f9b2163c9",
            "87686546265e259e439a4a4bef2d3f8ab7e0ef3c936fc13348a6f4409227cefb",
            "53b780fbe856d955fbe19405d9683100066bee897301333a48db678cf610c63e",
            "917ec21d884df2c6a1ba43008c0c0b016c05b6440dda626aa0adac7aae0ee4b1",
        ],
        [
            "4e017f7284dfb0800f1360c6b6afe309dc0a3bdbd47b2230b0f6b37d5a8404aa",
            "9212ba8ca046eb9ab74f0e80fb68252739450cdbe42b7f67210f29de26291116",
            "e01439ff25269c1ac6626f47b2180831154f48b7b8a6a197d205dd5b80ad15c0",
            "bbeec4e4e498c4e657c45245bb47bde2a2c52f00f04fa2c98fe7899f345af393",
            "22ca7965f1fb4ba67ec17ee5bd248c922c271222da718b60e8e6812d756191a7",
            "afa55f32937392dcc9060aed4e013924256dc16abdce8b44b94127162e187a85",
        ],
        [
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ],
        [
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "105e79d89849136951c8e63a9c9f093e20cc7d0c283f0d924e60b3a9beb13e79",
            "105e79d89849136951c8e63a9c9f093e20cc7d0c283f0d924e60b3a9beb13e79",
            "efa1862667b6ec97ae3719c56360f6c1df3382f4d7c0f26db19f4c56414ec186",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ],
    ];

    /// P25519_VECTORS: (a, b, a + b, a - b, a * b, 1 / a), from Python integers.
    const P25519_VECTORS: [[&str; 6]; 6] = [
        [
            "10378ae9ca270473fc17a950508fb2c57bed71bde312df3dc9518b01cb1d8ecf",
            "618462405e6f2a88a1fa86429bf2c79104d9cc9da117eae39973e03e8de09a82",
            "71bbed2a28962efc9e122f92ec827a5680c73e5b842aca2162c56b4058fe2951",
            "2eb328a96bb7d9eb5a1d230db49ceb347713a52041faf45a2fddaac33d3cf43a",
            "31ebbb2c321ef0450903b23d495376250951821ac5fdd85a69605c293ee3a9e5",
            "04d15362a1a480f6f8570d5ec2fe6fc137cf0db8552b507d5e53a6c38a13dc6f",
        ],
        [
            "60981bb556845ab7fccc5597b520a7eca3bb53f3c2a3829909f591fe09212e03",
            "64745c80ab9bd59cb07d43fc4689a98c5356764493fdde1c94e30508ed28fae1",
            "450c783602203054ad499993fbaa5178f711ca3856a160b59ed89706f64a28f7",
            "7c23bf34aae8851b4c4f119b6e96fe605064ddaf2ea5a47c75128cf51bf8330f",
            "5da3afba7704ac0a701511b46c2b86ab5f44a4a7257fb2c70ffa2153f5936b77",
            "4f579fb336639637101a7bbc8214dbb3ce1f02e71b9ca449b424c6e0c95e9974",
        ],
        [
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
        ],
        [
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffea",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "15c2e1744ff4739ed34072ed14528459dcffaee224de2738bd11379696d9ad27",
            "15c2e1744ff4739ed34072ed14528459dcffaee224de2738bd11379696d9ad27",
            "6a3d1e8bb00b8c612cbf8d12ebad7ba62300511ddb21d8c742eec869692652c6",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ],
    ];

    /// P521_VECTORS: (a, b, a + b, a - b, a * b, 1 / a), from Python integers.
    const P521_VECTORS: [[&str; 6]; 6] = [
        [
            "009e01b0bb307d121618c7f0b07fdb17653666aa43e95eb7ccbda2f4977f49bb599a29d080fb31bd74a3819d44c01fac6f2b983b504c71536724f0be2ae6b1a26342",
            "00fc91b547bbcbf38e912692c03c71f4161c806fd9ac53784bcc4d915aaf85271105a77284b6801a5ef63e149a8a293b0c38bff9ba9bbf59d1e211624a1eea7a2403",
            "019a936602ec4905a4a9ee8370bc4d0b7b52e71a1d95b2301889f085f22ecee26a9fd14305b1b1d7d399bfb1df4a48e77b6458350ae830ad3907022075059c1c8745",
            "01a16ffb7374b11e8787a15df04369234f19e63a6a3d0b3f80f155633ccfc4944894825dfc44b1a315ad4388aa35f67162f2d84195b0b1f99542df5be0c7c7283f3e",
            "00fd022f73d732feeab2e20d83bca0cccd7f2acf2fd00f2797e00b67b180b9b82b0a69bf81edae66023f95669c79c87a920eecaf873bd40c7eac72f71345fb1bb342",
            "012efc79229e804b342949f815dfd656134de1b24c1c33d597a3e4aaae7f7f6aaa9b21b7f32d378401fd8fbdda6198037df6d01bb2366ac97b4c59a5f13a2f74c77f",
        ],
        [
            "00c6e8d859ae04efb6f0cc801872bf4eb96ebbecb49f4f14463d6c5e39bf8da459a0d5a261863b0d839aa76b8673c2b65a0b6de8a3a7da0f7ec8633923005c11b0f6",
            "0195268a8112529ef14dc04545f2d0f93372e6402e70682ec4c1527707cc683c4d2ca4e101fbc3da48b7234af7840f892af9ecde3fae5f61f8b35f80b4fab21f87b8",
            "005c0f62dac0578ea83e8cc55e659047ece1a22ce30fb7430afebed5418bf5e0a6cd7a836381fee7cc51cab67df7d23f85055ac6e3563971777bc2b9d7fb0e3138af",
            "0131c24dd89bb250c5a30c3ad27fee5585fbd5ac862ee6e5817c19e731f325680c7430c15f8a77333ae384208eefb32d2f11810a63f97aad861503b86e05a9f2293d",
            "00f0fb473a15598461bc59da01fe69b8c137754277c48fc387a3940ff0f38886fd627e6946741a1816c670e5a62691cbf62f8920ae55cc2a866bde6fade26a6e6a87",
            "01bf7e94cc0163c59673584ded323c42dfef52ccb622504b11c9beed5ded4544bdd4e44d1ddc5c2cdf334a361c9b3b9d06f1d61503bf55e1aadaf1d0c309c96b712f",
        ],
        [
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
        ],
        [
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
        ],
        [
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "010fd24a03dcb5529e9ca806ffdec0518b20941f21548194a5f6efc3dd508be1418867495beaa0489be671784f5afed6dbdaacafbc9bf5640945c2d8611c57300143",
            "010fd24a03dcb5529e9ca806ffdec0518b20941f21548194a5f6efc3dd508be1418867495beaa0489be671784f5afed6dbdaacafbc9bf5640945c2d8611c57300143",
            "00f02db5fc234aad616357f900213fae74df6be0deab7e6b5a09103c22af741ebe7798b6a4155fb764198e87b0a501292425535043640a9bf6ba3d279ee3a8cffebc",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ],
        [
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        ],
    ];

    /// Checks sums, differences, products and inverses against the table, for
    /// a field whose elements have `N` limbs.
    fn check_vectors<M: Modulus<N>, const N: usize>(rows: &[[&str; 6]]) {
        for [a, b, sum, diff, product, inverse] in rows {
            let (x, y) = (fe::<M, N>(a), fe::<M, N>(b));
            assert_eq!(to_hex(x + y), *sum, "{a} + {b}");
            assert_eq!(to_hex(x - y), *diff, "{a} - {b}");
            assert_eq!(to_hex(x * y), *product, "{a} * {b}");
            assert_eq!(to_hex(x.square()), to_hex(x * x), "{a}^2");
            assert_eq!(to_hex(x.invert()), *inverse, "1 / {a}");
        }
    }

    /// `from_be_bytes_below_double` reduces what is below `2 * p` with one
    /// subtraction, and refuses the rest: a number of more bytes than the prime has,
    /// and one of the same length that is at least `2 * p`. 2^255 - 19 has room for
    /// both kinds in 32 bytes: 2p = 2^256 - 38.
    #[test]
    fn below_double_takes_what_one_subtraction_reduces() {
        type F = Fe<P25519, 4>;
        let bytes = |value: &str| hex(value, 32);

        // Below p, as it is; p itself, which is zero; and up to 2p - 1.
        assert_eq!(
            to_hex(F::from_be_bytes_below_double(&bytes("05")).unwrap()),
            hex_of("05")
        );
        let p = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
        assert!(F::from_be_bytes_below_double(&bytes(p)).unwrap().is_zero() == 1);
        let p_plus_5 = "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2";
        assert_eq!(
            to_hex(F::from_be_bytes_below_double(&bytes(p_plus_5)).unwrap()),
            hex_of("05")
        );
        let two_p_minus_1 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd9";
        assert_eq!(
            to_hex(F::from_be_bytes_below_double(&bytes(two_p_minus_1)).unwrap()),
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"
        );

        // 2p and everything above it, up to the largest 32-byte number.
        let two_p = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda";
        assert!(F::from_be_bytes_below_double(&bytes(two_p)).is_none());
        assert!(F::from_be_bytes_below_double(&[0xff; 32]).is_none());

        // A shorter number is padded on the left; a longer one is refused.
        assert_eq!(
            to_hex(F::from_be_bytes_below_double(&[5]).unwrap()),
            hex_of("05")
        );
        assert!(F::from_be_bytes_below_double(&[]).unwrap().is_zero() == 1);
        assert!(F::from_be_bytes_below_double(&[0; 33]).is_none());
        assert!(Fe::<Small, 1>::from_be_bytes_below_double(&[0; 9]).is_none());
    }

    /// The 32-byte hex of `value`, for comparing with `to_hex`.
    fn hex_of(value: &str) -> String {
        format!("{value:0>64}")
    }

    #[test]
    fn known_answers() {
        check_vectors::<P256, 4>(&P256_VECTORS);
        check_vectors::<P25519, 4>(&P25519_VECTORS);
        check_vectors::<P521, 9>(&P521_VECTORS);
    }
}
