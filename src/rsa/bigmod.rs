//! Integers of any size, and arithmetic modulo an odd number of any size.
//!
//! RSA works with numbers of 1,024 to 16,384 bits whose size is only known
//! when a key is read, so unlike the fields of [`ec`](crate::ec) these do not
//! have a number of limbs in their type. A number is a `Vec` of little-endian
//! 64-bit limbs, [`Limbs`], and a [`Modulus`] holds what Montgomery's
//! multiplication needs to work modulo one odd number: `R = 2^(64 * n)` for the
//! `n` limbs of the modulus, `R^2 mod m` to convert into Montgomery form, and
//! `-m^-1 mod 2^64`. A number `x` below `m` is kept as `x * R mod m`; a product
//! divides one factor of `R` out again, so a chain of products stays in the same
//! form and never needs a division.
//!
//! Everything that is applied to a secret (the multiplication, the powers, the
//! sums, the reduction of a number that is longer than the modulus) takes a time
//! and touches the memory that depend on the lengths of its operands and not on
//! their values. The exceptions are named: [`Modulus::pow_u32`] has a public
//! exponent, [`bit_len`] and [`Limbs::trimmed`] reveal how many limbs a number
//! has, and the key generation, which has its own file, is variable-time
//! throughout. The lengths of the primes and of the modulus are public.

use crate::ec::ct;
use crate::ec::field::{adc, mac, neg_inv, sbb};
use crate::wipe::wipe;
use core::ops::{Deref, DerefMut};

/// A natural number as little-endian 64-bit limbs, which are overwritten with
/// zeros when it is dropped: numbers of this type are private keys, the
/// factors of one, and the values computed from them.
///
/// The number of limbs is part of the value as far as this module is
/// concerned: functions that take two numbers say whether they must have the
/// same length. It is public information.
#[derive(Clone)]
pub(super) struct Limbs(Vec<u64>);

impl Drop for Limbs {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Deref for Limbs {
    type Target = [u64];

    fn deref(&self) -> &[u64] {
        &self.0
    }
}

impl DerefMut for Limbs {
    fn deref_mut(&mut self) -> &mut [u64] {
        &mut self.0
    }
}

impl From<&[u64]> for Limbs {
    fn from(limbs: &[u64]) -> Self {
        Limbs(limbs.to_vec())
    }
}

impl Limbs {
    /// Zero, in `len` limbs.
    pub(super) fn zero(len: usize) -> Self {
        Limbs(vec![0; len])
    }

    /// `value`, in `len` limbs, which must be at least one.
    pub(super) fn from_u64(value: u64, len: usize) -> Self {
        let mut limbs = Self::zero(len);
        limbs[0] = value;
        limbs
    }

    /// The number with the big-endian encoding `bytes`, in as many limbs as the
    /// bytes fill: a leading zero byte counts, so the length is that of the
    /// encoding and reveals nothing about the value.
    pub(super) fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Self::zero(bytes.len().div_ceil(8));
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        limbs
    }

    /// The same number without its zero limbs at the top. The result has as many
    /// limbs as the number needs, which is what makes this reveal its size; it
    /// is used on moduli and primes, whose sizes are public.
    pub(super) fn trimmed(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    /// The number as exactly `len` big-endian bytes, with zeros in front if it
    /// is shorter. The number must fit.
    pub(super) fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        for (i, byte) in bytes.iter_mut().rev().enumerate() {
            if let Some(limb) = self.0.get(i / 8) {
                *byte = (limb >> (8 * (i % 8))) as u8;
            }
        }
        debug_assert!(
            self.0
                .iter()
                .enumerate()
                .all(|(i, &limb)| (0..8).all(|b| 8 * i + b < len || (limb >> (8 * b)) as u8 == 0)),
            "the number does not fit"
        );
        bytes
    }
}

#[cfg(test)]
thread_local! {
    /// The number of Montgomery products this thread has made, for the tests that
    /// check the work does not depend on a secret.
    pub(super) static PRODUCTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The number of bits of `x`, which is 0 for zero. It branches on the limbs, so
/// it reveals the size of the number; call it on moduli, primes and public
/// values.
pub(super) fn bit_len(x: &[u64]) -> usize {
    for (i, &limb) in x.iter().enumerate().rev() {
        if limb != 0 {
            return 64 * i + (64 - limb.leading_zeros() as usize);
        }
    }
    0
}

/// 1 if `x` is zero and 0 otherwise.
pub(super) fn is_zero(x: &[u64]) -> u64 {
    ct::is_zero(x.iter().fold(0, |acc, &limb| acc | limb))
}

/// 1 if `x` is one and 0 otherwise.
pub(super) fn is_one(x: &[u64]) -> u64 {
    let high = x.iter().skip(1).fold(0, |acc, &limb| acc | limb);
    ct::eq(x.first().copied().unwrap_or(0), 1) & ct::is_zero(high)
}

/// 1 if `a == b` and 0 otherwise. The numbers may have different lengths: the
/// limbs that one has beyond the other must be zero.
pub(super) fn eq(a: &[u64], b: &[u64]) -> u64 {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut diff = 0;
    for (i, &limb) in long.iter().enumerate() {
        diff |= limb ^ short.get(i).copied().unwrap_or(0);
    }
    ct::is_zero(diff)
}

/// `a - b` as limbs of the length of `a`, and the borrow out of the top limb,
/// which is 1 exactly when `a < b`. `b` must not be longer than `a`.
pub(super) fn sub(a: &[u64], b: &[u64]) -> (Limbs, u64) {
    assert!(b.len() <= a.len());
    let mut diff = Limbs::zero(a.len());
    let mut borrow = 0;
    for (i, (d, &x)) in diff.iter_mut().zip(a).enumerate() {
        (*d, borrow) = sbb(x, b.get(i).copied().unwrap_or(0), borrow);
    }
    (diff, borrow)
}

/// 1 if `a < b` and 0 otherwise, for numbers of any lengths.
pub(super) fn lt(a: &[u64], b: &[u64]) -> u64 {
    let mut borrow = 0;
    for i in 0..a.len().max(b.len()) {
        let (_, next) = sbb(
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
            borrow,
        );
        borrow = next;
    }
    borrow
}

/// `a + b` as limbs of the length of the longer, and the carry out of the top
/// limb.
pub(super) fn add(a: &[u64], b: &[u64]) -> (Limbs, u64) {
    let len = a.len().max(b.len());
    let mut sum = Limbs::zero(len);
    let mut carry = 0;
    for (i, s) in sum.iter_mut().enumerate() {
        (*s, carry) = adc(
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
            carry,
        );
    }
    (sum, carry)
}

/// The product of `a` and `b`, in `a.len() + b.len()` limbs.
pub(super) fn mul(a: &[u64], b: &[u64]) -> Limbs {
    let mut product = Limbs::zero(a.len() + b.len());
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0;
        for (out, &y) in product[i..].iter_mut().zip(b) {
            (*out, carry) = mac(*out, x, y, carry);
        }
        product[i + b.len()] = carry;
    }
    product
}

/// `x mod m` for any nonzero `m`, even or odd, in `m.len()` limbs, one bit of
/// `x` at a time: the remainder so far is doubled, the next bit is added, and
/// `m` is subtracted if the result is not below it. That takes a time
/// proportional to the length of `x` times the length of `m` whatever their
/// values, which is slow (a multiplication by `m` costs as much as a few
/// hundred products) and the point: it is for checking the components of a key,
/// where the modulus can be even (`p - 1`), and not for the private operation.
pub(super) fn rem(x: &[u64], m: &[u64]) -> Limbs {
    let mut r = Limbs::zero(m.len());
    for &limb in x.iter().rev() {
        for bit in (0..64).rev() {
            let mut carry = (limb >> bit) & 1;
            for r_j in r.iter_mut() {
                let next = *r_j >> 63;
                *r_j = (*r_j << 1) | carry;
                carry = next;
            }
            // `carry:r` is below `2m`; one subtraction brings it below `m`.
            let (reduced, borrow) = sub(&r, m);
            let take = ct::mask(carry | (borrow ^ 1));
            for (r_j, &s) in r.iter_mut().zip(reduced.iter()) {
                *r_j = ct::select(take, s, *r_j);
            }
        }
    }
    r
}

/// An odd modulus and the constants of Montgomery's multiplication for it.
///
/// Its limbs are secret when it is a prime factor of a key, and are
/// overwritten with zeros when it is dropped, like everything derived from them.
pub(super) struct Modulus {
    /// The modulus, `n` limbs with the top one not zero.
    m: Limbs,
    /// `-m^-1 mod 2^64`.
    inv: u64,
    /// `R mod m`: the number 1 in Montgomery form.
    one: Limbs,
    /// `R^2 mod m`: multiplying by it converts to Montgomery form.
    rr: Limbs,
}

impl Clone for Modulus {
    fn clone(&self) -> Self {
        Modulus {
            m: self.m.clone(),
            inv: self.inv,
            one: self.one.clone(),
            rr: self.rr.clone(),
        }
    }
}

impl Modulus {
    /// The modulus `m`, which must be odd, above 1, and have no zero limb at the
    /// top (see [`Limbs::trimmed`]); `None` if it is not. The constants take a
    /// time that depends on the length of `m` and not on its value.
    pub(super) fn new(m: Limbs) -> Option<Self> {
        if m.last().is_none_or(|&top| top == 0) || m[0] & 1 == 0 || is_one(&m) == 1 {
            return None;
        }
        let n = m.len();
        let bits = bit_len(&m);

        // `R mod m`. `2^(bits - 1)` is below `m`, and doubling it modulo `m` up
        // to `2^(64 * n)` takes at most 64 steps.
        let mut one = Limbs::zero(n);
        one[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        for _ in bits - 1..64 * n {
            one = add_mod(&one, &one, &m);
        }

        let mut modulus = Modulus {
            inv: neg_inv(m[0]),
            rr: Limbs::zero(n),
            one,
            m,
        };

        // `R^2 mod m` is the number `R` in Montgomery form, that is `R * R`.
        // Starting from 1 in Montgomery form, doubling `c` times gives the form
        // of `2^c`; squaring gives the form of the square, so the form of
        // `2^(64 * n)` is reached by following the bits of the exponent
        // `64 * n` from the top: square, and double if the bit is set. The
        // first few bits are cheaper as plain doublings than as a product,
        // until the count is about a quarter of the number of limbs.
        let log_r = 64 * n;
        let mut shift = usize::BITS as usize - 1;
        while log_r >> shift <= n / 4 {
            shift -= 1;
        }
        let mut rr = modulus.one.clone();
        for _ in 0..log_r >> shift {
            rr = add_mod(&rr, &rr, &modulus.m);
        }
        let mut product = Limbs::zero(n);
        let mut scratch = Limbs::zero(n + 1);
        for bit in (0..shift).rev() {
            modulus.mont_mul(&mut product, &rr, &rr, &mut scratch);
            core::mem::swap(&mut rr, &mut product);
            if (log_r >> bit) & 1 == 1 {
                rr = add_mod(&rr, &rr, &modulus.m);
            }
        }
        modulus.rr = rr;
        Some(modulus)
    }

    /// The number of limbs of the modulus, and of every number modulo it.
    pub(super) fn len(&self) -> usize {
        self.m.len()
    }

    /// The number of bits of the modulus.
    pub(super) fn bit_len(&self) -> usize {
        bit_len(&self.m)
    }

    /// The modulus.
    pub(super) fn limbs(&self) -> &[u64] {
        &self.m
    }

    /// The number 1 in Montgomery form.
    pub(super) fn one(&self) -> &[u64] {
        &self.one
    }

    /// Montgomery's product (the CIOS method): `out = a * b / R mod m`, for
    /// `a * b < R * m`, which holds when both are below `m` and when one is
    /// below `R` and the other below `m`. `out`, `a` and `b` have `n` limbs and
    /// `scratch` has `n + 1`.
    ///
    /// Each of the `n` rounds adds `a * b[i]` to the accumulator, then the
    /// multiple of `m` that makes its lowest limb zero, and drops that limb.
    /// After the last round the accumulator is `(a * b + k * m) / R` for some
    /// `k` below `R`, which is below `2m`, and a final conditional subtraction
    /// brings it into range. The two additions of a round are made in one pass
    /// over the limbs, with a carry for each: two chains of additions that do not
    /// wait for each other.
    pub(super) fn mont_mul(&self, out: &mut [u64], a: &[u64], b: &[u64], scratch: &mut [u64]) {
        #[cfg(test)]
        PRODUCTS.with(|count| count.set(count.get() + 1));
        let n = self.m.len();
        assert!(out.len() == n && a.len() == n && b.len() == n && scratch.len() == n + 1);
        let m = &self.m[..];
        let t = scratch;
        t.fill(0);

        let mut hi = 0u64;
        for &b_i in b {
            // One pass over the limbs does both halves of the round: t += a * b[i],
            // then t += k * m, with k chosen so that the low limb vanishes, and the
            // sum is shifted down by a limb as it is written.
            let (low, mut carry_a) = mac(t[0], a[0], b_i, 0);
            let k = low.wrapping_mul(self.inv);
            let (_, mut carry_m) = mac(low, k, m[0], 0);
            for j in 1..n {
                let (sum, c) = mac(t[j], a[j], b_i, carry_a);
                carry_a = c;
                let (limb, c) = mac(sum, k, m[j], carry_m);
                carry_m = c;
                t[j - 1] = limb;
            }
            let (top, over) = adc(hi, carry_a, 0);
            let (limb, c) = adc(top, carry_m, 0);
            t[n - 1] = limb;
            hi = over + c;
        }
        t[n] = hi;

        // The accumulator is `t[n] * 2^(64 * n) + t[..n]`, below `2m`. Subtract
        // `m` if it is at least `m`: always when `t[n]` is set, otherwise when
        // `t[..n] >= m`.
        let mut borrow = 0;
        for ((o, &t_j), &m_j) in out.iter_mut().zip(&t[..n]).zip(m) {
            (*o, borrow) = sbb(t_j, m_j, borrow);
        }
        let reduced = ct::mask(t[n] | (borrow ^ 1));
        for (o, &t_j) in out.iter_mut().zip(&t[..n]) {
            *o = ct::select(reduced, *o, t_j);
        }
    }

    /// The Montgomery form of `x mod m`, for a number `x` of any length: the
    /// number is cut into pieces of `n` limbs, each piece is converted, and they
    /// are combined from the top with Horner's rule, a step being a product by
    /// `R^2` (which is the form of a multiplication by `R`) and a sum.
    pub(super) fn to_mont(&self, x: &[u64]) -> Limbs {
        let n = self.len();
        let mut scratch = Limbs::zero(n + 1);
        let mut acc = Limbs::zero(n);
        let mut shifted = Limbs::zero(n);
        let mut piece = Limbs::zero(n);
        let mut converted = Limbs::zero(n);
        for chunk in x.chunks(n).rev() {
            piece.fill(0);
            piece[..chunk.len()].copy_from_slice(chunk);
            self.mont_mul(&mut shifted, &acc, &self.rr, &mut scratch);
            self.mont_mul(&mut converted, &piece, &self.rr, &mut scratch);
            acc = add_mod(&shifted, &converted, &self.m);
        }
        acc
    }

    /// The number that has the Montgomery form `x`, below `m`.
    pub(super) fn to_plain(&self, x: &[u64]) -> Limbs {
        let n = self.len();
        let mut out = Limbs::zero(n);
        let mut scratch = Limbs::zero(n + 1);
        self.mont_mul(&mut out, x, &Limbs::from_u64(1, n), &mut scratch);
        out
    }

    /// The Montgomery form of the product of the numbers that have the forms
    /// `a` and `b`.
    pub(super) fn mul(&self, a: &[u64], b: &[u64]) -> Limbs {
        let n = self.len();
        let mut out = Limbs::zero(n);
        self.mont_mul(&mut out, a, b, &mut Limbs::zero(n + 1));
        out
    }

    /// The Montgomery form of the difference of the numbers that have the forms
    /// `a` and `b`.
    pub(super) fn sub(&self, a: &[u64], b: &[u64]) -> Limbs {
        let (mut diff, borrow) = sub(a, b);
        // If `a < b` the difference wrapped around `2^(64 * n)`; adding `m`
        // brings it back to the right residue.
        let mask = ct::mask(borrow);
        let mut carry = 0;
        for (d, &m_j) in diff.iter_mut().zip(self.m.iter()) {
            (*d, carry) = adc(*d, m_j & mask, carry);
        }
        diff
    }

    /// `base ^ exp` for a `base` in Montgomery form and the exponent `exp`, which
    /// may be a secret: the result is in Montgomery form. The exponent is
    /// processed four bits at a time, always the same four squarings and one
    /// product by an entry of the table of the sixteen powers of `base`, which is
    /// read in full to find it, so that neither the time nor the addresses that
    /// are read depend on the bits. The exponent has the same number of limbs
    /// whatever its value, and a zero exponent gives 1.
    pub(super) fn pow(&self, base: &[u64], exp: &[u64]) -> Limbs {
        let n = self.len();
        let mut scratch = Limbs::zero(n + 1);

        // table[i] = base^i
        let mut table = Limbs::zero(16 * n);
        table[..n].copy_from_slice(&self.one);
        table[n..2 * n].copy_from_slice(base);
        for i in 2..16 {
            let (done, rest) = table.split_at_mut(i * n);
            self.mont_mul(&mut rest[..n], &done[(i - 1) * n..], base, &mut scratch);
        }

        let mut acc = self.one.clone();
        let mut next = Limbs::zero(n);
        let mut entry = Limbs::zero(n);
        for &limb in exp.iter().rev() {
            for shift in (0..16).rev() {
                for _ in 0..4 {
                    self.mont_mul(&mut next, &acc, &acc, &mut scratch);
                    core::mem::swap(&mut acc, &mut next);
                }
                let window = (limb >> (4 * shift)) & 0xf;
                entry.fill(0);
                for (i, candidate) in table.chunks(n).enumerate() {
                    let hit = ct::mask(ct::eq(i as u64, window));
                    for (e, &c) in entry.iter_mut().zip(candidate) {
                        *e |= c & hit;
                    }
                }
                self.mont_mul(&mut next, &acc, &entry, &mut scratch);
                core::mem::swap(&mut acc, &mut next);
            }
        }
        acc
    }

    /// `base ^ exp` for a `base` in Montgomery form and a public exponent of at
    /// least 1, by squaring and multiplying from the top bit: the time depends on
    /// the exponent, which is the public exponent of a key.
    pub(super) fn pow_u32(&self, base: &[u64], exp: u32) -> Limbs {
        assert!(exp >= 1);
        let n = self.len();
        let mut scratch = Limbs::zero(n + 1);
        let mut acc = Limbs::from(base);
        let mut next = Limbs::zero(n);
        for bit in (0..31 - exp.leading_zeros()).rev() {
            self.mont_mul(&mut next, &acc, &acc, &mut scratch);
            core::mem::swap(&mut acc, &mut next);
            if (exp >> bit) & 1 == 1 {
                self.mont_mul(&mut next, &acc, base, &mut scratch);
                core::mem::swap(&mut acc, &mut next);
            }
        }
        acc
    }
}

/// `(a + b) mod m` for `a` and `b` below `m`, which all have the same length.
fn add_mod(a: &[u64], b: &[u64], m: &[u64]) -> Limbs {
    let (sum, carry) = add(a, b);
    let (reduced, borrow) = sub(&sum, m);
    // `sum - m` is the answer when the sum did not fit in the limbs (it is then
    // at least `m`) or when it did and is at least `m`.
    let take = ct::mask(carry | (borrow ^ 1));
    let mut out = sum;
    for (o, &r) in out.iter_mut().zip(reduced.iter()) {
        *o = ct::select(take, r, *o);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::testutil::{Record, records, unhex};

    const VECTORS: &str = include_str!("testdata/bigmod.txt");

    fn limbs(hex: &str) -> Limbs {
        Limbs::from_be_bytes(&unhex(hex)).trimmed()
    }

    /// `x` in as many limbs as `len`, which must hold it.
    fn padded(x: &Limbs, len: usize) -> Limbs {
        let mut out = Limbs::zero(len);
        out[..x.len()].copy_from_slice(x);
        out
    }

    fn field(r: &Record<'_>, key: &str, len: usize) -> Limbs {
        padded(&limbs(r.text(key)), len)
    }

    /// Products, powers and reductions against Python's integers, for moduli of 1
    /// to 32 limbs and of the shapes that stress carries: all ones, a power of two
    /// plus one, a top limb of 1 or with its top bits clear.
    #[test]
    fn modular_arithmetic_matches_python() {
        let mut count = 0;
        for r in records(VECTORS).iter().filter(|r| r.kind == "modular") {
            let m = limbs(r.text("m"));
            let n = m.len();
            let modulus = Modulus::new(m.clone()).unwrap();
            let what = r.text("m");
            let (a, b) = (field(r, "a", n), field(r, "b", n));
            let (a_m, b_m) = (modulus.to_mont(&a), modulus.to_mont(&b));

            // To Montgomery form and back is the identity, and the product is Python's.
            assert_eq!(*modulus.to_plain(&a_m), *a, "{what}");
            let product = modulus.to_plain(&modulus.mul(&a_m, &b_m));
            assert_eq!(*product, *field(r, "ab", n), "{what}");

            // A number of any length reduces to its remainder.
            let x = limbs(r.text("x"));
            assert_eq!(
                *modulus.to_plain(&modulus.to_mont(&x)),
                *field(r, "x_mod", n),
                "{what}"
            );

            // The powers, with a secret exponent and with a public one.
            let e = limbs(r.text("e"));
            let power = modulus.to_plain(&modulus.pow(&a_m, &e));
            assert_eq!(*power, *field(r, "a_pow_e", n), "{what}");
            let small = r.int("small") as u32;
            let power = modulus.to_plain(&modulus.pow_u32(&a_m, small));
            assert_eq!(*power, *field(r, "a_pow_s", n), "{what}");
            count += 1;
        }
        assert_eq!(count, 62);
    }

    #[test]
    fn remainder_matches_python() {
        let mut count = 0;
        for r in records(VECTORS).iter().filter(|r| r.kind == "remainder") {
            let m = limbs(r.text("m"));
            let remainder = rem(&limbs(r.text("x")), &m);
            assert_eq!(
                *remainder,
                *field(r, "x_mod", m.len()),
                "{} {}",
                r.text("m"),
                r.text("x")
            );
            count += 1;
        }
        assert_eq!(count, 90);
    }

    #[test]
    fn products_and_differences() {
        // 2^64 - 1 squared is 2^128 - 2^65 + 1.
        let product = mul(&[u64::MAX], &[u64::MAX]);
        assert_eq!(*product, [1, u64::MAX - 1]);
        // The lengths add up even when the top is zero.
        let product = mul(&[3, 0], &[5]);
        assert_eq!(*product, [15, 0, 0]);

        let (diff, borrow) = sub(&[0, 1], &[1]);
        assert_eq!((&*diff, borrow), (&[u64::MAX, 0][..], 0));
        let (diff, borrow) = sub(&[0, 0], &[1]);
        assert_eq!((&*diff, borrow), (&[u64::MAX, u64::MAX][..], 1));
        let (sum, carry) = add(&[u64::MAX, u64::MAX], &[1]);
        assert_eq!((&*sum, carry), (&[0, 0][..], 1));

        // Comparisons of numbers of different lengths.
        assert_eq!(lt(&[5], &[5, 1]), 1);
        assert_eq!(lt(&[5, 1], &[5]), 0);
        assert_eq!(lt(&[5, 0], &[5]), 0);
        assert_eq!(lt(&[5], &[6, 0, 0]), 1);
        assert_eq!(eq(&[5, 0, 0], &[5]), 1);
        assert_eq!(eq(&[5], &[5, 0, 1]), 0);
        assert_eq!(is_zero(&[0, 0]), 1);
        assert_eq!(is_zero(&[0, 1]), 0);
        assert_eq!(is_one(&[1, 0]), 1);
        assert_eq!(is_one(&[1, 1]), 0);
        assert_eq!(is_one(&[0]), 0);
        assert_eq!(bit_len(&[0, 0]), 0);
        assert_eq!(bit_len(&[1, 0]), 1);
        assert_eq!(bit_len(&[0, 1 << 63]), 128);
    }

    #[test]
    fn modular_sum_and_difference() {
        let modulus = Modulus::new(limbs("ffffffffffffffff").clone()).unwrap();
        let three = modulus.to_mont(&[3]);
        let big = modulus.to_mont(&[u64::MAX - 1]);
        // (m - 1) + 3 = 2 and 3 - (m - 1) = 4 modulo m = 2^64 - 1.
        let sum = add_mod(&big, &three, modulus.limbs());
        assert_eq!(*modulus.to_plain(&sum), [2]);
        let diff = modulus.sub(&three, &big);
        assert_eq!(*modulus.to_plain(&diff), [4]);
        let diff = modulus.sub(&big, &three);
        assert_eq!(*modulus.to_plain(&diff), [u64::MAX - 4]);
        assert_eq!(*modulus.to_plain(&modulus.sub(&three, &three)), [0]);
    }

    #[test]
    fn a_modulus_must_be_odd_and_above_one() {
        assert!(Modulus::new(Limbs::from(&[1u64][..])).is_none());
        assert!(Modulus::new(Limbs::from(&[0u64][..])).is_none());
        assert!(Modulus::new(Limbs::from(&[4u64][..])).is_none());
        assert!(
            Modulus::new(Limbs::from(&[3u64, 0][..])).is_none(),
            "a zero limb on top"
        );
        assert!(Modulus::new(Limbs::zero(0)).is_none());
        assert!(Modulus::new(Limbs::from(&[3u64][..])).is_some());
        assert!(Modulus::new(Limbs::from(&[1u64, 1][..])).is_some());
    }

    #[test]
    fn exponents_of_zero_and_one() {
        let modulus = Modulus::new(limbs("b7e151628aed2a6abf7158809cf4f3c7")).unwrap();
        let base = modulus.to_mont(&[0x1234_5678_9abc_def0, 7]);
        assert_eq!(*modulus.pow(&base, &[0, 0]), *modulus.one());
        assert_eq!(*modulus.pow(&base, &[1, 0]), *base);
        assert_eq!(*modulus.pow_u32(&base, 1), *base);
        // The one of the modulus converts back to 1.
        assert_eq!(*modulus.to_plain(modulus.one()), [1, 0]);
    }

    #[test]
    fn bytes_and_limbs() {
        let bytes = unhex("0102030405060708090a");
        let n = Limbs::from_be_bytes(&bytes);
        assert_eq!(*n, [0x0304_0506_0708_090a, 0x0102]);
        assert_eq!(n.to_be_bytes(10), bytes);
        // Longer than the number: zeros in front.
        let mut longer = vec![0; 3];
        longer.extend_from_slice(&bytes);
        assert_eq!(n.to_be_bytes(13), longer);
        // Leading zero bytes count as limbs until the number is trimmed.
        let padded = Limbs::from_be_bytes(&longer);
        assert_eq!(padded.len(), 2);
        let wide = Limbs::from_be_bytes(&[0; 20]);
        assert_eq!(wide.len(), 3);
        assert_eq!(wide.trimmed().len(), 0);
    }

    /// Dropping a number, a modulus and a clone of one leaves no limb of them in the
    /// memory that goes back to the allocator (see `testutil::probe`); and a
    /// number that is not wiped would be found, which the control checks.
    #[test]
    fn dropping_wipes_the_limbs() {
        use crate::rsa::testutil::probe::{leaks, needles_of_limbs};

        let m = limbs("c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b23");
        let secret = Limbs::from(
            &[
                0x1111_2222_3333_4444,
                0x5555_6666_7777_8888,
                0x9999_aaaa_bbbb_cccc,
            ][..],
        );
        let mut needles = needles_of_limbs(&secret);
        needles.extend(needles_of_limbs(&m));

        // The control: a plain vector is not wiped.
        let plain = secret.to_vec();
        assert_eq!(leaks(&needles, || drop(plain)), 3);

        let hits = leaks(&needles, || {
            let secret = secret.clone();
            let modulus = Modulus::new(m.clone()).unwrap();
            let base = modulus.to_mont(&secret);
            let power = modulus.pow(&base, &secret);
            let more = power.clone();
            drop((secret, modulus, base, power, more));
        });
        assert_eq!(hits, 0);
    }
}
