//! Arithmetic modulo the group order ℓ = 2^252 + 27742317777372353535851937790883648493
//! (RFC 8032 section 5.1): the integers that multiply points. The secret
//! scalar, the per-message nonce, the challenge and the S half of a signature
//! are all of this kind.
//!
//! A scalar is four 64-bit words. Reduction is Barrett's: the quotient is
//! estimated by a multiplication with a precomputed `2^512 / ℓ` instead of a
//! division, and a single conditional subtraction corrects the estimate. Every
//! function except `non_adjacent_form` runs the same instructions whatever the
//! values; that one is only used on public scalars.

use crate::ec::ct;

/// ℓ, in little-endian 64-bit words.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0,
    0x1000000000000000,
];

/// ⌊2^512 / ℓ⌋, the constant of Barrett reduction for 512-bit inputs. It is
/// just under 2^260.
const BARRETT: [u64; 5] = [
    0xed9ce5a30a2c131b,
    0x2106215d086329a7,
    0xffffffffffffffeb,
    0xffffffffffffffff,
    0xf,
];

/// An integer modulo ℓ, always fully reduced (below ℓ), in little-endian
/// 64-bit words.
#[derive(Clone, Copy)]
pub(super) struct Scalar(pub(super) [u64; 4]);

impl Scalar {
    /// A 64-byte little-endian integer, such as a SHA-512 digest, reduced
    /// modulo ℓ (RFC 8032 section 5.1.6, steps 2 and 4).
    pub(super) fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        let mut words = [0u64; 8];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let s = reduce(&words);
        crate::wipe::wipe(&mut words);
        s
    }

    /// The S half of a signature, if it is below ℓ (RFC 8032 section 5.1.7,
    /// step 1). Accepting S + ℓ as well would let anyone turn one valid
    /// signature into another (section 8.4).
    pub(super) fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut words = [0u64; 4];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        // `words - ℓ` borrows exactly when `words < ℓ`.
        let (_, borrow) = sub(&words, &L);
        (borrow == 1).then_some(Self(words))
    }

    /// The 32-byte little-endian encoding. The top three bits are always 0.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// `a * b + c` modulo ℓ: the S of RFC 8032 section 5.1.6, step 5.
    pub(super) fn mul_add(a: &Self, b: &Self, c: &Self) -> Self {
        // Schoolbook multiplication into eight words. Each step adds a
        // product below (2^64 - 1)^2 and two words to a u128, which is at
        // most 2^128 - 1, so the carries never overflow.
        let mut product = [0u64; 8];
        for (i, &ai) in a.0.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &bj) in b.0.iter().enumerate() {
                let t = u128::from(product[i + j]) + u128::from(ai) * u128::from(bj) + carry;
                product[i + j] = t as u64;
                carry = t >> 64;
            }
            product[i + 4] = carry as u64;
        }

        // a and b are below ℓ < 2^253, so a * b + c < 2^507 and the sum
        // cannot carry out of the eighth word.
        let addend = c.0.into_iter().chain([0; 4]);
        let mut carry = 0u128;
        for (word, c) in product.iter_mut().zip(addend) {
            let t = u128::from(*word) + u128::from(c) + carry;
            *word = t as u64;
            carry = t >> 64;
        }

        let s = reduce(&product);
        crate::wipe::wipe(&mut product);
        s
    }

    /// The scalar as 64 signed digits in radix 16, each in -8..=8:
    /// `self = sum(digits[i] * 16^i)`. Fixed-base multiplication then needs a
    /// table of only eight multiples per position, as negating a point is
    /// cheap. Constant time: the scalar is secret.
    pub(super) fn signed_radix16(self) -> [i8; 64] {
        let bytes = self.to_bytes();

        // First the plain digits, 0..=15, two per byte.
        let mut digits = [0i8; 64];
        for (pair, byte) in digits.chunks_exact_mut(2).zip(bytes) {
            pair[0] = (byte & 15) as i8;
            pair[1] = (byte >> 4) as i8;
        }

        // Then from the bottom up, each digit of 8 or more becomes itself
        // minus 16, with a carry of 1 into the next one. A digit is at most
        // 15 + 1 here, so `(digit + 8) >> 4` is that carry, 0 or 1, without a
        // comparison. The top digit is at most 1 + 1, since self < 2^253.
        for i in 0..63 {
            let carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
            digits[i + 1] += carry;
        }
        digits
    }

    /// The width-`w` non-adjacent form of the scalar: 256 digits, each 0 or
    /// odd and below 2^(w - 1) in absolute value, with at least `w - 1` zeros
    /// after every nonzero digit, such that `self = sum(naf[i] * 2^i)`.
    ///
    /// Few digits are nonzero, so a multiplication that skips the zeros does
    /// few additions. Which ones are nonzero depends on the scalar, so this is
    /// for public scalars only: verification uses it, signing does not.
    pub(super) fn non_adjacent_form(self, w: usize) -> [i8; 256] {
        debug_assert!((2..=8).contains(&w));
        let width = 1i64 << w;
        let window_mask = width - 1;

        // One spare word, so that a window that straddles the last word can
        // read past it.
        let mut words = [0u64; 5];
        words[..4].copy_from_slice(&self.0);

        let mut naf = [0i8; 256];
        let mut position = 0;
        let mut carry = 0;
        while position < 256 {
            let (word, bit) = (position / 64, position % 64);
            // The w bits starting at `position`, possibly from two words.
            let bits = if bit + w <= 64 {
                words[word] >> bit
            } else {
                (words[word] >> bit) | (words[word + 1] << (64 - bit))
            };
            let window = carry + (bits as i64 & window_mask);

            if window & 1 == 0 {
                // An even window adds nothing here; the carry, if any, moves
                // on with it to the next bit.
                position += 1;
                continue;
            }

            // An odd window becomes a digit. One of 2^(w - 1) or more is
            // taken as negative, and the 2^w it lacks carries upwards.
            if window < width / 2 {
                carry = 0;
                naf[position] = window as i8;
            } else {
                carry = 1;
                naf[position] = (window - width) as i8;
            }
            position += w;
        }
        naf
    }
}

/// `a - b` over four words, and the borrow out of the top word (1 if
/// `a < b`).
fn sub(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut difference = [0u64; 4];
    let mut borrow = 0u64;
    for ((d, &x), &y) in difference.iter_mut().zip(a).zip(b) {
        let (t, b1) = x.overflowing_sub(y);
        let (t, b2) = t.overflowing_sub(borrow);
        *d = t;
        borrow = u64::from(b1 | b2);
    }
    (difference, borrow)
}

/// `x` modulo ℓ, for any 512-bit `x`, by Barrett reduction.
///
/// With `m = ⌊2^512 / ℓ⌋` and `q = ⌊x m / 2^512⌋`, `q` is at most `x / ℓ`
/// and more than `x / ℓ - 2`, so `x - q ℓ` is in `[0, 2ℓ)`: one conditional
/// subtraction of ℓ completes the reduction. Since `x - q ℓ` is below
/// `2ℓ < 2^254`, it can be computed modulo 2^256, from the low four words of
/// `x` and of `q ℓ` only.
fn reduce(x: &[u64; 8]) -> Scalar {
    // x * m, a 13-word product, of which q is the top five words.
    let mut xm = [0u64; 13];
    for (i, &mi) in BARRETT.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &xj) in x.iter().enumerate() {
            let t = u128::from(xm[i + j]) + u128::from(mi) * u128::from(xj) + carry;
            xm[i + j] = t as u64;
            carry = t >> 64;
        }
        xm[i + 8] = carry as u64;
    }
    let q = &xm[8..];

    // q * ℓ modulo 2^256.
    let mut ql = [0u64; 4];
    for (i, &qi) in q.iter().enumerate().take(4) {
        let mut carry = 0u128;
        for (j, &lj) in L.iter().enumerate().take(4 - i) {
            let t = u128::from(ql[i + j]) + u128::from(qi) * u128::from(lj) + carry;
            ql[i + j] = t as u64;
            carry = t >> 64;
        }
    }

    let low: [u64; 4] = x[..4].try_into().expect("four words");
    let (r, _) = sub(&low, &ql);

    // r is below 2ℓ. Take r - ℓ unless that borrows, choosing with a mask
    // rather than a branch.
    let (r_minus_l, borrow) = sub(&r, &L);
    let keep_r = ct::mask(borrow);
    let mut s = [0u64; 4];
    for ((s, a), b) in s.iter_mut().zip(r).zip(r_minus_l) {
        *s = (a & keep_r) | (b & !keep_r);
    }

    crate::wipe::wipe(&mut xm);
    Scalar(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::sha2::Sha512;

    /// `x` modulo ℓ the slow way, one bit at a time from the top: double,
    /// add the bit, subtract ℓ if the result reached it. Written separately
    /// from `reduce`, against which it is checked.
    fn reference_reduce(x: &[u64]) -> [u64; 4] {
        let mut acc = [0u64; 4];
        for bit in (0..64 * x.len()).rev() {
            // acc < ℓ < 2^253, so doubling it and adding a bit fits.
            let mut carry = (x[bit / 64] >> (bit % 64)) & 1;
            for word in &mut acc {
                let next = *word >> 63;
                *word = (*word << 1) | carry;
                carry = next;
            }
            let (difference, borrow) = sub(&acc, &L);
            if borrow == 0 {
                acc = difference;
            }
        }
        acc
    }

    /// 512-bit values where Barrett reduction can go wrong: around 0, around
    /// multiples of ℓ, at the top of the range, and with long runs of ones
    /// or zeros, plus SHA-512 digests for good measure.
    fn edge_values() -> Vec<[u64; 8]> {
        let mut values = Vec::new();
        let l_times = |k: u64| -> [u64; 8] {
            // k * ℓ for a small k, then spread over eight words.
            let mut out = [0u64; 8];
            let mut carry = 0u128;
            for (o, &w) in out.iter_mut().zip(&L) {
                let t = u128::from(w) * u128::from(k) + carry;
                *o = t as u64;
                carry = t >> 64;
            }
            out[4] = carry as u64;
            out
        };
        for k in [0, 1, 2, 3, 16, 255] {
            let base = l_times(k);
            values.push(base);
            // One below and one above the multiple, where they exist.
            let mut above = base;
            above[0] += 1;
            values.push(above);
            if k > 0 {
                let mut below = base;
                let mut i = 0;
                loop {
                    let (w, b) = below[i].overflowing_sub(1);
                    below[i] = w;
                    if !b {
                        break;
                    }
                    i += 1;
                }
                values.push(below);
            }
        }
        values.push([u64::MAX; 8]);
        values.push([u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0, 0, 0, 0]);
        values.push([0, 0, 0, 0, 0, 0, 0, 1 << 63]);
        values.push([0, 0, 0, 0, 0, 0, 0, u64::MAX]);
        values.push([u64::MAX, 0, u64::MAX, 0, u64::MAX, 0, u64::MAX, 0]);
        for i in 0u8..32 {
            let digest = Sha512::digest(&[i]);
            let mut words = [0u64; 8];
            for (w, c) in words.iter_mut().zip(digest.as_chunks::<8>().0) {
                *w = u64::from_le_bytes(*c);
            }
            values.push(words);
        }
        values
    }

    #[test]
    fn reduction_matches_reference() {
        for x in edge_values() {
            assert_eq!(reduce(&x).0, reference_reduce(&x), "x = {x:x?}");
        }
    }

    #[test]
    fn mul_add_matches_reference() {
        // Operands at the top of the range, where every carry is taken, and
        // 2^160 + 1 and 2^160 - 1, whose product 2^320 - 1 fills five words
        // with ones, so that adding 1 carries all the way into the sixth.
        let l_minus = |k: u64| Scalar([L[0] - k, L[1], L[2], L[3]]);
        let operands = [
            Scalar([0; 4]),
            Scalar([1, 0, 0, 0]),
            l_minus(1),
            l_minus(2),
            Scalar([u64::MAX, u64::MAX, u64::MAX, 0x0fff_ffff_ffff_ffff]),
            reduce(&[u64::MAX; 8]),
            Scalar([1, 0, 1 << 32, 0]),
            Scalar([u64::MAX, u64::MAX, (1 << 32) - 1, 0]),
        ];
        for a in &operands {
            for b in &operands {
                for c in &operands {
                    // The same, by the reference: a * b as a 512-bit
                    // integer, reduced one bit at a time, plus c.
                    let mut wide = [0u64; 8];
                    for (i, &ai) in a.0.iter().enumerate() {
                        let mut carry = 0u128;
                        for (j, &bj) in b.0.iter().enumerate() {
                            let t =
                                u128::from(wide[i + j]) + u128::from(ai) * u128::from(bj) + carry;
                            wide[i + j] = t as u64;
                            carry = t >> 64;
                        }
                        wide[i + 4] = carry as u64;
                    }
                    let expected = reference_add(&reference_reduce(&wide), &c.0);
                    assert_eq!(
                        Scalar::mul_add(a, b, c).0,
                        expected,
                        "a = {:x?}, b = {:x?}, c = {:x?}",
                        a.0,
                        b.0,
                        c.0
                    );
                }
            }
        }
    }

    /// `a + b` modulo ℓ, for `a` and `b` below ℓ.
    fn reference_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for ((s, &x), &y) in sum.iter_mut().zip(a).zip(b) {
            let t = u128::from(x) + u128::from(y) + carry;
            *s = t as u64;
            carry = t >> 64;
        }
        reference_reduce(&sum)
    }
}
