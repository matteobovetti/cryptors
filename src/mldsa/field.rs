//! Arithmetic in `Z_q` and in the ring `R_q = Z_q[X] / (X^256 + 1)`, with the
//! number-theoretic transform that makes multiplying two elements of the ring
//! cheap (FIPS 204, sections 2.5 and 7.5, and algorithms 41 and 42).
//!
//! `q = 2^23 - 2^13 + 1 = 8380417`. A coefficient is an `i32` that is allowed
//! to be anywhere in a range that the function documents, not reduced to
//! `[0, q)` after each operation: the sums, the differences and the products
//! below do not overflow, so a value is reduced only where a later step needs
//! it to be (the rounding, the comparison with a bound and the encoding).
//! Every function says which ranges it takes and gives.
//!
//! Products are computed with Montgomery's reduction for `R = 2^32`: the product
//! of two values `a` and `b` comes out as `a * b / R mod q`. The transform and
//! its inverse are arranged so that the factor cancels: the table of roots of
//! unity is stored multiplied by `R`, and the inverse transform multiplies
//! by `R / 256`, so a product made in the transform domain and brought back with
//! [`inv_ntt_to_mont`] is the true product.
//!
//! None of it branches on a coefficient or uses one as an index.

/// The degree of the polynomials: they have `N` coefficients.
pub(super) const N: usize = 256;

/// The prime modulus of FIPS 204.
pub(super) const Q: i32 = 8_380_417;

/// An element of `R_q`, or of its image under the transform: the coefficient of
/// `X^i` at index `i`. What range the coefficients are in depends on where the
/// polynomial came from.
pub(super) type Poly = [i32; N];

/// `q^-1 mod 2^32`.
const QINV: i32 = 58_728_449;
const _: () = assert!((Q as u32).wrapping_mul(QINV as u32) == 1);

/// `a * b mod q` for `a, b < q`, at compile time.
const fn mul_mod(a: u64, b: u64) -> u64 {
    a * b % Q as u64
}

/// `base^exp mod q`, at compile time.
const fn pow_mod(mut base: u64, mut exp: u64) -> u64 {
    base %= Q as u64;
    let mut result = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exp >>= 1;
    }
    result
}

/// The 8 low bits of `k`, in the opposite order.
const fn bit_reverse_8(k: usize) -> usize {
    let mut out = 0;
    let mut i = 0;
    while i < 8 {
        out |= ((k >> i) & 1) << (7 - i);
        i += 1;
    }
    out
}

/// `1753`, a 512th root of unity modulo `q` (FIPS 204, section 2.5, which
/// calls it `zeta`): `1753^256 = -1`.
const ROOT: u64 = 1753;

/// `zeta^brv(k) * 2^32 mod q` for `k` in `0..256`, where `brv` reverses the
/// eight bits of `k` (FIPS 204, appendix B), each as the integer of smallest
/// absolute value, so that a product with it is within the range of
/// [`montgomery_reduce`]. `ZETAS[0]` is not used by the transforms.
const ZETAS: [i32; N] = {
    let mut table = [0i32; N];
    let mut k = 0;
    while k < N {
        let root = pow_mod(ROOT, bit_reverse_8(k) as u64);
        let montgomery = (root << 32) % Q as u64;
        table[k] = if montgomery > (Q / 2) as u64 {
            montgomery as i32 - Q
        } else {
            montgomery as i32
        };
        k += 1;
    }
    table
};

/// `2^64 / 256 mod q`: the factor of the last step of [`inv_ntt_to_mont`], which
/// scales by the inverse of the length of the transform and by `R`, and cancels
/// the `R^-1` that the products in the transform domain left.
const INV_N_MONT_SQUARED: i32 = {
    let r = (1u64 << 32) % Q as u64;
    mul_mod(mul_mod(r, r), pow_mod(N as u64, Q as u64 - 2)) as i32
};

/// Returns `a * 2^-32 mod q`, in `(-q, q)`, for `|a| < 2^31 * q`.
///
/// `t` is chosen so that `a - t * q` is a multiple of `2^32`.
#[inline(always)]
pub(super) fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

/// Returns a number congruent to `a` modulo `q`, in `[-6283009, 6283008]`, for
/// `a <= 2^31 - 2^22 - 1`. Not the representative of smallest absolute value,
/// which is what `centered` gives.
#[inline(always)]
pub(super) fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Returns `a + q` if `a` is negative and `a` otherwise, so `[0, q)` for
/// `a` in `[-q, q)`.
#[inline(always)]
pub(super) fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Returns the number in `[0, q)` congruent to `a`, for `a` in the range of
/// [`reduce32`].
#[inline(always)]
pub(super) fn reduce_to_positive(a: i32) -> i32 {
    caddq(reduce32(a))
}

/// Returns the number congruent to `a` modulo `q` with the smallest absolute
/// value, in `[-(q - 1) / 2, (q - 1) / 2]`, for `a` in `[0, q)`.
#[cfg(test)]
#[inline(always)]
pub(super) fn centered(a: i32) -> i32 {
    // `(q - 1) / 2 - a` is negative exactly when `a` is above the middle.
    a - ((((Q - 1) / 2 - a) >> 31) & Q)
}

/// Reduces every coefficient with [`reduce32`].
pub(super) fn reduce(a: &mut Poly) {
    for c in a {
        *c = reduce32(*c);
    }
}

/// Maps every coefficient from `[-q, q)` to `[0, q)`.
pub(super) fn caddq_all(a: &mut Poly) {
    for c in a {
        *c = caddq(*c);
    }
}

/// `a + b`, coefficient by coefficient, with no reduction.
pub(super) fn add_assign(a: &mut Poly, b: &Poly) {
    for (x, y) in a.iter_mut().zip(b) {
        *x += *y;
    }
}

/// `a - b`, coefficient by coefficient, with no reduction.
pub(super) fn sub_assign(a: &mut Poly, b: &Poly) {
    for (x, y) in a.iter_mut().zip(b) {
        *x -= *y;
    }
}

/// Whether some coefficient of `a` has absolute value `bound` or more, for
/// `0 < bound <= (q - 1) / 8` and `a` made by [`reduce`], so with coefficients
/// in `[-6283009, 6283008]`.
///
/// Such a coefficient is a representative of its class modulo `q` that is
/// within `bound` of zero only if it is the one of smallest absolute value,
/// because the others are at least `q - 6283009` away from zero, which is more
/// than `bound`. So this tells whether the centered coefficient reaches `bound`.
pub(super) fn exceeds(a: &Poly, bound: i32) -> bool {
    let mut over = 0;
    for &c in a {
        let abs = c - ((c >> 31) & (2 * c));
        // Negative exactly when `abs >= bound`.
        over |= (bound - 1 - abs) >> 31;
    }
    over != 0
}

/// Maps a polynomial to the transform domain, in place (FIPS 204, algorithm 41).
///
/// Takes coefficients of absolute value `B`, gives coefficients of absolute
/// value at most `B + 8q`: each of the eight layers adds at most `q`, which is
/// the bound of the product that it adds.
pub(super) fn ntt(a: &mut Poly) {
    let mut k = 0;
    let mut len = N / 2;
    while len >= 1 {
        for block in a.chunks_exact_mut(2 * len) {
            k += 1;
            let zeta = i64::from(ZETAS[k]);
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                let t = montgomery_reduce(zeta * i64::from(*y));
                *y = *x - t;
                *x += t;
            }
        }
        len >>= 1;
    }
}

/// Maps a polynomial back from the transform domain, in place, and multiplies
/// it by `2^32` (FIPS 204, algorithm 42). A product of two polynomials in the
/// transform domain, made by `montgomery_reduce` and so scaled by `2^-32`, comes
/// out as the true product.
///
/// Takes coefficients of absolute value less than `q` (what a Montgomery
/// reduction gives) and gives coefficients in `(-q, q)`. The additions in the
/// layers are not reduced; they stay in the `i32` because `256 * (q - 1)` is
/// less than `2^31`.
pub(super) fn inv_ntt_to_mont(a: &mut Poly) {
    let mut k = N;
    let mut len = 1;
    while len < N {
        for block in a.chunks_exact_mut(2 * len) {
            k -= 1;
            let zeta = -i64::from(ZETAS[k]);
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                let t = *x;
                *x = t + *y;
                *y = montgomery_reduce(zeta * i64::from(t - *y));
            }
        }
        len <<= 1;
    }
    let f = i64::from(INV_N_MONT_SQUARED);
    for c in a {
        *c = montgomery_reduce(f * i64::from(*c));
    }
}

/// Multiplies two polynomials of the transform domain, coefficient by
/// coefficient, and scales by `2^-32`. The product of the absolute values of
/// `a[i]` and `b[i]` must be less than `2^31 * q`.
pub(super) fn pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0; N];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = montgomery_reduce(i64::from(*x) * i64::from(*y));
    }
    out
}

/// Adds the products `a[i] * b[i]` to `acc[i]` in 64 bits, with no reduction.
/// [`reduce_sums`] finishes a sum of them.
#[inline]
pub(super) fn multiply_accumulate(acc: &mut [i64; N], a: &Poly, b: &Poly) {
    for ((s, x), y) in acc.iter_mut().zip(a).zip(b) {
        *s += i64::from(*x) * i64::from(*y);
    }
}

/// Subtracts the products `a[i] * b[i]` from `acc[i]`, as [`multiply_accumulate`]
/// adds them.
#[inline]
pub(super) fn multiply_subtract(acc: &mut [i64; N], a: &Poly, b: &Poly) {
    for ((s, x), y) in acc.iter_mut().zip(a).zip(b) {
        *s -= i64::from(*x) * i64::from(*y);
    }
}

/// Reduces a sum made by [`multiply_accumulate`] to coefficients in `(-q, q)`,
/// scaled by `2^-32`. The sum of the absolute values must be less than `2^31 * q`.
#[inline]
pub(super) fn reduce_sums(acc: &[i64; N]) -> Poly {
    let mut out = [0; N];
    for (o, s) in out.iter_mut().zip(acc) {
        *o = montgomery_reduce(*s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::testutil::Prng;
    use super::*;

    fn naive_mul(a: &[i64; N], b: &[i64; N]) -> [i64; N] {
        let q = i64::from(Q);
        let mut out = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] * b[j] % q;
                // X^256 = -1.
                if i + j < N {
                    out[i + j] = (out[i + j] + p) % q;
                } else {
                    out[i + j - N] = (out[i + j - N] - p) % q;
                }
            }
        }
        out.map(|x| x.rem_euclid(q))
    }

    #[test]
    fn montgomery_constants() {
        // The first entries of the table in the reference implementation of
        // CRYSTALS-Dilithium.
        assert_eq!(&ZETAS[1..5], &[25_847, -2_608_894, -518_909, 237_124]);
        assert_eq!(ZETAS[255], 1_976_782);
        // 2^64 / 256 mod q.
        assert_eq!(INV_N_MONT_SQUARED, 41_978);
        // 1753 is a primitive 512th root of unity.
        assert_eq!(pow_mod(ROOT, 256), Q as u64 - 1);
        assert_eq!(pow_mod(ROOT, 512), 1);
        // Every entry is the smallest representative.
        assert!(ZETAS.iter().all(|&z| z.abs() <= (Q - 1) / 2));
    }

    #[test]
    fn montgomery_reduce_divides_by_2_32() {
        let r_inv = pow_mod(1 << 32, Q as u64 - 2) as i64;
        let q = i64::from(Q);
        let mut prng = Prng(1);
        let edge = [0i64, 1, -1, q, -q, (1 << 31) * q - 1, -(1 << 31) * q + 1];
        let check = |a: i64| {
            let r = montgomery_reduce(a);
            assert!(r.abs() < Q, "{a} -> {r}");
            assert_eq!(
                i64::from(r).rem_euclid(q),
                a.rem_euclid(q) * r_inv % q,
                "{a}"
            );
        };
        for a in edge {
            check(a);
        }
        for _ in 0..200_000 {
            let magnitude = (prng.next() % ((1u64 << 31) * Q as u64)) as i64;
            check(if prng.next() & 1 == 0 {
                magnitude
            } else {
                -magnitude
            });
        }
    }

    /// `reduce32`, `caddq` and `centered` over every value that they take, and
    /// the ends of the range of `reduce32`.
    #[test]
    fn reductions_cover_their_ranges() {
        let q = i64::from(Q);
        for a in (-(1i64 << 31)..(1 << 31) - (1 << 22)).step_by(997).chain([
            (1 << 31) - (1 << 22) - 1,
            -(1 << 31),
            0,
        ]) {
            let a = a as i32;
            let r = reduce32(a);
            assert!((-6_283_009..=6_283_008).contains(&r), "{a} -> {r}");
            assert_eq!(i64::from(r).rem_euclid(q), i64::from(a).rem_euclid(q));
        }
        for a in -Q..Q {
            let r = caddq(a);
            assert!((0..Q).contains(&r));
            assert_eq!(i64::from(r), i64::from(a).rem_euclid(q));
        }
        for a in 0..Q {
            let c = centered(a);
            assert!(c.abs() <= (Q - 1) / 2);
            assert_eq!(i64::from(c).rem_euclid(q), i64::from(a));
        }
    }

    #[test]
    fn exceeds_is_the_infinity_norm_of_the_centered_value() {
        let mut a = [0; N];
        // Every class modulo q, as the representative that `reduce` gives.
        for bound in [
            1,
            78,
            196,
            120,
            95_232 - 78,
            131_072 - 78,
            261_888,
            1_047_552,
        ] {
            for v in (-Q / 2..=Q / 2).step_by(1_009).chain(
                [bound - 1, bound, -bound, -bound + 1, 0, Q / 2, -Q / 2]
                    .into_iter()
                    .chain([bound + Q, bound - Q, 1 - bound + Q]),
            ) {
                // A value that `reduce32` could give is not more than 6283009.
                if v.abs() > 6_283_008 {
                    continue;
                }
                a[7] = v;
                let centered_abs = i64::from(centered(caddq(reduce32(v)))).abs();
                assert_eq!(
                    exceeds(&a, bound),
                    centered_abs >= i64::from(bound),
                    "v {v}, bound {bound}"
                );
            }
        }
        // Any one position, and the others at zero.
        for position in 0..N {
            let mut a = [0; N];
            a[position] = -5;
            assert!(exceeds(&a, 5));
            assert!(!exceeds(&a, 6));
        }
    }

    #[test]
    fn transform_multiplies_polynomials() {
        let mut prng = Prng(7);
        for round in 0..6 {
            // Inputs as far from zero as the transform allows, and random ones.
            let bound = [Q - 1, 1, 6_283_008, 1 << 19, 4, Q / 2][round];
            let mut a = [0i32; N];
            let mut b = [0i32; N];
            for i in 0..N {
                a[i] = prng.signed(bound);
                b[i] = prng.signed(bound.min(Q - 1));
            }
            if round == 0 {
                a = [Q - 1; N];
                b = [-(Q - 1); N];
            }
            let expected = naive_mul(&a.map(i64::from), &b.map(i64::from));

            let (mut fa, mut fb) = (a, b);
            // The documented bound on the inputs of the transform.
            ntt(&mut fa);
            ntt(&mut fb);
            // The product must stay within the range of montgomery_reduce.
            let mut fc = pointwise(&fa, &fb);
            inv_ntt_to_mont(&mut fc);
            for i in 0..N {
                assert!(fc[i].abs() < Q);
                assert_eq!(
                    i64::from(fc[i]).rem_euclid(i64::from(Q)),
                    expected[i],
                    "{round} {i}"
                );
            }
        }
    }

    /// The transform's output stays within `B + 8q`, the bound that the sums of
    /// products downstream rely on.
    #[test]
    fn transform_output_bound() {
        let mut prng = Prng(11);
        for bound in [1, 4, 1 << 19, Q - 1] {
            for _ in 0..50 {
                let mut a = [0i32; N];
                for c in &mut a {
                    *c = if prng.next() & 3 == 0 { bound } else { -bound };
                }
                ntt(&mut a);
                assert!(
                    a.iter()
                        .all(|&c| i64::from(c).abs() <= i64::from(bound) + 8 * i64::from(Q))
                );
            }
        }
    }

    /// The inverse of the transform multiplies by `2^32`, so that a polynomial
    /// scaled by `2^-32` (as a product is) returns to itself.
    #[test]
    fn inverse_transform_undoes_the_transform() {
        let mut prng = Prng(13);
        let mut a = [0i32; N];
        for c in &mut a {
            *c = prng.signed(Q - 1);
        }
        let mut b = a;
        ntt(&mut b);
        // Multiplying by 2^-32 in the transform domain, as pointwise does.
        let one_over_r = [1i32 << 0; N];
        let mont_one = {
            let mut p = [0; N];
            p[0] = 1;
            ntt(&mut p);
            p
        };
        // The transform of 1 is all ones, and a pointwise product with it
        // scales by 2^-32.
        assert_eq!(mont_one, one_over_r);
        let mut c = pointwise(&b, &mont_one);
        inv_ntt_to_mont(&mut c);
        for i in 0..N {
            assert_eq!(
                i64::from(c[i]).rem_euclid(i64::from(Q)),
                i64::from(a[i]).rem_euclid(i64::from(Q))
            );
        }
    }

    /// A sum of seven products stays within the budget of `reduce_sums`.
    #[test]
    fn accumulated_products() {
        let mut prng = Prng(17);
        let mut acc = [0i64; N];
        let mut expected = [0i64; N];
        let q = i64::from(Q);
        for _ in 0..7 {
            let (mut a, mut b) = ([0i32; N], [0i32; N]);
            for i in 0..N {
                a[i] = prng.signed(Q - 1);
                b[i] = prng.signed((1 << 19) + 8 * Q);
            }
            multiply_accumulate(&mut acc, &a, &b);
            for i in 0..N {
                expected[i] += i64::from(a[i]) * i64::from(b[i]);
            }
        }
        let out = reduce_sums(&acc);
        let r_inv = pow_mod(1 << 32, Q as u64 - 2) as i64;
        for i in 0..N {
            assert!(out[i].abs() < Q);
            assert_eq!(
                i64::from(out[i]).rem_euclid(q),
                expected[i].rem_euclid(q) * r_inv % q
            );
        }
    }
}
