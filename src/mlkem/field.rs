//! The integers modulo `q = 3329`, and the polynomials of `R_q` and `T_q` over
//! them (FIPS 203, section 2.4 and 4.3).
//!
//! A coefficient is an `i16`. It is not reduced after each sum or difference,
//! but where the next step needs it to be small, and the products are made with
//! Montgomery's reduction (`R = 2^16`) and reduced with Barrett's. Every
//! function says what it takes and what it gives, in absolute value, and the
//! tests run each of them with all coefficients at the largest value allowed
//! (in debug builds, where an overflow is a panic).
//!
//! Nothing here depends on a secret except by way of additions, multiplications,
//! shifts and masks: no branch, and no table indexed by a coefficient. The
//! tables (of the roots of unity) are read in the order of the loops.

/// `n`: the number of coefficients of a polynomial.
pub(super) const N: usize = 256;

/// `q`: the prime of the field.
pub(super) const Q: i32 = 3329;

/// A polynomial of `R_q`, or its image in `T_q`: 256 coefficients, in `i16`.
pub(super) type Poly = [i16; N];

/// `R = 2^16`, the radix of Montgomery's reduction.
const R: i32 = 1 << 16;

/// `q^-1 mod 2^16`, as a signed 16-bit number (`-3327`).
const Q_INV: i16 = inverse_of_q_mod_2_16();

/// `R^2 mod q`: multiplying by it with [`fqmul`] multiplies by `R`.
const R_SQUARED: i16 = (R as i64 * R as i64 % Q as i64) as i16;

/// `2^7 = 128` has the inverse `3303` modulo `q`, and `R / 128 = 512`: [`fqmul`]
/// by it divides by 128, the last step of the inverse transform.
const INVERSE_OF_128_TIMES_R: i16 = 512;

const fn inverse_of_q_mod_2_16() -> i16 {
    // Newton's iteration: each step doubles the number of correct low bits.
    let q = Q as u32;
    let mut x = q; // correct to 3 bits, as q * q = 1 mod 8
    let mut i = 0;
    while i < 4 {
        x = x.wrapping_mul(2u32.wrapping_sub(q.wrapping_mul(x)));
        i += 1;
    }
    x as u16 as i16
}

/// `a * b mod q` for plain numbers, in `u32`. For the constants below.
const fn mul_mod(a: u32, b: u32) -> u32 {
    a * b % Q as u32
}

const fn pow_mod(mut base: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}

/// `BitRev7` of FIPS 203 (section 4.3): the 7 low bits of `x`, reversed.
const fn bit_rev_7(mut x: u32) -> u32 {
    let mut reversed = 0;
    let mut i = 0;
    while i < 7 {
        reversed = reversed << 1 | x & 1;
        x >>= 1;
        i += 1;
    }
    reversed
}

/// `x * R mod q`, as the representative between `-q/2` and `q/2`: `x` in
/// Montgomery's form, which [`fqmul`] turns back into plain numbers.
const fn to_montgomery(x: u32) -> i16 {
    let m = (x * (1 << 16) % Q as u32) as i32;
    (if m > Q / 2 { m - Q } else { m }) as i16
}

/// `zeta = 17`, the primitive 256th root of unity modulo `q` (FIPS 203,
/// section 2.4).
const ZETA: u32 = 17;

/// `ZETAS[i] = zeta^BitRev7(i)` for the 128 `i` (FIPS 203, appendix A), in
/// Montgomery's form: the factors of the butterflies of the transform.
pub(super) const ZETAS: [i16; 128] = {
    let mut table = [0; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = to_montgomery(pow_mod(ZETA, bit_rev_7(i as u32)));
        i += 1;
    }
    table
};

/// `GAMMAS[i] = zeta^(2 * BitRev7(i) + 1)` for the 128 pairs of coefficients
/// (FIPS 203, appendix A), in Montgomery's form: the `X^2 - gamma` that
/// `T_q` multiplies modulo, pair by pair. They come from the table above: the
/// exponent of an even pair is `BitRev7(64 + i / 2)`, and an odd pair has the
/// negative of its predecessor's.
const GAMMAS: [i16; 128] = {
    let mut table = [0; 128];
    let mut i = 0;
    while i < 128 {
        let z = ZETAS[64 + i / 2];
        table[i] = if i % 2 == 0 { z } else { -z };
        i += 1;
    }
    table
};

/// Montgomery's reduction: `a / 2^16 mod q`, for `|a| <= 2^15 * q`, and a
/// number between `-q` and `q` (`|result| <= |a| / 2^16 + q / 2`).
///
/// `t` is the number below `2^16` for which `a - t * q` is a multiple of
/// `2^16`; the quotient is exact, so nothing is lost and nothing branches.
#[inline(always)]
pub(super) fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(Q_INV);
    ((a - i32::from(t) * Q) >> 16) as i16
}

/// Barrett's reduction: the representative of `a` modulo `q` between `-1664`
/// and `1664`, for any `a`.
///
/// `V / 2^26` is a little over `1 / q`, so `t` is `a / q` rounded to the nearest
/// integer.
#[inline(always)]
pub(super) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + Q / 2) / Q;
    let t = (V * i32::from(a) + (1 << 25)) >> 26;
    (i32::from(a) - t * Q) as i16
}

/// `a * b / 2^16 mod q`: Montgomery's product. With one of the two in
/// Montgomery's form (`x * 2^16`) it is the plain product of the two.
#[inline(always)]
pub(super) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// The coefficient `a` as a number between 0 and `q - 1`, for any `a`.
#[inline(always)]
pub(super) fn to_unsigned(a: i16) -> u16 {
    let r = barrett_reduce(a);
    (r + ((r >> 15) & Q as i16)) as u16
}

/// Brings every coefficient to between `-1664` and `1664`.
pub(super) fn reduce(f: &mut Poly) {
    for c in f {
        *c = barrett_reduce(*c);
    }
}

/// `f + g`, coefficient by coefficient, not reduced. For `|f| + |g| < 2^15`.
pub(super) fn add(f: &mut Poly, g: &Poly) {
    for (a, b) in f.iter_mut().zip(g) {
        *a += b;
    }
}

/// `f - g`, coefficient by coefficient, not reduced. For `|f| + |g| < 2^15`.
pub(super) fn sub(f: &mut Poly, g: &Poly) {
    for (a, b) in f.iter_mut().zip(g) {
        *a -= b;
    }
}

/// `NTT` (FIPS 203, algorithm 9): the image of `f` in `T_q`, in place.
///
/// Seven layers of butterflies, each `f[j] + zeta * f[j + len]` and
/// `f[j] - zeta * f[j + len]` with the `zeta` of the block. Each layer adds
/// less than `q` to the largest coefficient (the product is under `q / 2 +
/// |zeta| * |f| / 2^16`), so for `|f| <= q` before, the result is under `8 * q`
/// in absolute value, which fits; the last step reduces it to between `-1664`
/// and `1664`.
pub(super) fn ntt(f: &mut Poly) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        for block in f.chunks_exact_mut(2 * len) {
            let zeta = ZETAS[k];
            k += 1;
            let (low, high) = block.split_at_mut(len);
            for (a, b) in low.iter_mut().zip(high) {
                let t = fqmul(zeta, *b);
                *b = *a - t;
                *a += t;
            }
        }
        len /= 2;
    }
    reduce(f);
}

/// `NTT^-1` (FIPS 203, algorithm 10): the polynomial of `R_q` whose image is
/// `f`, in place.
///
/// The butterflies run the other way, with the sum reduced after each (so that
/// it cannot grow) and the difference brought under `2 * q` by the product
/// with `zeta`; the 128 that the sums add up to is divided out at the end.
/// For `|f| <= q` the result is under `1700` in absolute value.
pub(super) fn inverse_ntt(f: &mut Poly) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        for block in f.chunks_exact_mut(2 * len) {
            let zeta = ZETAS[k];
            k -= 1;
            let (low, high) = block.split_at_mut(len);
            for (a, b) in low.iter_mut().zip(high) {
                let t = *a;
                *a = barrett_reduce(t + *b);
                *b = fqmul(zeta, *b - t);
            }
        }
        len *= 2;
    }
    for c in f {
        *c = fqmul(*c, INVERSE_OF_128_TIMES_R);
    }
}

/// The sum of the products `a[i] * b[i]` in `T_q` (`MultiplyNTTs`, FIPS 203
/// algorithm 11, with `BaseCaseMultiply`, algorithm 12), for the vectors `a`
/// and `b` of polynomials of `T_q`, as a polynomial with every coefficient
/// between `-q` and `q`.
///
/// `T_q` is 128 pairs of coefficients, each multiplied modulo `X^2 - gamma`:
/// `(a0 + a1 X)(b0 + b1 X) = (a0 b0 + a1 b1 gamma) + (a0 b1 + a1 b0) X`. The
/// products of the terms are added in 32 bits first, which is exact: for
/// `|a|, |b| <= q`, and at most four terms, a sum is under `8 * q^2`, which is
/// under `2^15 * q`, what [`montgomery_reduce`] takes. `a1 b1` is reduced
/// once (it still has to be multiplied by `gamma`), and each output once, and
/// then once more by `R^2` to cancel the `R^-1` of the first.
///
/// # Panics
///
/// If `b` has fewer polynomials than `a`, or `a` more than four (debug builds
/// only: the sums would overflow).
pub(super) fn dot<'a>(a: impl Iterator<Item = &'a Poly>, b: &[Poly]) -> Poly {
    // Sums of the terms for the 128 pairs: a0 b0, a1 b1, and a0 b1 + a1 b0.
    let mut even = [0i32; N / 2];
    let mut odd_product = [0i32; N / 2];
    let mut cross = [0i32; N / 2];
    for (a, b) in a.zip(b) {
        for (i, (a, b)) in a.chunks_exact(2).zip(b.chunks_exact(2)).enumerate() {
            let (a0, a1) = (i32::from(a[0]), i32::from(a[1]));
            let (b0, b1) = (i32::from(b[0]), i32::from(b[1]));
            even[i] += a0 * b0;
            odd_product[i] += a1 * b1;
            cross[i] += a0 * b1 + a1 * b0;
        }
    }

    let mut out = [0; N];
    for (i, pair) in out.chunks_exact_mut(2).enumerate() {
        // a1 b1 / R, times gamma * R: gamma * a1 b1, added to a0 b0.
        let x0 = even[i] + i32::from(GAMMAS[i]) * i32::from(montgomery_reduce(odd_product[i]));
        // Each is the right sum divided by R; the product with R^2 divides by R
        // once more and so multiplies by R.
        pair[0] = fqmul(montgomery_reduce(x0), R_SQUARED);
        pair[1] = fqmul(montgomery_reduce(cross[i]), R_SQUARED);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::testutil::Prng;
    use super::*;

    /// `zeta^BitRev7(i)` for `i` from 0 to 127: the first table of FIPS 203, appendix A.
    const APPENDIX_A_ZETAS: [u32; 128] = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885,
        2154,
    ];

    /// `zeta^(2 * BitRev7(i) + 1)` for `i` from 0 to 127: the second table of FIPS 203, appendix A.
    const APPENDIX_A_GAMMAS: [u32; 128] = [
        17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
        1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
        1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687,
        642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641,
        2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239,
        1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863,
        2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554,
        886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885,
        2444, 2154, 1175,
    ];

    /// `a mod q`, as a number from 0 to `q - 1`.
    fn modulo(a: i64) -> u32 {
        a.rem_euclid(i64::from(Q)) as u32
    }

    /// `R^-1 mod q`.
    fn inverse_of_r() -> u32 {
        pow_mod(modulo(i64::from(R)), Q as u32 - 2)
    }

    /// A polynomial of numbers from 0 to `q - 1`, as the specification has it.
    type Spec = [u32; N];

    /// `NTT` written out as FIPS 203 algorithm 9 has it, on numbers from 0 to
    /// `q - 1` and with the table of appendix A.
    fn spec_ntt(f: &Spec) -> Spec {
        let q = Q as u32;
        let mut f = *f;
        let mut i = 1;
        let mut len = 128;
        while len >= 2 {
            let mut start = 0;
            while start < N {
                let zeta = APPENDIX_A_ZETAS[i];
                i += 1;
                for j in start..start + len {
                    let t = zeta * f[j + len] % q;
                    f[j + len] = (f[j] + q - t) % q;
                    f[j] = (f[j] + t) % q;
                }
                start += 2 * len;
            }
            len /= 2;
        }
        f
    }

    /// `NTT^-1`, FIPS 203 algorithm 10.
    fn spec_inverse_ntt(f: &Spec) -> Spec {
        let q = Q as u32;
        let mut f = *f;
        let mut i = 127;
        let mut len = 2;
        while len <= 128 {
            let mut start = 0;
            while start < N {
                let zeta = APPENDIX_A_ZETAS[i];
                i -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = (t + f[j + len]) % q;
                    f[j + len] = zeta * ((f[j + len] + q - t) % q) % q;
                }
                start += 2 * len;
            }
            len *= 2;
        }
        f.map(|c| c * 3303 % q)
    }

    /// `MultiplyNTTs`, FIPS 203 algorithm 11, with `BaseCaseMultiply`
    /// (algorithm 12) written into it.
    fn spec_multiply_ntts(f: &Spec, g: &Spec) -> Spec {
        let q = Q as u32;
        let mut h = [0; N];
        for i in 0..N / 2 {
            let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
            h[2 * i] = (a0 * b0 + a1 * b1 % q * APPENDIX_A_GAMMAS[i]) % q;
            h[2 * i + 1] = (a0 * b1 + a1 * b0) % q;
        }
        h
    }

    /// The product in `R_q = Z_q[X] / (X^256 + 1)`, by the definition: the
    /// product of the polynomials, with `X^256` replaced by `-1`.
    fn schoolbook(f: &Spec, g: &Spec) -> Spec {
        let mut h = [0i64; N];
        for (i, &a) in f.iter().enumerate() {
            for (j, &b) in g.iter().enumerate() {
                let product = i64::from(a) * i64::from(b);
                if i + j < N {
                    h[i + j] += product;
                } else {
                    h[i + j - N] -= product;
                }
            }
        }
        h.map(modulo)
    }

    fn random_spec(prng: &mut Prng) -> Spec {
        core::array::from_fn(|_| prng.below(Q as u64) as u32)
    }

    fn to_poly(f: &Spec) -> Poly {
        f.map(|c| c as i16)
    }

    fn from_poly(f: &Poly) -> Spec {
        f.map(|c| modulo(i64::from(c)))
    }

    /// The polynomial with this coefficient in every position.
    fn constant(value: i16) -> Poly {
        [value; N]
    }

    /// Polynomials whose coefficients are at the edges of what the
    /// transforms are specified for (`|c| <= q`), alone and mixed.
    fn extremes() -> Vec<Poly> {
        let q = Q as i16;
        let mut out = vec![
            constant(q),
            constant(-q),
            constant(0),
            constant(1),
            constant(-1),
            constant(q / 2),
            constant(-(q / 2)),
        ];
        out.push(core::array::from_fn(|i| if i % 2 == 0 { q } else { -q }));
        out.push(core::array::from_fn(|i| if i % 2 == 0 { -q } else { q }));
        out.push(core::array::from_fn(|i| if i < N / 2 { q } else { -q }));
        out.push(core::array::from_fn(|i| if i % 4 < 2 { q } else { -q }));
        let mut prng = Prng(0x1234_5678_9abc_def1);
        for _ in 0..8 {
            out.push(core::array::from_fn(|_| {
                if prng.below(2) == 0 { q } else { -q }
            }));
        }
        out
    }

    #[test]
    fn the_constants_are_what_they_say() {
        // q^-1 mod 2^16, and the other numbers of the reductions.
        assert_eq!(Q_INV, -3327);
        assert_eq!((i32::from(Q_INV) * Q).rem_euclid(R), 1);
        assert_eq!(R_SQUARED, 1353);
        assert_eq!(
            modulo(i64::from(R_SQUARED)),
            pow_mod(modulo(i64::from(R)), 2)
        );
        // R / 128 is 512, and 3303 is the inverse of 128 modulo q.
        assert_eq!(modulo(128 * 3303), 1);
        assert_eq!(
            modulo(128 * i64::from(INVERSE_OF_128_TIMES_R)),
            modulo(i64::from(R))
        );
        // zeta has order 256: its 128th power is -1 (FIPS 203, section 2.4).
        assert_eq!(pow_mod(ZETA, 128), Q as u32 - 1);
        assert_eq!(pow_mod(ZETA, 256), 1);
    }

    /// The tables are computed when the crate is compiled, and these are the
    /// tables of appendix A: `ZETAS` and `GAMMAS` hold them in Montgomery's
    /// form, between `-q/2` and `q/2`.
    #[test]
    fn the_tables_are_those_of_appendix_a() {
        let from_montgomery = |z: i16| modulo(i64::from(z) * i64::from(inverse_of_r()));
        for i in 0..128 {
            assert_eq!(from_montgomery(ZETAS[i]), APPENDIX_A_ZETAS[i], "zeta {i}");
            assert_eq!(
                from_montgomery(GAMMAS[i]),
                APPENDIX_A_GAMMAS[i],
                "gamma {i}"
            );
            assert!(ZETAS[i].abs() <= 1664 && GAMMAS[i].abs() <= 1664);
        }
    }

    #[test]
    fn barrett_reduces_every_i16() {
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            assert_eq!(modulo(i64::from(r)), modulo(i64::from(a)), "{a}");
            assert!(r.abs() <= 1664, "{a} -> {r}");

            let u = to_unsigned(a);
            assert_eq!(u32::from(u), modulo(i64::from(a)), "{a}");
        }
    }

    /// Montgomery's reduction gives `a / R mod q` and a number under `q` in
    /// absolute value, over the whole range it is specified for.
    #[test]
    fn montgomery_reduces_its_whole_range() {
        let limit = (1i32 << 15) * Q;
        let check = |a: i32| {
            let r = montgomery_reduce(a);
            assert_eq!(
                modulo(i64::from(r) * i64::from(R)),
                modulo(i64::from(a)),
                "{a}"
            );
            assert!(i32::from(r).abs() <= a.abs() / R + Q / 2 + 1, "{a} -> {r}");
        };
        for a in (-limit..=limit).step_by(7919) {
            check(a);
        }
        for a in [
            -limit,
            limit,
            -limit + 1,
            limit - 1,
            0,
            1,
            -1,
            R,
            -R,
            R - 1,
            1 - R,
        ] {
            check(a);
        }
        let mut prng = Prng(77);
        for _ in 0..200_000 {
            check(prng.below(2 * limit as u64 + 1) as i32 - limit);
        }
    }

    #[test]
    fn the_transform_matches_the_specification() {
        let mut prng = Prng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200 {
            let f = random_spec(&mut prng);
            let mut fast = to_poly(&f);
            ntt(&mut fast);
            assert!(fast.iter().all(|c| c.abs() <= 1664));
            assert_eq!(from_poly(&fast), spec_ntt(&f));

            // The same polynomial with its coefficients between -q/2 and q/2.
            let mut centered = f.map(|c| barrett_reduce(c as i16));
            ntt(&mut centered);
            assert_eq!(from_poly(&centered), spec_ntt(&f));
        }
        // The edges of the range, which fix the bound on the intermediate values.
        for f in extremes() {
            let mut fast = f;
            ntt(&mut fast);
            assert_eq!(from_poly(&fast), spec_ntt(&from_poly(&f)));
        }
    }

    #[test]
    fn the_inverse_transform_matches_the_specification() {
        let mut prng = Prng(0x2545_f491_4f6c_dd1d);
        for _ in 0..200 {
            let f = random_spec(&mut prng);
            let mut fast = to_poly(&f);
            inverse_ntt(&mut fast);
            assert!(fast.iter().all(|c| c.abs() < 1700));
            assert_eq!(from_poly(&fast), spec_inverse_ntt(&f));
        }
        for f in extremes() {
            let mut fast = f;
            inverse_ntt(&mut fast);
            assert!(fast.iter().all(|c| c.abs() < 1700), "{:?}", &fast[..4]);
            assert_eq!(from_poly(&fast), spec_inverse_ntt(&from_poly(&f)));
        }
    }

    /// The point of the transform: the product of `T_q` is the product of
    /// `R_q`, which the definition (`X^256 = -1`) gives with no table at all.
    #[test]
    fn the_product_in_t_q_is_the_product_in_r_q() {
        let mut prng = Prng(2024);
        for _ in 0..10 {
            let (f, g) = (random_spec(&mut prng), random_spec(&mut prng));
            let (mut a, mut b) = (to_poly(&f), to_poly(&g));
            ntt(&mut a);
            ntt(&mut b);
            let mut product = dot([&a].into_iter(), &[b]);
            inverse_ntt(&mut product);
            assert_eq!(from_poly(&product), schoolbook(&f, &g));
            // And the specification's own product agrees.
            assert_eq!(
                schoolbook(&f, &g),
                spec_inverse_ntt(&spec_multiply_ntts(&spec_ntt(&f), &spec_ntt(&g)))
            );
        }
    }

    #[test]
    fn the_dot_product_matches_the_specification() {
        let mut prng = Prng(99);
        for terms in 1..=4 {
            for _ in 0..30 {
                let a: Vec<Spec> = (0..terms).map(|_| random_spec(&mut prng)).collect();
                let b: Vec<Spec> = (0..terms).map(|_| random_spec(&mut prng)).collect();
                let mut expected = [0u32; N];
                for (a, b) in a.iter().zip(&b) {
                    let product = spec_multiply_ntts(a, b);
                    expected = core::array::from_fn(|i| (expected[i] + product[i]) % Q as u32);
                }
                let a: Vec<Poly> = a.iter().map(to_poly).collect();
                let b: Vec<Poly> = b.iter().map(to_poly).collect();
                let got = dot(a.iter(), &b);
                assert!(got.iter().all(|c| c.abs() <= Q as i16));
                assert_eq!(from_poly(&got), expected);
            }
        }
    }

    /// Four terms with every coefficient at the edge of what is allowed, in every
    /// combination of signs: the sums that the 32-bit accumulators and the
    /// reductions are sized for.
    #[test]
    fn the_dot_product_at_the_edges() {
        let edges = extremes();
        for (x, a) in edges.iter().enumerate() {
            for (y, b) in edges.iter().enumerate() {
                let a4 = [*a, *a, *a, *a];
                let b4 = [*b, *b, *b, *b];
                let got = dot(a4.iter(), &b4);
                let one = spec_multiply_ntts(&from_poly(a), &from_poly(b));
                let expected = one.map(|c| c * 4 % Q as u32);
                assert_eq!(from_poly(&got), expected, "{x} {y}");
            }
        }
    }
}
