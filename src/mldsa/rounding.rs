//! Splitting a coefficient into a high part and a low part, and the hints that
//! let a verifier recover the high part of a number it can only approximate
//! (FIPS 204, section 7.4, algorithms 35 to 40).
//!
//! The functions take a coefficient in `[0, q)`, and none of them branches on
//! it: the choices are arithmetic shifts and masks, in the form that the
//! reference implementation of CRYSTALS-Dilithium has.

use super::field::Q;
use super::params::sealed::Sealed;

/// The number of bits dropped from `t` to make the public key: `d` in FIPS 204.
pub(super) const D: u32 = 13;

/// `Power2Round` (algorithm 35): `(t1, t0)` with `t = t1 * 2^13 + t0` and `t0` in
/// `(-2^12, 2^12]`, for `t` in `[0, q)`. Then `t1` is in `[0, 2^10)`.
#[inline(always)]
pub(super) fn power2round(t: i32) -> (i32, i32) {
    let t1 = (t + (1 << (D - 1)) - 1) >> D;
    (t1, t - (t1 << D))
}

/// `Decompose` (algorithm 36): `(r1, r0)` with `r = r1 * 2 * gamma2 + r0` modulo
/// `q`, `r0` in `(-gamma2, gamma2]`, except that when `r - r0` would be `q - 1`
/// the high part is 0 and the low part one less. Then `r1` is in `[0, m)`, where
/// `m = (q - 1) / (2 * gamma2)` is 44 or 16.
///
/// The high part is a division by `2 * gamma2` made with a multiplication: the
/// constants are those of the reference implementation, and the tests check
/// them against the definition for every `r`.
#[inline(always)]
pub(super) fn decompose<P: Sealed>(r: i32) -> (i32, i32) {
    let mut r1 = (r + 127) >> 7;
    if P::GAMMA2 == (Q - 1) / 32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    } else {
        debug_assert!(P::GAMMA2 == (Q - 1) / 88);
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        // 44 wraps to 0.
        r1 ^= ((43 - r1) >> 31) & r1;
    }
    let mut r0 = r - r1 * 2 * P::GAMMA2;
    // Brings a low part above (q - 1) / 2 down by q.
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;
    (r1, r0)
}

/// Whether the hint for a coefficient is 1, given the low part `r0` of the
/// number that the verifier will see and the high part `r1` of the one that the
/// signer meant (algorithm 39, `MakeHint`, in the form of the reference
/// implementation).
///
/// With `r0` in `(-gamma2, gamma2]` the high part of the number is `r1` and no
/// hint is needed. Past that range the high part changes, which the hint
/// reports. At `-gamma2` exactly, the high part changes unless `r1` is 0, where
/// `Decompose` folds the lowest low part into the top of the previous range.
///
/// The three conditions are combined with masks and not with `||`, which the
/// compiler is free to turn into jumps: the inputs come from the private key,
/// and the hints of an attempt that is rejected are never published.
#[inline(always)]
pub(super) fn make_hint<P: Sealed>(r0: i32, r1: i32) -> bool {
    // All ones when `r0 > gamma2`, and when `r0 < -gamma2`.
    let above = (P::GAMMA2 - r0) >> 31;
    let below = (r0 + P::GAMMA2) >> 31;
    // All ones when `r0 == -gamma2`, and when `r1 != 0`.
    let from_bottom = r0 + P::GAMMA2;
    let at_the_bottom = !((from_bottom | -from_bottom) >> 31);
    let high_part_is_not_zero = (r1 | -r1) >> 31;
    (above | below | (at_the_bottom & high_part_is_not_zero)) & 1 == 1
}

/// `UseHint` (algorithm 40): the high part of the number that `hint` and `r`
/// stand for.
#[inline(always)]
pub(super) fn use_hint<P: Sealed>(r: i32, hint: bool) -> i32 {
    let (r1, r0) = decompose::<P>(r);
    if !hint {
        return r1;
    }
    if P::GAMMA2 == (Q - 1) / 32 {
        if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 }
    } else if r0 > 0 {
        if r1 == 43 { 0 } else { r1 + 1 }
    } else if r1 == 0 {
        43
    } else {
        r1 - 1
    }
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlDsa44, MlDsa65};
    use super::super::testutil::Prng;
    use super::*;

    /// `r mod± m` for `m` even or odd, as FIPS 204 section 2.3 defines it: the
    /// number congruent to `r` modulo `m` in `(-m/2, m/2]`.
    fn mod_pm(r: i64, m: i64) -> i64 {
        let x = r.rem_euclid(m);
        if x > m / 2 { x - m } else { x }
    }

    /// Algorithm 36 as written.
    fn decompose_spec(r: i32, gamma2: i32) -> (i32, i32) {
        let r = i64::from(r).rem_euclid(i64::from(Q));
        let two_gamma2 = 2 * i64::from(gamma2);
        let r0 = mod_pm(r, two_gamma2);
        if r - r0 == i64::from(Q) - 1 {
            (0, (r0 - 1) as i32)
        } else {
            (((r - r0) / two_gamma2) as i32, r0 as i32)
        }
    }

    /// The reference implementation's way of computing the high part, which
    /// divides by `2 * gamma2` with a multiplication, against the definition for
    /// every number modulo `q`.
    #[test]
    fn decompose_matches_the_definition_for_every_number() {
        for r in 0..Q {
            assert_eq!(
                decompose::<MlDsa44>(r),
                decompose_spec(r, MlDsa44::GAMMA2),
                "{r}"
            );
            assert_eq!(
                decompose::<MlDsa65>(r),
                decompose_spec(r, MlDsa65::GAMMA2),
                "{r}"
            );
        }
    }

    #[test]
    fn power2round_matches_the_definition_for_every_number() {
        for t in 0..Q {
            let (t1, t0) = power2round(t);
            let expected_t0 = mod_pm(i64::from(t), 1 << D);
            assert_eq!(i64::from(t0), expected_t0, "{t}");
            assert_eq!(i64::from(t1) * (1 << D) + expected_t0, i64::from(t));
            assert!((0..1 << 10).contains(&t1));
            assert!(t0 > -(1 << 12) && t0 <= 1 << 12);
        }
    }

    /// Algorithm 40 as written.
    fn use_hint_spec(r: i32, hint: bool, gamma2: i32) -> i32 {
        let m = (Q - 1) / (2 * gamma2);
        let (r1, r0) = decompose_spec(r, gamma2);
        match (hint, r0 > 0) {
            (false, _) => r1,
            (true, true) => (r1 + 1).rem_euclid(m),
            (true, false) => (r1 - 1).rem_euclid(m),
        }
    }

    #[test]
    fn use_hint_matches_the_definition_for_every_number() {
        for r in 0..Q {
            for hint in [false, true] {
                assert_eq!(
                    use_hint::<MlDsa44>(r, hint),
                    use_hint_spec(r, hint, MlDsa44::GAMMA2),
                    "{r} {hint}"
                );
                assert_eq!(
                    use_hint::<MlDsa65>(r, hint),
                    use_hint_spec(r, hint, MlDsa65::GAMMA2),
                    "{r} {hint}"
                );
            }
        }
    }

    /// What the signer computes: the hint bit of `MakeHint(-ct0, w - cs2 + ct0)`
    /// (algorithm 39, which compares `HighBits(r)` with `HighBits(r + z)`)
    /// written from the low part of `w` the way the reference does, against the
    /// definition.
    ///
    /// Signing only gets as far as the hint for a `w` whose low part stays
    /// `gamma2 - beta` away from the ends of its range after `cs2` is taken off,
    /// and a `ct0` below `gamma2`. So the cases are those `w` at each of the 44
    /// or 16 boundaries, a little inside the reachable edge, and the `ct0` that
    /// puts the sum just inside, exactly on and just past each end of the range
    /// of the low part, as well as a spread of others.
    fn make_hint_agrees<P: Sealed>() {
        let g2 = P::GAMMA2;
        let mut checked = 0u64;
        let mut check = |w: i32, cs2: i32, ct0: i32| {
            let (w1, w0) = decompose_spec(w, g2);
            if (w0 - cs2).abs() >= g2 - P::BETA || ct0.abs() >= g2 {
                return;
            }
            let after = (w - cs2 + ct0).rem_euclid(Q);
            let before = (w - cs2).rem_euclid(Q);
            let expected = decompose_spec(after, g2).0 != decompose_spec(before, g2).0;
            let got = make_hint::<P>(w0 - cs2 + ct0, w1);
            assert_eq!(got, expected, "w {w} cs2 {cs2} ct0 {ct0}");
            checked += 1;
        };

        let mut boundaries = vec![0, Q - 1];
        let mut edge = g2;
        while edge < Q {
            boundaries.push(edge);
            edge += 2 * g2;
        }
        let mut prng = Prng(3);
        for boundary in boundaries {
            for inset in [P::BETA, P::BETA + 1, P::BETA + 40, g2 / 2, 5, 0] {
                for offset in [-inset, inset, -inset - 1, inset + 1] {
                    for w in (boundary + offset - 2)..=(boundary + offset + 2) {
                        let w = w.rem_euclid(Q);
                        let w0 = decompose_spec(w, g2).1;
                        for cs2 in [-P::BETA, -1, 0, 1, P::BETA, prng.signed(P::BETA)] {
                            // The sums that land on, next to and past each end.
                            for target in [g2 - 1, g2, g2 + 1, -g2 - 1, -g2, -g2 + 1, 0] {
                                check(w, cs2, target - (w0 - cs2));
                            }
                            for ct0 in [-g2 + 1, -P::BETA, -1, 0, 1, P::BETA, g2 - 1] {
                                check(w, cs2, ct0);
                            }
                        }
                    }
                }
            }
        }
        for _ in 0..50_000 {
            let w = (prng.next() % Q as u64) as i32;
            check(w, prng.signed(P::BETA), prng.signed(g2 - 1));
        }
        assert!(checked > 20_000, "{checked}");
    }

    #[test]
    fn make_hint_matches_the_definition() {
        make_hint_agrees::<MlDsa44>();
        make_hint_agrees::<MlDsa65>();
    }
}
