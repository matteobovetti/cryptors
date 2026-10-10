//! Points of edwards25519, the twisted Edwards curve
//! `-x^2 + y^2 = 1 + d x^2 y^2` over GF(2^255 - 19) (RFC 8032 section 5.1):
//! their encoding, the group law, and the two scalar multiplications that
//! Ed25519 needs.
//!
//! - [`EdwardsPoint::mul_base`] computes `[s]B` for a secret `s`, in constant
//!   time: the same additions, doublings and memory accesses for every `s`.
//!   Key derivation and signing use it.
//! - [`EdwardsPoint::vartime_double_mul_base`] computes `[a]A + [b]B` for
//!   public `a`, `A` and `b`, in time that depends on them. Verification uses
//!   it, and nothing else does.
//!
//! The formulas are those of RFC 8032 section 5.1.4 (from "Twisted Edwards
//! Curves Revisited", Hisil, Wong, Carter and Dawson, 2008), which are
//! complete: they hold for every pair of points, the identity and equal points
//! included, so no case needs a branch. The precomputed forms and the order
//! of operations follow Go's `crypto/internal/fips140/edwards25519`.

use std::sync::OnceLock;

use super::scalar::Scalar;
use crate::ec::ct;
use crate::ec::fe25519::Fe;

/// The curve constant d = -121665 / 121666 (RFC 8032, section 5.1).
const D: Fe = Fe::from_bytes(&[
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
]);

/// 2 * d, which the addition formulas use.
const D2: Fe = Fe::from_bytes(&[
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24,
]);

/// The encoding of the base point B: y = 4/5, with x positive.
const BASEPOINT_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// A point in extended homogeneous coordinates (X : Y : Z : T), standing for
/// x = X/Z, y = Y/Z, with x y = T/Z (RFC 8032 section 5.1.4).
#[derive(Clone, Copy)]
pub(super) struct EdwardsPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// A point in projective coordinates (X : Y : Z): the extended ones without
/// T, which doubling does not need.
#[derive(Clone, Copy)]
struct ProjectivePoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// The result of an addition or a doubling before its last four
/// multiplications: the E, F, G and H of RFC 8032 section 5.1.4, from which
/// X3 = E F, Y3 = G H, T3 = E H and Z3 = F G.
///
/// Stopping here lets the caller do only the multiplications it needs: all
/// four for the extended coordinates of the next addition, three for the
/// projective ones of the next doubling.
#[derive(Clone, Copy)]
struct CompletedPoint {
    e: Fe,
    f: Fe,
    g: Fe,
    h: Fe,
}

/// A point prepared to be the second operand of an addition:
/// (Y + X, Y - X, Z, 2 d T), the factors the addition formula multiplies by.
#[derive(Clone, Copy)]
struct CachedPoint {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

/// A point prepared like [`CachedPoint`] but divided through by Z, so that
/// Z = 1 is implied: (y + x, y - x, 2 d x y). The fixed tables of multiples
/// of B are made of these, which saves a multiplication per addition.
#[derive(Clone, Copy)]
struct AffineCachedPoint {
    y_plus_x: Fe,
    y_minus_x: Fe,
    t2d: Fe,
}

impl EdwardsPoint {
    /// The neutral element, (0, 1).
    pub(super) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The base point B of RFC 8032 section 5.1.
    pub(super) fn basepoint() -> Self {
        Self::decompress(&BASEPOINT_BYTES).expect("the base point decodes")
    }

    /// The encoding of RFC 8032 section 5.1.2: y, as 32 little-endian bytes,
    /// with the least significant bit of x in the top bit. Constant time.
    pub(super) fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;
        let mut bytes = y.to_bytes();
        bytes[31] |= x.is_negative() << 7;
        bytes
    }

    /// Decodes a point as RFC 8032 section 5.1.3 does, rejecting every string
    /// that is not the encoding [`compress`](Self::compress) would produce for
    /// a point of the curve:
    ///
    /// - y must be below p (step 1),
    /// - (y^2 - 1) / (d y^2 + 1) must be a square, the x^2 of the point
    ///   (steps 2 and 3),
    /// - and x = 0, which has only one sign, must come with the sign bit
    ///   clear (step 4).
    ///
    /// Variable time: it is only used on public keys.
    pub(super) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let y = Fe::from_bytes(bytes);
        let sign = bytes[31] >> 7;

        // Step 1. `from_bytes` keeps y as it is even if it is p or more;
        // then its canonical encoding differs from the bytes it came from.
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        if y.to_bytes() != y_bytes {
            return None;
        }

        // Steps 2 and 3: x^2 = u / v, with u = y^2 - 1 and v = d y^2 + 1.
        let yy = y.square();
        let u = yy - Fe::ONE;
        let v = yy * D + Fe::ONE;
        let mut x = Fe::sqrt_ratio(&u, &v)?;

        // Step 4.
        if x.is_zero() && sign == 1 {
            return None;
        }
        if x.is_negative() != sign {
            x = -x;
        }

        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x * y,
        })
    }

    /// -P = (-x, y).
    pub(super) fn negate(&self) -> Self {
        Self {
            x: -self.x,
            y: self.y,
            z: self.z,
            t: -self.t,
        }
    }

    /// P + Q.
    pub(super) fn add(&self, other: &Self) -> Self {
        self.add_cached(&other.to_cached()).to_extended()
    }

    /// 2P.
    pub(super) fn double(&self) -> Self {
        self.to_projective().double().to_extended()
    }

    /// Whether the point is in the small subgroup: one of the eight points
    /// whose order divides the cofactor 8, the identity among them.
    ///
    /// The group of the curve has order 8ℓ and is cyclic, so `[8]P` is in the
    /// subgroup of prime order ℓ, where only the identity has x = 0. P has
    /// small order exactly when `[8]P` is the identity. The three doublings
    /// need only projective coordinates, and X = 0 means x = 0.
    pub(super) fn is_small_order(&self) -> bool {
        let mut p = self.to_projective();
        for _ in 0..3 {
            p = p.double().to_projective();
        }
        p.x.is_zero()
    }

    fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    fn to_cached(self) -> CachedPoint {
        CachedPoint {
            y_plus_x: self.y + self.x,
            y_minus_x: self.y - self.x,
            z: self.z,
            t2d: self.t * D2,
        }
    }

    /// Divides through by Z, which costs an inversion. Only the fixed tables,
    /// built once, use it.
    fn to_affine_cached(self) -> AffineCachedPoint {
        let z_inv = self.z.invert();
        let (x, y) = (self.x * z_inv, self.y * z_inv);
        AffineCachedPoint {
            y_plus_x: y + x,
            y_minus_x: y - x,
            t2d: x * y * D2,
        }
    }

    /// P + Q, RFC 8032 section 5.1.4:
    ///
    /// ```text
    /// A = (Y1 - X1) (Y2 - X2)    E = B - A
    /// B = (Y1 + X1) (Y2 + X2)    F = D - C
    /// C = T1 2d T2               G = D + C
    /// D = Z1 2 Z2                H = B + A
    /// ```
    fn add_cached(&self, q: &CachedPoint) -> CompletedPoint {
        let a = (self.y - self.x) * q.y_minus_x;
        let b = (self.y + self.x) * q.y_plus_x;
        let c = self.t * q.t2d;
        let zz = self.z * q.z;
        let d = zz + zz;
        CompletedPoint {
            e: b - a,
            f: d - c,
            g: d + c,
            h: b + a,
        }
    }

    /// P - Q: the addition of -Q = (-x, y), whose Y + X and Y - X are those
    /// of Q swapped, and whose T is negated, which turns C into -C.
    fn sub_cached(&self, q: &CachedPoint) -> CompletedPoint {
        let a = (self.y - self.x) * q.y_plus_x;
        let b = (self.y + self.x) * q.y_minus_x;
        let c = self.t * q.t2d;
        let zz = self.z * q.z;
        let d = zz + zz;
        CompletedPoint {
            e: b - a,
            f: d + c,
            g: d - c,
            h: b + a,
        }
    }

    /// P + Q for Q with Z = 1, so that D = 2 Z1.
    fn add_affine(&self, q: &AffineCachedPoint) -> CompletedPoint {
        let a = (self.y - self.x) * q.y_minus_x;
        let b = (self.y + self.x) * q.y_plus_x;
        let c = self.t * q.t2d;
        let d = self.z + self.z;
        CompletedPoint {
            e: b - a,
            f: d - c,
            g: d + c,
            h: b + a,
        }
    }

    /// P - Q for Q with Z = 1.
    fn sub_affine(&self, q: &AffineCachedPoint) -> CompletedPoint {
        let a = (self.y - self.x) * q.y_plus_x;
        let b = (self.y + self.x) * q.y_minus_x;
        let c = self.t * q.t2d;
        let d = self.z + self.z;
        CompletedPoint {
            e: b - a,
            f: d + c,
            g: d - c,
            h: b + a,
        }
    }

    /// `[s]B`, in constant time.
    ///
    /// `s` is written in signed radix 16, `s = sum(s_i 16^i)` with
    /// `-8 <= s_i <= 8`, and split into its odd and even positions:
    ///
    /// ```text
    /// [s]B = sum over even i of [s_i] (16^i B)  +  16 * sum over odd i of [s_i] (16^(i-1) B)
    /// ```
    ///
    /// `16^i B` for even `i` is `256^(i/2) B`, and the table holds its first
    /// eight multiples for each of the 32 values of `i/2`. So the whole
    /// multiplication is 64 additions of a table entry and four doublings.
    /// Each entry is picked by reading all eight of its row and keeping one
    /// with masks, then negated or not with masks, so neither the memory
    /// accessed nor the instructions run depend on `s`.
    pub(super) fn mul_base(s: &Scalar) -> Self {
        let table = base_table();
        let mut digits = s.signed_radix16();

        let mut acc = Self::IDENTITY;
        for i in (1..64).step_by(2) {
            acc = acc
                .add_affine(&select(&table[i / 2], digits[i]))
                .to_extended();
        }

        // Times 16: four doublings, the first three of which only need the
        // projective coordinates of their result.
        let mut p = acc.to_projective();
        for _ in 0..3 {
            p = p.double().to_projective();
        }
        acc = p.double().to_extended();

        for i in (0..64).step_by(2) {
            acc = acc
                .add_affine(&select(&table[i / 2], digits[i]))
                .to_extended();
        }

        crate::wipe::wipe(&mut digits);
        acc
    }

    /// `[a]A + [b]B`, in variable time: only for public `a`, `A` and `b`.
    ///
    /// Both scalars go into non-adjacent form, and one pass of doublings
    /// from the top serves both: at each bit, a nonzero digit of `a` adds or
    /// subtracts an odd multiple of `A`, and one of `b` an odd multiple of
    /// `B`. `A`'s multiples (up to 15A) are computed here; `B`'s (up to 127B,
    /// a wider window since it costs nothing per call) come from a table
    /// built once.
    pub(super) fn vartime_double_mul_base(a: &Scalar, point: &Self, b: &Scalar) -> Self {
        let a_naf = a.non_adjacent_form(5);
        let b_naf = b.non_adjacent_form(8);

        // A, 3A, 5A, ..., 15A.
        let mut a_table = [point.to_cached(); 8];
        let a2 = point.double();
        for i in 1..8 {
            a_table[i] = a2.add_cached(&a_table[i - 1]).to_extended().to_cached();
        }
        let b_table = base_naf_table();

        // The highest bit at which either form has a nonzero digit; below it
        // the accumulator would only double the identity.
        let Some(top) = (0..256).rev().find(|&i| a_naf[i] != 0 || b_naf[i] != 0) else {
            return Self::IDENTITY;
        };

        let mut acc = ProjectivePoint {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
        };
        for i in (0..=top).rev() {
            let mut sum = acc.double();
            // The digits are odd, so digit / 2 is the index of |digit| times
            // the point: 1 -> 0, 3 -> 1, ..., 15 -> 7.
            match a_naf[i] {
                0 => {}
                d if d > 0 => sum = sum.to_extended().add_cached(&a_table[(d / 2) as usize]),
                d => sum = sum.to_extended().sub_cached(&a_table[(-d / 2) as usize]),
            }
            match b_naf[i] {
                0 => {}
                d if d > 0 => sum = sum.to_extended().add_affine(&b_table[(d / 2) as usize]),
                d => sum = sum.to_extended().sub_affine(&b_table[(-d / 2) as usize]),
            }
            acc = sum.to_projective();
        }
        acc.to_extended()
    }
}

impl ProjectivePoint {
    /// 2P, RFC 8032 section 5.1.4:
    ///
    /// ```text
    /// A = X1^2      H = A + B
    /// B = Y1^2      E = H - (X1 + Y1)^2
    /// C = 2 Z1^2    G = A - B
    ///               F = C + G
    /// ```
    fn double(&self) -> CompletedPoint {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz + zz;
        let h = a + b;
        let g = a - b;
        CompletedPoint {
            e: h - (self.x + self.y).square(),
            f: c + g,
            g,
            h,
        }
    }

    /// (X : Y : Z) to (X Z : Y Z : Z^2 : X Y), the same point with T.
    fn to_extended(self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x * self.z,
            y: self.y * self.z,
            z: self.z.square(),
            t: self.x * self.y,
        }
    }
}

impl CompletedPoint {
    /// X3 = E F, Y3 = G H, T3 = E H, Z3 = F G.
    fn to_extended(self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.e * self.f,
            y: self.g * self.h,
            z: self.f * self.g,
            t: self.e * self.h,
        }
    }

    /// As [`to_extended`](Self::to_extended), without T.
    fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.e * self.f,
            y: self.g * self.h,
            z: self.f * self.g,
        }
    }
}

impl AffineCachedPoint {
    /// The identity: y + x = 1, y - x = 1, 2 d x y = 0.
    const IDENTITY: Self = Self {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        t2d: Fe::ZERO,
    };

    /// `a` where `mask` is all ones and `b` where it is all zeros.
    #[inline(always)]
    fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Self {
            y_plus_x: Fe::select(mask, &a.y_plus_x, &b.y_plus_x),
            y_minus_x: Fe::select(mask, &a.y_minus_x, &b.y_minus_x),
            t2d: Fe::select(mask, &a.t2d, &b.t2d),
        }
    }
}

/// `row[|digit| - 1]`, negated if `digit` is negative, or the identity if it
/// is 0, for `digit` in -8..=8.
///
/// Constant time: all eight entries are read, and the one kept is chosen with
/// masks. Negating swaps y + x with y - x and negates 2 d x y, also with masks.
fn select(row: &[AffineCachedPoint; 8], digit: i8) -> AffineCachedPoint {
    // 1 if digit < 0, else 0; then |digit| as (digit XOR sign) - sign, with
    // sign all ones or all zeros.
    let negative = (digit as u8) >> 7;
    let sign = -(negative as i8);
    let magnitude = u64::from(((digit ^ sign) - sign) as u8);

    let mut out = AffineCachedPoint::IDENTITY;
    for (entry, j) in row.iter().zip(1u64..) {
        out = AffineCachedPoint::select(ct::mask(ct::eq(magnitude, j)), entry, &out);
    }

    let negate = ct::mask(u64::from(negative));
    AffineCachedPoint {
        y_plus_x: Fe::select(negate, &out.y_minus_x, &out.y_plus_x),
        y_minus_x: Fe::select(negate, &out.y_plus_x, &out.y_minus_x),
        t2d: Fe::select(negate, &-out.t2d, &out.t2d),
    }
}

/// The table of [`EdwardsPoint::mul_base`]: row `i` holds `B'`, `2B'`, ...,
/// `8B'` for `B' = 256^i B`. 32 rows of 8 points, built on first use.
fn base_table() -> &'static [[AffineCachedPoint; 8]; 32] {
    static TABLE: OnceLock<[[AffineCachedPoint; 8]; 32]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [[AffineCachedPoint::IDENTITY; 8]; 32];
        let mut row_base = EdwardsPoint::basepoint();
        for row in &mut table {
            let mut multiple = row_base;
            for entry in row.iter_mut() {
                *entry = multiple.to_affine_cached();
                multiple = multiple.add(&row_base);
            }
            for _ in 0..8 {
                row_base = row_base.double();
            }
        }
        table
    })
}

/// The table of [`EdwardsPoint::vartime_double_mul_base`]: B, 3B, 5B, ...,
/// 127B, built on first use.
fn base_naf_table() -> &'static [AffineCachedPoint; 64] {
    static TABLE: OnceLock<[AffineCachedPoint; 64]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let b = EdwardsPoint::basepoint();
        let b2 = b.double();
        let mut table = [AffineCachedPoint::IDENTITY; 64];
        let mut multiple = b;
        for entry in &mut table {
            *entry = multiple.to_affine_cached();
            multiple = multiple.add(&b2);
        }
        table
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[s]P` by plain double-and-add over the bits of `s`, from the top:
    /// none of the tables, digit recodings or precomputed forms of the real
    /// multiplication.
    fn reference_mul(s: &Scalar, p: &EdwardsPoint) -> EdwardsPoint {
        let bytes = s.to_bytes();
        let mut acc = EdwardsPoint::IDENTITY;
        for bit in (0..256).rev() {
            acc = acc.double();
            if (bytes[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = acc.add(p);
            }
        }
        acc
    }

    /// Scalars whose non-adjacent forms are unusual, all below ℓ: 0, small
    /// values, ℓ - 1, 2^252, and patterns repeated across the whole scalar.
    /// All ones is one long carry; alternating bits are the densest form.
    ///
    /// The hashes that make the challenge k never come out like this, but
    /// the S of a signature is whatever the sender chose, so verification
    /// has to be right for every scalar, not just likely ones.
    fn edge_scalars() -> [Scalar; 10] {
        let repeat = |w: u64| Scalar([w, w, w, w & 0x0fff_ffff_ffff_ffff]);
        [
            Scalar([0; 4]),
            Scalar([1, 0, 0, 0]),
            Scalar([8, 0, 0, 0]),
            Scalar([
                0x5812631a5cf5d3ec,
                0x14def9dea2f79cd6,
                0,
                0x1000000000000000,
            ]),
            Scalar([0, 0, 0, 1 << 60]),
            repeat(u64::MAX),
            repeat(0x8888_8888_8888_8888),
            repeat(0x7777_7777_7777_7777),
            repeat(0x5555_5555_5555_5555),
            repeat(0xaaaa_aaaa_aaaa_aaaa),
        ]
    }

    #[test]
    fn double_mul_matches_reference() {
        let b = EdwardsPoint::basepoint();
        let b_multiples = edge_scalars().map(|s| reference_mul(&s, &b));
        // A point other than B as A, and B itself.
        let other = reference_mul(&Scalar([0x1234_5678_9abc_def1, 7, 0, 0]), &b);
        for point in [other, b] {
            for a in edge_scalars() {
                let a_multiple = reference_mul(&a, &point);
                for (s, s_multiple) in edge_scalars().iter().zip(&b_multiples) {
                    assert_eq!(
                        EdwardsPoint::vartime_double_mul_base(&a, &point, s).compress(),
                        a_multiple.add(s_multiple).compress(),
                        "a = {:x?}, b = {:x?}",
                        a.0,
                        s.0
                    );
                }
            }
        }
    }
}
