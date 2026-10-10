//! Points of a curve `y^2 = x^3 - 3x + b` over a prime field, which is the
//! shape of all three NIST curves of this module (their `a` is -3).
//!
//! A point is kept in projective coordinates `(X : Y : Z)`, standing for the
//! affine point `(X / Z, Y / Z)`, and the point at infinity is `(0 : 1 : 0)`.
//! Addition and doubling use the complete formulas of Renes, Costello and
//! Batina, "Complete addition formulas for prime order elliptic curves"
//! (Eurocrypt 2016, <https://eprint.iacr.org/2015/1060>), Algorithms 4 and 6.
//! "Complete" means they are right for every pair of points of the curve,
//! including two equal points, opposite points and the point at infinity, so
//! the code that uses them has no special cases to branch on and a secret
//! scalar never selects between code paths.

use super::ct;
use super::field::{Fe, Modulus};

/// A curve `y^2 = x^3 - 3x + b` of prime order, with a generator.
pub(super) trait Weierstrass<const N: usize>: Modulus<N> {
    /// The coefficient `b`, below the prime, as little-endian limbs.
    const B: [u64; N];
    /// The coordinates of the generator.
    const GX: [u64; N];
    const GY: [u64; N];
    /// The order of the generator, as a big-endian number of the same length
    /// as an encoded scalar.
    const ORDER: &'static [u8];
}

/// A point of the curve `C`.
pub(super) struct Point<C: Weierstrass<N>, const N: usize> {
    x: Fe<C, N>,
    y: Fe<C, N>,
    z: Fe<C, N>,
}

impl<C: Weierstrass<N>, const N: usize> Clone for Point<C, N> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Weierstrass<N>, const N: usize> Copy for Point<C, N> {}

impl<C: Weierstrass<N>, const N: usize> Point<C, N> {
    const B: Fe<C, N> = Fe::from_limbs(C::B);

    /// The point at infinity.
    pub(super) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    /// The generator of the curve.
    pub(super) const GENERATOR: Self = Self {
        x: Fe::from_limbs(C::GX),
        y: Fe::from_limbs(C::GY),
        z: Fe::ONE,
    };

    /// The point with the affine coordinates `(x, y)`, given as the big-endian
    /// encodings of SEC 1, or `None` if either is not a number below the prime
    /// or the point is not on the curve. All of that is public.
    pub(super) fn from_affine_bytes(x: &[u8], y: &[u8]) -> Option<Self> {
        let (x, y) = (Fe::from_be_bytes(x)?, Fe::from_be_bytes(y)?);
        // y^2 = x^3 - 3x + b
        let rhs = x.square() * x - (x + x + x) + Self::B;
        if y.square().eq(&rhs) == 1 {
            Some(Self { x, y, z: Fe::ONE })
        } else {
            None
        }
    }

    /// The affine coordinates `(x, y)`, or `None` for the point at infinity.
    ///
    /// Whether the point is the identity is not hidden. The points this is
    /// called on are the product of a scalar below the order and a point other
    /// than infinity, which is never the identity, so the answer is always the
    /// same and tells nothing.
    pub(super) fn to_affine(self) -> Option<(Fe<C, N>, Fe<C, N>)> {
        if self.z.is_zero() == 1 {
            return None;
        }
        let z_inv = self.z.invert();
        Some((self.x * z_inv, self.y * z_inv))
    }

    /// `a` where `mask` is all ones and `b` where it is all zeros.
    #[inline(always)]
    fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Self {
            x: Fe::select(mask, &a.x, &b.x),
            y: Fe::select(mask, &a.y, &b.y),
            z: Fe::select(mask, &a.z, &b.z),
        }
    }

    /// `self + q`: Algorithm 4 of the paper, for `a = -3`.
    pub(super) fn add(&self, q: &Self) -> Self {
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (q.x, q.y, q.z);
        let b = Self::B;

        let mut t0 = x1 * x2;
        let mut t1 = y1 * y2;
        let mut t2 = z1 * z2;
        let mut t3 = x1 + y1;
        let mut t4 = x2 + y2;
        t3 = t3 * t4;
        t4 = t0 + t1;
        t3 = t3 - t4;
        t4 = y1 + z1;
        let mut x3 = y2 + z2;
        t4 = t4 * x3;
        x3 = t1 + t2;
        t4 = t4 - x3;
        x3 = x1 + z1;
        let mut y3 = x2 + z2;
        x3 = x3 * y3;
        y3 = t0 + t2;
        y3 = x3 - y3;
        let mut z3 = b * t2;
        x3 = y3 - z3;
        z3 = x3 + x3;
        x3 = x3 + z3;
        z3 = t1 - x3;
        x3 = t1 + x3;
        y3 = b * y3;
        t1 = t2 + t2;
        t2 = t1 + t2;
        y3 = y3 - t2;
        y3 = y3 - t0;
        t1 = y3 + y3;
        y3 = t1 + y3;
        t1 = t0 + t0;
        t0 = t1 + t0;
        t0 = t0 - t2;
        t1 = t4 * y3;
        t2 = t0 * y3;
        y3 = x3 * z3;
        y3 = y3 + t2;
        x3 = t3 * x3;
        x3 = x3 - t1;
        z3 = t4 * z3;
        t1 = t3 * t0;
        z3 = z3 + t1;

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + self`: Algorithm 6 of the paper, for `a = -3`.
    pub(super) fn double(&self) -> Self {
        let (x, y, z) = (self.x, self.y, self.z);
        let b = Self::B;

        let mut t0 = x.square();
        let t1 = y.square();
        let mut t2 = z.square();
        let mut t3 = x * y;
        t3 = t3 + t3;
        let mut z3 = x * z;
        z3 = z3 + z3;
        let mut y3 = b * t2;
        y3 = y3 - z3;
        let mut x3 = y3 + y3;
        y3 = x3 + y3;
        x3 = t1 - y3;
        y3 = t1 + y3;
        y3 = x3 * y3;
        x3 = x3 * t3;
        t3 = t2 + t2;
        t2 = t2 + t3;
        z3 = b * z3;
        z3 = z3 - t2;
        z3 = z3 - t0;
        t3 = z3 + z3;
        z3 = z3 + t3;
        t3 = t0 + t0;
        t0 = t3 + t0;
        t0 = t0 - t2;
        t0 = t0 * z3;
        y3 = y3 + t0;
        t0 = y * z;
        t0 = t0 + t0;
        z3 = t0 * z3;
        x3 = x3 - z3;
        z3 = t0 * t1;
        z3 = z3 + z3;
        z3 = z3 + z3;

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `-self`.
    #[cfg(test)]
    pub(super) fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Whether the two represent the same point.
    #[cfg(test)]
    pub(super) fn same_as(&self, other: &Self) -> bool {
        // X1 / Z1 = X2 / Z2 and Y1 / Z1 = Y2 / Z2, without dividing; for two
        // points at infinity both sides are zero.
        (self.x * other.z).eq(&(other.x * self.z)) == 1
            && (self.y * other.z).eq(&(other.y * self.z)) == 1
    }

    /// `index` times the point whose multiples 1 to 15 are `multiples`, for an
    /// `index` below 16: the point at infinity for 0. It reads every entry, so
    /// that the address of the one used does not depend on the (secret) index.
    #[inline(always)]
    fn lookup(multiples: &[Self; 15], index: u8) -> Self {
        let mut out = Self::IDENTITY;
        for (i, entry) in multiples.iter().enumerate() {
            let mask = ct::mask(ct::eq(i as u64 + 1, u64::from(index)));
            out = Self::select(mask, entry, &out);
        }
        out
    }

    /// `scalar * self`, for a big-endian `scalar`.
    ///
    /// The scalar is taken four bits at a time, from the top: four doublings,
    /// then one addition of the multiple of the point that the four bits name,
    /// looked up in a table of the multiples 0 to 15.
    pub(super) fn mul(&self, scalar: &[u8]) -> Self {
        // `table[k]` is `(k + 1)` times the point.
        let mut table = [*self; 15];
        for k in 1..15 {
            table[k] = if k % 2 == 1 {
                table[k / 2].double()
            } else {
                table[k - 1].add(self)
            };
        }

        let mut acc = Self::IDENTITY;
        for (i, &byte) in scalar.iter().enumerate() {
            for (j, nibble) in [byte >> 4, byte & 0xf].into_iter().enumerate() {
                // Doubling the point at infinity changes nothing, so the very
                // first window skips it. Where in the scalar we are is public.
                if i != 0 || j != 0 {
                    for _ in 0..4 {
                        acc = acc.double();
                    }
                }
                acc = acc.add(&Self::lookup(&table, nibble));
            }
        }
        acc
    }
}

/// The multiples of the generator that `Point::mul_base` adds up.
///
/// `windows[i][j - 1]` is `j * 16^i * G` for `j` from 1 to 15: for each of the
/// four-bit windows of a scalar, the 15 points it can name. Having those
/// already multiplied by the right power of 16 removes the doublings, so the
/// product with the generator is just one addition per window.
///
/// The table holds public data only.
pub(super) struct BaseTable<C: Weierstrass<N>, const N: usize> {
    windows: Vec<[Point<C, N>; 15]>,
}

impl<C: Weierstrass<N>, const N: usize> BaseTable<C, N> {
    /// Builds the table for scalars of `scalar_len` bytes.
    pub(super) fn new(scalar_len: usize) -> Self {
        let mut windows = Vec::with_capacity(2 * scalar_len);
        let mut base = Point::<C, N>::GENERATOR;
        for _ in 0..2 * scalar_len {
            let mut multiples = [base; 15];
            for j in 1..15 {
                multiples[j] = multiples[j - 1].add(&base);
            }
            windows.push(multiples);
            for _ in 0..4 {
                base = base.double();
            }
        }
        Self { windows }
    }

    /// `scalar * G`, for a big-endian `scalar` of the length the table was
    /// built for.
    pub(super) fn mul(&self, scalar: &[u8]) -> Point<C, N> {
        assert_eq!(2 * scalar.len(), self.windows.len());
        let mut acc = Point::<C, N>::IDENTITY;
        // Window `2k` holds the low nibble of the `k`-th byte from the end,
        // and window `2k + 1` the high one.
        for (k, &byte) in scalar.iter().rev().enumerate() {
            for (window, nibble) in [(2 * k, byte & 0xf), (2 * k + 1, byte >> 4)] {
                acc = acc.add(&Point::lookup(&self.windows[window], nibble));
            }
        }
        acc
    }
}
