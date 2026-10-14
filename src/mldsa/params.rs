//! The three parameter sets of FIPS 204 (Table 1), as types.

/// A parameter set of ML-DSA: [`MlDsa44`], [`MlDsa65`] or [`MlDsa87`].
///
/// The keys and the signature are generic over it, so a key of one set cannot
/// be used with a signature of another: the compiler refuses it, where a
/// library that picks the set at run time can only return an error.
///
/// The trait cannot be implemented outside this crate. What it exposes are the
/// names and the sizes of the encodings; the numbers behind them are private.
pub trait Parameters: sealed::Sealed {
    /// The name in FIPS 204: `"ML-DSA-65"`.
    const NAME: &'static str;

    /// Size in bytes of an encoded public key: `32 + 320 * k`.
    const PUBLIC_KEY_LEN: usize;

    /// Size in bytes of an encoded signature: `lambda / 4 + 32 * l * (1 +
    /// log2(gamma1)) + omega + k`.
    const SIGNATURE_LEN: usize;
}

/// Size in bytes of a private key: the seed `xi` of FIPS 204's `ML-DSA.KeyGen`,
/// for all three sets.
pub const SEED_LEN: usize = 32;

/// ML-DSA-44: security category 2, comparable to a collision search on SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlDsa44;

/// ML-DSA-65: security category 3, comparable to a key search on AES-192.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlDsa65;

/// ML-DSA-87: security category 5, comparable to a key search on AES-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlDsa87;

pub(super) mod sealed {
    use super::super::field::Q;

    /// The numbers of Table 1 of FIPS 204 and what follows from them.
    pub trait Sealed: Sized + 'static {
        /// Rows of the matrix `A`: the number of polynomials in `t`, `s2`, `w`
        /// and the hint.
        const K: usize;
        /// Columns of `A`: the number of polynomials in `s1`, `y` and `z`.
        const L: usize;
        /// `eta`: the coefficients of `s1` and `s2` are in `[-eta, eta]`.
        const ETA: i32;
        /// `log2(gamma1)`: the coefficients of `y` are in `[-gamma1 + 1,
        /// gamma1]`.
        const GAMMA1_BITS: u32;
        /// `gamma2`, the low-order rounding range: `(q - 1) / 88` or
        /// `(q - 1) / 32`.
        const GAMMA2: i32;
        /// `lambda`, the collision strength in bits: the commitment hash
        /// `c_tilde` is `lambda / 4` bytes.
        const LAMBDA: usize;
        /// `tau`, the number of nonzero coefficients (`+1` or `-1`) of the
        /// challenge polynomial.
        const TAU: usize;
        /// `omega`, the most hint bits that a signature may carry.
        const OMEGA: usize;

        /// `gamma1`.
        const GAMMA1: i32 = 1 << Self::GAMMA1_BITS;
        /// `beta = tau * eta`: the most that `c * s` can change a coefficient.
        const BETA: i32 = Self::TAU as i32 * Self::ETA;
        /// Bytes of the commitment hash `c_tilde`.
        const C_TILDE_LEN: usize = Self::LAMBDA / 4;
        /// Bytes of one packed polynomial of `z`: `gamma1_bits + 1` bits for
        /// each of 256 coefficients.
        const Z_LEN: usize = 32 * (Self::GAMMA1_BITS as usize + 1);
        /// Bytes of one packed polynomial of `w1`: 6 bits for each
        /// coefficient when `gamma2 = (q - 1) / 88`, else 4.
        const W1_LEN: usize = if Self::GAMMA2 == (Q - 1) / 88 {
            192
        } else {
            128
        };
        /// Bytes of the hint: `omega` indices and `k` counts.
        const HINT_LEN: usize = Self::OMEGA + Self::K;
    }
}

macro_rules! parameter_set {
    (
        $ty:ident, $name:literal,
        k: $k:literal, l: $l:literal, eta: $eta:literal, gamma1_bits: $g1:literal,
        gamma2_divisor: $g2:literal, lambda: $lambda:literal, tau: $tau:literal,
        omega: $omega:literal
    ) => {
        impl sealed::Sealed for $ty {
            const K: usize = $k;
            const L: usize = $l;
            const ETA: i32 = $eta;
            const GAMMA1_BITS: u32 = $g1;
            const GAMMA2: i32 = (super::field::Q - 1) / $g2;
            const LAMBDA: usize = $lambda;
            const TAU: usize = $tau;
            const OMEGA: usize = $omega;
        }

        impl Parameters for $ty {
            const NAME: &'static str = $name;
            const PUBLIC_KEY_LEN: usize = 32 + 320 * $k;
            const SIGNATURE_LEN: usize = $lambda / 4 + 32 * $l * ($g1 + 1) + $omega + $k;
        }
    };
}

parameter_set!(MlDsa44, "ML-DSA-44",
    k: 4, l: 4, eta: 2, gamma1_bits: 17, gamma2_divisor: 88, lambda: 128, tau: 39, omega: 80);
parameter_set!(MlDsa65, "ML-DSA-65",
    k: 6, l: 5, eta: 4, gamma1_bits: 19, gamma2_divisor: 32, lambda: 192, tau: 49, omega: 55);
parameter_set!(MlDsa87, "ML-DSA-87",
    k: 8, l: 7, eta: 2, gamma1_bits: 19, gamma2_divisor: 32, lambda: 256, tau: 60, omega: 75);

/// The largest `k` and `l` of the three sets: the size of the arrays that hold
/// a vector of polynomials.
pub(super) const MAX_K: usize = 8;
pub(super) const MAX_L: usize = 7;

#[cfg(test)]
mod tests {
    use super::sealed::Sealed;
    use super::*;

    /// Table 2 of FIPS 204, and the sizes that every other implementation
    /// agrees on.
    #[test]
    fn sizes_are_those_of_fips_204() {
        assert_eq!(MlDsa44::PUBLIC_KEY_LEN, 1312);
        assert_eq!(MlDsa65::PUBLIC_KEY_LEN, 1952);
        assert_eq!(MlDsa87::PUBLIC_KEY_LEN, 2592);
        assert_eq!(MlDsa44::SIGNATURE_LEN, 2420);
        assert_eq!(MlDsa65::SIGNATURE_LEN, 3309);
        assert_eq!(MlDsa87::SIGNATURE_LEN, 4627);
    }

    #[test]
    fn derived_numbers_are_those_of_table_1() {
        assert_eq!(
            (MlDsa44::BETA, MlDsa65::BETA, MlDsa87::BETA),
            (78, 196, 120)
        );
        assert_eq!(MlDsa44::GAMMA1, 1 << 17);
        assert_eq!(MlDsa65::GAMMA1, 1 << 19);
        assert_eq!(MlDsa87::GAMMA1, 1 << 19);
        assert_eq!(MlDsa44::GAMMA2, 95_232);
        assert_eq!(MlDsa65::GAMMA2, 261_888);
        assert_eq!(MlDsa87::GAMMA2, 261_888);
        assert_eq!(
            (
                MlDsa44::C_TILDE_LEN,
                MlDsa65::C_TILDE_LEN,
                MlDsa87::C_TILDE_LEN
            ),
            (32, 48, 64)
        );
        assert_eq!((MlDsa44::W1_LEN, MlDsa65::W1_LEN), (192, 128));
        assert_eq!((MlDsa44::Z_LEN, MlDsa65::Z_LEN), (576, 640));
        // The largest sets are what the arrays are sized for.
        assert_eq!(MAX_K, MlDsa87::K);
        assert_eq!(MAX_L, MlDsa87::L);
        for k in [MlDsa44::K, MlDsa65::K, MlDsa87::K] {
            assert!(k <= MAX_K);
        }
        for l in [MlDsa44::L, MlDsa65::L, MlDsa87::L] {
            assert!(l <= MAX_L);
        }
    }
}
