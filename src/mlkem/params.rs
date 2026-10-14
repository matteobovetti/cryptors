//! The three parameter sets of FIPS 203 (Table 2), as types.

/// A parameter set of ML-KEM: [`MlKem512`], [`MlKem768`] or [`MlKem1024`].
///
/// The keys, the ciphertext and the shared secret are generic over it, so a
/// key of one set cannot be used with a ciphertext of another: the compiler
/// refuses it, where a library that picks the set at run time can only return
/// an error.
///
/// The trait cannot be implemented outside this crate. What it exposes are the
/// names and the sizes of the encodings; the numbers behind them are private.
pub trait Parameters: sealed::Sealed {
    /// The name in FIPS 203: `"ML-KEM-768"`.
    const NAME: &'static str;

    /// Size in bytes of an encoded encapsulation key: `384 * k + 32`.
    const ENCAPSULATION_KEY_LEN: usize;

    /// Size in bytes of a ciphertext: `32 * (du * k + dv)`.
    const CIPHERTEXT_LEN: usize;
}

/// Size in bytes of a decapsulation key: the 64-byte seed `d || z` of FIPS 203's
/// `ML-KEM.KeyGen`, for all three sets.
pub const SEED_LEN: usize = 64;

/// Size in bytes of the shared secret `K` that encapsulation and decapsulation
/// agree on, for all three sets.
pub const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-512: security category 1, comparable to a key search on AES-128.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKem512;

/// ML-KEM-768: security category 3, comparable to a key search on AES-192.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKem768;

/// ML-KEM-1024: security category 5, comparable to a key search on AES-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKem1024;

pub(super) mod sealed {
    /// The numbers of Table 2 of FIPS 203 and what follows from them.
    pub trait Sealed: Sized + 'static {
        /// `k`: the number of polynomials in a vector, and the side of the
        /// matrix `A`.
        const K: usize;
        /// `eta1`: the coefficients of the secret `s`, of `e` in key generation
        /// and of `y` in encryption are in `[-eta1, eta1]`.
        const ETA1: usize;
        /// `eta2`: the coefficients of `e1` and `e2` in encryption are in
        /// `[-eta2, eta2]`.
        const ETA2: usize;
        /// `du`: bits of each coefficient of the compressed vector `u`.
        const DU: usize;
        /// `dv`: bits of each coefficient of the compressed polynomial `v`.
        const DV: usize;

        /// Bytes of a vector of polynomials, each coefficient in 12 bits.
        const VECTOR_LEN: usize = 384 * Self::K;
        /// Bytes of the compressed `u` of a ciphertext.
        const U_LEN: usize = 32 * Self::DU * Self::K;
        /// Bytes of the compressed `v` of a ciphertext.
        const V_LEN: usize = 32 * Self::DV;
    }
}

macro_rules! parameter_set {
    (
        $ty:ident, $name:literal,
        k: $k:literal, eta1: $eta1:literal, eta2: $eta2:literal, du: $du:literal, dv: $dv:literal
    ) => {
        impl sealed::Sealed for $ty {
            const K: usize = $k;
            const ETA1: usize = $eta1;
            const ETA2: usize = $eta2;
            const DU: usize = $du;
            const DV: usize = $dv;
        }

        impl Parameters for $ty {
            const NAME: &'static str = $name;
            const ENCAPSULATION_KEY_LEN: usize = 384 * $k + 32;
            const CIPHERTEXT_LEN: usize = 32 * ($du * $k + $dv);
        }
    };
}

parameter_set!(MlKem512, "ML-KEM-512", k: 2, eta1: 3, eta2: 2, du: 10, dv: 4);
parameter_set!(MlKem768, "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4);
parameter_set!(MlKem1024, "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5);

/// The largest `k` of the three sets: the size of the arrays that hold a vector
/// of polynomials.
pub(super) const MAX_K: usize = 4;

/// The longest ciphertext, which is ML-KEM-1024's: the size of the buffer that
/// decapsulation encrypts again into.
pub(super) const MAX_CIPHERTEXT_LEN: usize = 1568;

#[cfg(test)]
mod tests {
    use super::*;

    /// Table 3 of FIPS 203, and the sizes that every other implementation
    /// agrees on. The expanded decapsulation key (`768 * k + 96` bytes) is not
    /// a type of this crate, so its sizes are not here.
    #[test]
    fn sizes_are_those_of_fips_203() {
        assert_eq!(MlKem512::ENCAPSULATION_KEY_LEN, 800);
        assert_eq!(MlKem768::ENCAPSULATION_KEY_LEN, 1184);
        assert_eq!(MlKem1024::ENCAPSULATION_KEY_LEN, 1568);
        assert_eq!(MlKem512::CIPHERTEXT_LEN, 768);
        assert_eq!(MlKem768::CIPHERTEXT_LEN, 1088);
        assert_eq!(MlKem1024::CIPHERTEXT_LEN, 1568);
        assert_eq!(SEED_LEN, 64);
        assert_eq!(SHARED_SECRET_LEN, 32);
    }
}
