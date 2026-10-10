//! The four NIST curves as ECDSA uses them: the implementation of the private
//! half of `Curve` on byte strings, over the curve arithmetic of `crate::ec`.

use super::algorithm;
use super::curve::{Curve, sealed::Nonces, sealed::Sealed};
use crate::ec::field::Fe;
use crate::ec::nist::{decode_point, encode_point, is_valid_scalar};
use crate::ec::weierstrass::Weierstrass;
use crate::ec::{P224, P256, P384, P521};

/// Implements `Curve` and the private operations for a NIST curve.
macro_rules! nist_curve {
    ($curve:ident, $limbs:literal, $name:literal) => {
        impl Curve for $curve {
            const NAME: &'static str = $name;
            const PRIVATE_KEY_LEN: usize = <$curve as Weierstrass<$limbs>>::ORDER.len();
            const PUBLIC_KEY_LEN: usize = 1 + 2 * Fe::<$curve, $limbs>::BYTES;
            const SIGNATURE_LEN: usize = 2 * <$curve as Weierstrass<$limbs>>::ORDER.len();
        }

        impl Sealed for $curve {
            // The order's first byte is not zero, so its leading zeros are the
            // bits that the whole bytes have beyond its length.
            const EXCESS_BITS: u32 = <$curve as Weierstrass<$limbs>>::ORDER[0].leading_zeros();

            fn check_private(bytes: &[u8]) -> bool {
                is_valid_scalar::<$curve, $limbs>(bytes)
            }

            fn public_key(private: &[u8], out: &mut [u8]) {
                // The table of multiples of the generator is built on first
                // use and shared with every other user of the curve.
                let table = <$curve as Weierstrass<$limbs>>::base_table();
                encode_point(&table.mul(private), out);
            }

            fn check_public(bytes: &[u8]) -> bool {
                decode_point::<$curve, $limbs>(bytes).is_some()
            }

            fn check_signature(bytes: &[u8]) -> bool {
                let len = <$curve as Weierstrass<$limbs>>::ORDER.len();
                bytes.len() == 2 * len
                    && is_valid_scalar::<$curve, $limbs>(&bytes[..len])
                    && is_valid_scalar::<$curve, $limbs>(&bytes[len..])
            }

            fn digest_to_octets(digest: &[u8], out: &mut [u8]) {
                algorithm::digest_to_octets::<$curve, $limbs>(digest, out);
            }

            fn sign(private: &[u8], digest: &[u8], nonces: &mut dyn Nonces, out: &mut [u8]) {
                algorithm::sign::<$curve, $limbs>(private, digest, nonces, out);
            }

            fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
                algorithm::verify::<$curve, $limbs>(public, digest, signature)
            }
        }
    };
}

nist_curve!(P224, 4, "P-224");
nist_curve!(P256, 4, "P-256");
nist_curve!(P384, 6, "P-384");
nist_curve!(P521, 9, "P-521");
