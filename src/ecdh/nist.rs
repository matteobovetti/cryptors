//! The three NIST curves as ECDH uses them: the implementation of the private
//! half of `Curve` on byte strings, over the curve arithmetic of `crate::ec`.

use super::curve::{Curve, Error, sealed::Sealed};
use crate::ec::field::Fe;
use crate::ec::nist::{decode_point, encode_point, is_valid_scalar};
use crate::ec::weierstrass::Weierstrass;
use crate::ec::{P256, P384, P521};

/// Implements `Curve` and the private operations for a NIST curve.
macro_rules! nist_curve {
    ($curve:ident, $limbs:literal, $name:literal, $first_byte_mask:literal) => {
        impl Curve for $curve {
            const NAME: &'static str = $name;
            const PRIVATE_KEY_LEN: usize = <$curve as Weierstrass<$limbs>>::ORDER.len();
            const PUBLIC_KEY_LEN: usize = 1 + 2 * Fe::<$curve, $limbs>::BYTES;
            const SHARED_SECRET_LEN: usize = Fe::<$curve, $limbs>::BYTES;
        }

        impl Sealed for $curve {
            const FIRST_BYTE_MASK: u8 = $first_byte_mask;

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

            fn diffie_hellman(private: &[u8], public: &[u8], out: &mut [u8]) -> Result<(), Error> {
                let peer = decode_point::<$curve, $limbs>(public).ok_or(Error::InvalidPublicKey)?;
                // SEC 1, section 3.3.1: the shared point is the product, and
                // the secret is its x-coordinate. For a prime-order curve the
                // product is the point at infinity only for a zero scalar.
                let (x, _) = peer.mul(private).to_affine().ok_or(Error::LowOrderPoint)?;
                x.write_be_bytes(out);
                Ok(())
            }
        }
    };
}

nist_curve!(P256, 4, "P-256", 0xff);
nist_curve!(P384, 6, "P-384", 0xff);
// The order of P-521 has 521 bits, so the top byte of a 66-byte scalar holds
// only one.
nist_curve!(P521, 9, "P-521", 0x01);

#[cfg(test)]
mod tests {
    use super::super::vectors::{Kat, P256_KAT, P384_KAT, P521_KAT, unhex};
    use super::*;

    fn check_kat<C: Curve + Sealed>(kat: &Kat) {
        let (private, public, peer, secret) = (
            unhex(kat.private),
            unhex(kat.public),
            unhex(kat.peer),
            unhex(kat.secret),
        );
        assert_eq!(private.len(), C::PRIVATE_KEY_LEN);
        assert_eq!(public.len(), C::PUBLIC_KEY_LEN);
        assert_eq!(secret.len(), C::SHARED_SECRET_LEN);

        assert!(C::check_private(&private));
        let mut derived = vec![0; C::PUBLIC_KEY_LEN];
        C::public_key(&private, &mut derived);
        assert_eq!(derived, public, "public key");

        assert!(C::check_public(&peer));
        let mut got = vec![0; C::SHARED_SECRET_LEN];
        C::diffie_hellman(&private, &peer, &mut got).unwrap();
        assert_eq!(got, secret, "shared secret");
    }

    #[test]
    fn nist_known_answers() {
        check_kat::<P256>(&P256_KAT);
        check_kat::<P384>(&P384_KAT);
        check_kat::<P521>(&P521_KAT);
    }
}
