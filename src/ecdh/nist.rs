//! The NIST curves P-256, P-384 and P-521 (NIST SP 800-186, sections 3.2.1.3 to
//! 3.2.1.5; SEC 2, sections 2.4.2, 2.5.1 and 2.6.1), as they are used for ECDH.
//!
//! Their parameters are the standards' own numbers. `src/ecdh/nist.rs` states
//! each as limbs, and the tests check the relations that make them a curve:
//! the generator is on it, and the order times the generator is the point at
//! infinity.

use super::ct;
use super::curve::{Curve, Error, sealed::Sealed};
use super::field::{Fe, Modulus};
use super::weierstrass::{BaseTable, Point, Weierstrass};
use std::sync::OnceLock;

/// The NIST curve P-256 (also called secp256r1 and prime256v1), over the
/// prime field of `2^256 - 2^224 + 2^192 + 2^96 - 1`: private keys of 32
/// bytes, public keys of 65 and shared secrets of 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256;

/// The NIST curve P-384 (secp384r1), over the prime field of
/// `2^384 - 2^128 - 2^96 + 2^32 - 1`: private keys of 48 bytes, public keys of
/// 97 and shared secrets of 48.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P384;

/// The NIST curve P-521 (secp521r1), over the prime field of `2^521 - 1`:
/// private keys of 66 bytes, public keys of 133 and shared secrets of 66.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P521;

impl Modulus<4> for P256 {
    const P: [u64; 4] = [
        0xffffffffffffffff,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ];
}

impl Weierstrass<4> for P256 {
    const B: [u64; 4] = [
        0x3bce3c3e27d2604b,
        0x651d06b0cc53b0f6,
        0xb3ebbd55769886bc,
        0x5ac635d8aa3a93e7,
    ];
    const GX: [u64; 4] = [
        0xf4a13945d898c296,
        0x77037d812deb33a0,
        0xf8bce6e563a440f2,
        0x6b17d1f2e12c4247,
    ];
    const GY: [u64; 4] = [
        0xcbb6406837bf51f5,
        0x2bce33576b315ece,
        0x8ee7eb4a7c0f9e16,
        0x4fe342e2fe1a7f9b,
    ];
    const ORDER: &'static [u8] = &[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
}

impl Modulus<6> for P384 {
    const P: [u64; 6] = [
        0x00000000ffffffff,
        0xffffffff00000000,
        0xfffffffffffffffe,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ];
}

impl Weierstrass<6> for P384 {
    const B: [u64; 6] = [
        0x2a85c8edd3ec2aef,
        0xc656398d8a2ed19d,
        0x0314088f5013875a,
        0x181d9c6efe814112,
        0x988e056be3f82d19,
        0xb3312fa7e23ee7e4,
    ];
    const GX: [u64; 6] = [
        0x3a545e3872760ab7,
        0x5502f25dbf55296c,
        0x59f741e082542a38,
        0x6e1d3b628ba79b98,
        0x8eb1c71ef320ad74,
        0xaa87ca22be8b0537,
    ];
    const GY: [u64; 6] = [
        0x7a431d7c90ea0e5f,
        0x0a60b1ce1d7e819d,
        0xe9da3113b5f0b8c0,
        0xf8f41dbd289a147c,
        0x5d9e98bf9292dc29,
        0x3617de4a96262c6f,
    ];
    const ORDER: &'static [u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ];
}

impl Modulus<9> for P521 {
    const P: [u64; 9] = [
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x00000000000001ff,
    ];
}

impl Weierstrass<9> for P521 {
    const B: [u64; 9] = [
        0xef451fd46b503f00,
        0x3573df883d2c34f1,
        0x1652c0bd3bb1bf07,
        0x56193951ec7e937b,
        0xb8b489918ef109e1,
        0xa2da725b99b315f3,
        0x929a21a0b68540ee,
        0x953eb9618e1c9a1f,
        0x0000000000000051,
    ];
    const GX: [u64; 9] = [
        0xf97e7e31c2e5bd66,
        0x3348b3c1856a429b,
        0xfe1dc127a2ffa8de,
        0xa14b5e77efe75928,
        0xf828af606b4d3dba,
        0x9c648139053fb521,
        0x9e3ecb662395b442,
        0x858e06b70404e9cd,
        0x00000000000000c6,
    ];
    const GY: [u64; 9] = [
        0x88be94769fd16650,
        0x353c7086a272c240,
        0xc550b9013fad0761,
        0x97ee72995ef42640,
        0x17afbd17273e662c,
        0x98f54449579b4468,
        0x5c8a5fb42c7d1bd9,
        0x39296a789a3bc004,
        0x0000000000000118,
    ];
    const ORDER: &'static [u8] = &[
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ];
}

/// Whether `bytes` is a private key: `L` bytes holding a number from 1 to the
/// order of the curve minus 1. The time it takes depends on the length alone.
fn is_valid_scalar<C: Weierstrass<N>, const N: usize>(bytes: &[u8]) -> bool {
    // `&`, not `&&`: both checks always run, so that how long this takes does not
    // say whether the scalar was zero.
    bytes.len() == C::ORDER.len() && (!ct::bytes_are_zero(bytes) & ct::bytes_lt(bytes, C::ORDER))
}

/// Writes the uncompressed encoding (SEC 1, section 2.3.3) of `point`, which
/// must not be the point at infinity, to `out`.
fn encode_point<C: Weierstrass<N>, const N: usize>(point: &Point<C, N>, out: &mut [u8]) {
    let (x, y) = point
        .to_affine()
        .expect("a point that is not the point at infinity has affine coordinates");
    let len = Fe::<C, N>::BYTES;
    out[0] = 4;
    x.write_be_bytes(&mut out[1..=len]);
    y.write_be_bytes(&mut out[1 + len..]);
}

/// The point that the uncompressed encoding `bytes` stands for, if it is one.
fn decode_point<C: Weierstrass<N>, const N: usize>(bytes: &[u8]) -> Option<Point<C, N>> {
    let len = Fe::<C, N>::BYTES;
    if bytes.len() != 1 + 2 * len || bytes[0] != 4 {
        return None;
    }
    Point::from_affine_bytes(&bytes[1..=len], &bytes[1 + len..])
}

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
                // Built on first use, then shared: 15 multiples for each of
                // the windows of a scalar.
                static TABLE: OnceLock<BaseTable<$curve, $limbs>> = OnceLock::new();
                let table = TABLE
                    .get_or_init(|| BaseTable::new(<$curve as Weierstrass<$limbs>>::ORDER.len()));
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

    /// The relations that make the numbers of a curve a curve. A wrong digit in
    /// the prime, `b`, the generator or the order breaks at least one of them,
    /// and none of them looks at how the numbers were typed.
    fn check_group<C: Weierstrass<N>, const N: usize>() {
        let g = Point::<C, N>::GENERATOR;
        let order = C::ORDER;

        // The generator satisfies the curve equation: encoding it and decoding
        // the result checks that.
        let mut encoded = vec![0; 1 + 2 * Fe::<C, N>::BYTES];
        encode_point(&g, &mut encoded);
        assert!(
            decode_point::<C, N>(&encoded).is_some(),
            "G is not on the curve"
        );

        // n * G is the point at infinity, and (n - 1) * G is -G.
        assert!(g.mul(order).to_affine().is_none(), "n * G is not infinity");
        let mut n_minus_1 = order.to_vec();
        *n_minus_1.last_mut().unwrap() -= 1;
        assert!(g.mul(&n_minus_1).same_as(&g.neg()), "(n - 1) * G is not -G");

        // The group law, on a handful of multiples.
        let (p2, p3) = (g.double(), g.double().add(&g));
        assert!(p2.same_as(&g.add(&g)), "doubling is not self-addition");
        assert!(g.add(&Point::IDENTITY).same_as(&g), "G + O != G");
        assert!(Point::<C, N>::IDENTITY.add(&g).same_as(&g), "O + G != G");
        assert!(g.add(&g.neg()).same_as(&Point::IDENTITY), "G + (-G) != O");
        assert!(
            p3.add(&p2).same_as(&p2.add(&p3)),
            "addition is not commutative"
        );
        assert!(
            p3.add(&p3).add(&p2).same_as(&p3.add(&p3.add(&p2))),
            "addition is not associative"
        );
        assert!(Point::<C, N>::IDENTITY.double().same_as(&Point::IDENTITY));
        assert!(g.mul(&[3]).same_as(&p3), "3 * G");
        assert!(
            g.mul(&[0, 0, 7]).same_as(&p3.double().add(&g)),
            "7 * G, with leading zeros"
        );
    }

    #[test]
    fn the_curves_are_curves() {
        check_group::<P256, 4>();
        check_group::<P384, 6>();
        check_group::<P521, 9>();
    }

    /// The table of multiples of the generator and the generic multiplication
    /// agree, for scalars that exercise every window.
    fn check_base_mul<C: Weierstrass<N>, const N: usize>() {
        let len = C::ORDER.len();
        let table = BaseTable::<C, N>::new(len);
        let g = Point::<C, N>::GENERATOR;

        let mut scalars = vec![
            vec![0u8; len],
            vec![0xffu8; len],
            vec![0x0fu8; len],
            vec![0xf0u8; len],
        ];
        scalars[0][len - 1] = 1;
        // Distinct nibbles in every position.
        scalars.push((0..len).map(|i| (i * 17 + 3) as u8).collect());
        scalars.push((0..len).rev().map(|i| (i * 29 + 11) as u8).collect());
        for scalar in &scalars {
            assert!(
                table.mul(scalar).same_as(&g.mul(scalar)),
                "table and windows disagree on {scalar:02x?}"
            );
        }
    }

    #[test]
    fn base_table_matches_generic_multiplication() {
        check_base_mul::<P256, 4>();
        check_base_mul::<P384, 6>();
        check_base_mul::<P521, 9>();
    }

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
