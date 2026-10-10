//! X25519, the Diffie-Hellman function of RFC 7748 on Curve25519.
//!
//! Curve25519 is the Montgomery curve `v^2 = u^3 + 486662 u^2 + u` over the
//! integers modulo `2^255 - 19`. X25519 works on the `u` coordinate alone:
//! the Montgomery ladder takes a point's `u` and a scalar and returns the `u`
//! of the multiple, and never needs `v`. Every 32 bytes are a valid public key
//! and, once clamped, a valid private key, so there is nothing to validate; the
//! one thing that can go wrong is a peer's `u` that has small order, whose
//! multiple is the point at infinity and comes out as zero.
//!
//! The ladder does the same work for every scalar. In each of its 255 steps
//! both of the two points it carries are added and doubled, and which one is
//! which is decided by swapping them under a mask, not by a branch.

use super::curve::{Curve, Error, sealed::Sealed};
use super::fe25519::Fe;
use crate::ec::ct;
use crate::wipe::wipe;

/// The curve Curve25519 with the function X25519 of RFC 7748: private keys,
/// public keys and shared secrets of 32 bytes each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519;

/// `(A - 2) / 4` for the curve constant `A = 486662`, as RFC 7748 (section 5)
/// calls it.
const A24: u64 = 121_665;

/// The `u` coordinate of the base point, 9, as 32 little-endian bytes.
const BASE_POINT: [u8; 32] = {
    let mut u = [0; 32];
    u[0] = 9;
    u
};

/// `a` and `b` swapped where `mask` is all ones, and unchanged where it is all
/// zeros.
#[inline(always)]
fn conditional_swap(mask: u64, a: &mut Fe, b: &mut Fe) {
    let (new_a, new_b) = (Fe::select(mask, b, a), Fe::select(mask, a, b));
    *a = new_a;
    *b = new_b;
}

/// RFC 7748, section 5: `X25519(k, u)`, for 32-byte `k` and `u`.
fn scalar_mult(k: &[u8], u: &[u8]) -> [u8; 32] {
    // Clamp the scalar: a multiple of 8 (the cofactor) below 2^255 with bit 254
    // set, so the ladder always runs the same 255 steps.
    let mut k: [u8; 32] = k.try_into().expect("a private key is 32 bytes");
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    // The top bit of `u` is ignored, and a value not below the prime (there are
    // 19 of them under 2^255) is the same number as that value minus the prime.
    let u: &[u8; 32] = u.try_into().expect("a public key is 32 bytes");
    let x1 = Fe::from_bytes(u);

    // (x2 : z2) is the running point and (x3 : z3) is that point plus the input.
    let (mut x2, mut z2) = (Fe::ONE, Fe::ZERO);
    let (mut x3, mut z3) = (x1, Fe::ONE);

    let mut swap = 0;
    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
        // Swapping when the bit differs from the last one's, instead of at
        // every step and back, halves the swaps.
        swap ^= bit;
        let mask = ct::mask(swap);
        conditional_swap(mask, &mut x2, &mut x3);
        conditional_swap(mask, &mut z2, &mut z3);
        swap = bit;

        // One step of the ladder: a differential addition and a doubling.
        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = e * (aa + e.mul_small(A24));
    }
    let mask = ct::mask(swap);
    conditional_swap(mask, &mut x2, &mut x3);
    conditional_swap(mask, &mut z2, &mut z3);

    // Back to the affine `u = x2 / z2`. A point at infinity has `z2 = 0`, and
    // zero has no inverse; the inversion returns zero for it, which is the
    // value RFC 7748 specifies.
    let result = (x2 * z2.invert()).to_bytes();
    // The clamped copy of the private key is ours to overwrite.
    wipe(&mut k);
    result
}

impl Curve for X25519 {
    const NAME: &'static str = "X25519";
    const PRIVATE_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SHARED_SECRET_LEN: usize = 32;
}

impl Sealed for X25519 {
    const FIRST_BYTE_MASK: u8 = 0xff;

    fn check_private(bytes: &[u8]) -> bool {
        bytes.len() == 32
    }

    fn public_key(private: &[u8], out: &mut [u8]) {
        out.copy_from_slice(&scalar_mult(private, &BASE_POINT));
    }

    fn check_public(bytes: &[u8]) -> bool {
        bytes.len() == 32
    }

    fn diffie_hellman(private: &[u8], public: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut result = scalar_mult(private, public);
        out.copy_from_slice(&result);
        wipe(&mut result);
        // RFC 7748, section 6.1: a peer that sends a point of small order makes
        // the secret all zeros, whatever our key, and the check says so.
        if ct::bytes_are_zero(out) {
            return Err(Error::LowOrderPoint);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::vectors::{
        X25519_ITERATED_1, X25519_ITERATED_1000, X25519_KAT, X25519_RFC_5_2, unhex,
    };
    use super::*;

    #[test]
    fn rfc_7748_function_vectors() {
        for [k, u, want] in X25519_RFC_5_2 {
            assert_eq!(scalar_mult(&unhex(k), &unhex(u)).to_vec(), unhex(want));
        }
    }

    #[test]
    fn rfc_7748_diffie_hellman() {
        let kat = X25519_KAT;
        let mut public = [0; 32];
        X25519::public_key(&unhex(kat.private), &mut public);
        assert_eq!(public.to_vec(), unhex(kat.public));

        let mut secret = [0; 32];
        X25519::diffie_hellman(&unhex(kat.private), &unhex(kat.peer), &mut secret).unwrap();
        assert_eq!(secret.to_vec(), unhex(kat.secret));
    }

    /// RFC 7748, section 5.2: feed each result back in as the scalar, with the
    /// previous scalar as the point. A mistake in any one of the 255 ladder
    /// steps changes everything after it.
    #[test]
    fn rfc_7748_iterated() {
        let (mut k, mut u) = (BASE_POINT, BASE_POINT);
        for i in 1..=1000 {
            (k, u) = (scalar_mult(&k, &u), k);
            if i == 1 {
                assert_eq!(k.to_vec(), unhex(X25519_ITERATED_1));
            }
        }
        assert_eq!(k.to_vec(), unhex(X25519_ITERATED_1000));
    }

    /// The same ladder on the generic Montgomery field, which shares no
    /// arithmetic with the real one.
    mod generic {
        use crate::ec::ct;
        use crate::ec::field::{Fe, Modulus};

        struct Prime;
        impl Modulus<4> for Prime {
            const P: [u64; 4] = [
                0xffff_ffff_ffff_ffed,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0x7fff_ffff_ffff_ffff,
            ];
        }
        type F = Fe<Prime, 4>;

        pub(super) fn scalar_mult(k: &[u8], u: &[u8]) -> [u8; 32] {
            let mut k: [u8; 32] = k.try_into().unwrap();
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            let mut limbs = [0u64; 4];
            for (limb, bytes) in limbs.iter_mut().zip(u.chunks_exact(8)) {
                *limb = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            limbs[3] &= 0x7fff_ffff_ffff_ffff;
            let x1 = F::from_limbs_below_double(limbs);
            let a24 = F::from_limbs([121_665, 0, 0, 0]);

            let (mut x2, mut z2) = (F::ONE, F::ZERO);
            let (mut x3, mut z3) = (x1, F::ONE);
            let swap = |mask: u64, a: &mut F, b: &mut F| {
                let (new_a, new_b) = (F::select(mask, b, a), F::select(mask, a, b));
                *a = new_a;
                *b = new_b;
            };
            let mut previous = 0;
            for t in (0..255).rev() {
                let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
                let mask = ct::mask(previous ^ bit);
                swap(mask, &mut x2, &mut x3);
                swap(mask, &mut z2, &mut z3);
                previous = bit;

                let a = x2 + z2;
                let aa = a.square();
                let b = x2 - z2;
                let bb = b.square();
                let e = aa - bb;
                let c = x3 + z3;
                let d = x3 - z3;
                let da = d * a;
                let cb = c * b;
                x3 = (da + cb).square();
                z3 = x1 * (da - cb).square();
                x2 = aa * bb;
                z2 = e * (aa + a24 * e);
            }
            let mask = ct::mask(previous);
            swap(mask, &mut x2, &mut x3);
            swap(mask, &mut z2, &mut z3);

            let mut out = [0; 32];
            (x2 * z2.invert()).write_be_bytes(&mut out);
            out.reverse();
            out
        }
    }

    /// The ladder on the radix-2^51 field and on the Montgomery field agree, for
    /// scalars and points of every shape.
    #[test]
    fn matches_the_generic_field() {
        use crate::{Digest, sha2::Sha512};

        let mut cases: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for i in 0u32..40 {
            let digest = Sha512::digest(&i.to_le_bytes());
            cases.push((
                digest[..32].try_into().unwrap(),
                digest[32..].try_into().unwrap(),
            ));
        }
        let mut p = [0xff; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        for u in [[0; 32], BASE_POINT, p, [0xff; 32]] {
            for k in [[0; 32], [0xff; 32], [0x55; 32], [9; 32]] {
                cases.push((k, u));
            }
        }
        for (k, u) in cases {
            assert_eq!(
                scalar_mult(&k, &u),
                generic::scalar_mult(&k, &u),
                "k = {k:02x?}, u = {u:02x?}"
            );
        }
    }
}
