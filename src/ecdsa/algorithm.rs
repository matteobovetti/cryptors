//! The signature and verification of FIPS 186-5 (sections 6.4.1 and 6.4.2) on
//! any of the curves of `crate::ec`.
//!
//! Numbers modulo the order `n` of the curve are `Scalar`s, in the same
//! Montgomery form as the field of the curve itself, so the products and the
//! inverse that the algorithm needs are the arithmetic of ECDH with another
//! modulus.

use super::curve::sealed::Nonces;
use crate::ec::nist::{decode_point, is_valid_scalar};
use crate::ec::weierstrass::{Scalar, Weierstrass};
use crate::wipe::wipe;

/// The longest scalar, in bytes: P-521.
const MAX_LEN: usize = 66;

/// How many candidates for the per-message secret number in a row `sign` accepts
/// being refused before it gives up. A generator that works gets a refusal with a
/// probability of 2^-32 at most.
const MAX_REFUSED: usize = 64;

/// Shifts the big-endian number `bytes` right by `shift` bits, from 0 to 7. The
/// bits that fall off the end are lost.
pub(super) fn shift_right(bytes: &mut [u8], shift: u32) {
    debug_assert!(shift < 8);
    if shift == 0 {
        return;
    }
    let mut carry = 0u8;
    for byte in bytes {
        let low = *byte << (8 - shift);
        *byte = (*byte >> shift) | carry;
        carry = low;
    }
}

/// The number of bits that a scalar of `ORDER.len()` bytes has beyond the bit
/// length of the order: 0 for every curve but P-521, which has 7.
fn excess_bits<C: Weierstrass<N>, const N: usize>() -> u32 {
    C::ORDER[0].leading_zeros()
}

/// `e` of FIPS 186-5, section 6.4.1, step 2: the leftmost bits of the digest,
/// as many as the bit length of the order or fewer if the digest is shorter, as
/// a number modulo the order. (RFC 6979 calls that `bits2int`.)
fn digest_to_scalar<C: Weierstrass<N>, const N: usize>(digest: &[u8]) -> Scalar<C, N> {
    let len = C::ORDER.len();
    let scalar = if digest.len() < len {
        // A short digest is just the number it encodes.
        Scalar::<C, N>::from_be_bytes_below_double(digest)
    } else {
        // The first `len` bytes hold the leftmost bits and up to 7 more, which
        // the shift drops.
        let mut head = [0u8; MAX_LEN];
        head[..len].copy_from_slice(&digest[..len]);
        shift_right(&mut head[..len], excess_bits::<C, N>());
        Scalar::from_be_bytes_below_double(&head[..len])
    };
    // A number with at most the bit length of `n` is below `2 * n`.
    scalar.expect("a number of the bit length of the order is below twice the order")
}

/// `bits2octets` of RFC 6979, section 2.3.4.
pub(super) fn digest_to_octets<C: Weierstrass<N>, const N: usize>(digest: &[u8], out: &mut [u8]) {
    digest_to_scalar::<C, N>(digest).write_be_bytes(out);
}

/// One attempt at steps 4 to 9 of FIPS 186-5, section 6.4.1, with the
/// per-message secret `k` (step 3), a valid scalar: `(r, s)`, or `None` where
/// step 11 says to try again with another `k` because `r` or `s` is zero.
fn sign_once<C: Weierstrass<N>, const N: usize>(
    d: &Scalar<C, N>,
    e: &Scalar<C, N>,
    k: &[u8],
) -> Option<(Scalar<C, N>, Scalar<C, N>)> {
    // R = k * G. The table lookups read every entry, so the address of the one
    // used does not depend on `k`.
    let (x, _) = C::base_table()
        .mul(k)
        .to_affine()
        .expect("k is from 1 to n - 1, so k * G is not the point at infinity");
    // r = x mod n. The x-coordinate is below p, and p is below 2n.
    let mut x_bytes = [0u8; MAX_LEN];
    x.write_be_bytes(&mut x_bytes[..k.len()]);
    let r = Scalar::<C, N>::from_be_bytes_below_double(&x_bytes[..k.len()])
        .expect("a coordinate is below the prime, which is below twice the order");

    // s = k^-1 (e + r d) mod n. The inverse follows the bits of the constant
    // n - 2, so its time does not depend on `k`.
    let k = Scalar::<C, N>::from_be_bytes(k).expect("k is below the order");
    let s = k.invert() * (*e + r * *d);

    if (r.is_zero() | s.is_zero()) == 1 {
        None
    } else {
        Some((r, s))
    }
}

/// Signs `digest` with the valid private key `private`, taking the per-message
/// secret from `nonces`, and writes `r || s` to `out`.
pub(super) fn sign<C: Weierstrass<N>, const N: usize>(
    private: &[u8],
    digest: &[u8],
    nonces: &mut dyn Nonces,
    out: &mut [u8],
) {
    let len = C::ORDER.len();
    assert_eq!(out.len(), 2 * len);

    let e = digest_to_scalar::<C, N>(digest);
    let d = Scalar::<C, N>::from_be_bytes(private).expect("a valid private key is below the order");

    let mut buffer = [0u8; MAX_LEN];
    let k = &mut buffer[..len];
    let (r, s) = loop {
        // FIPS 186-5, appendix A.3.2 and A.3.3: a candidate is the leftmost
        // bits of what the generator produced, and it is used if it is from 1
        // to n - 1. Whether a candidate was refused does not depend on the
        // one that is accepted.
        let mut refused = 0;
        while {
            nonces.candidate(k);
            shift_right(k, excess_bits::<C, N>());
            !is_valid_scalar::<C, N>(k)
        } {
            // A generator built on a hash gives a refused candidate with a
            // probability of 2^-32 at most (P-256), so this many in a row means
            // the hash is broken: one whose output does not change, say.
            refused += 1;
            assert!(
                refused < MAX_REFUSED,
                "the generator of the per-message secret number does not produce a number from 1 to n - 1"
            );
        }
        if let Some(pair) = sign_once(&d, &e, k) {
            break pair;
        }
    };
    wipe(&mut buffer);

    r.write_be_bytes(&mut out[..len]);
    s.write_be_bytes(&mut out[len..]);
}

/// Whether the `r || s` in `signature` is a signature of `digest` by the key
/// `public` (FIPS 186-5, section 6.4.2).
pub(super) fn verify<C: Weierstrass<N>, const N: usize>(
    public: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let len = C::ORDER.len();
    if signature.len() != 2 * len {
        return false;
    }
    // The key is on the curve: a point on another, weaker curve is refused
    // here.
    let Some(q) = decode_point::<C, N>(public) else {
        return false;
    };

    // Step 1: r and s are integers from 1 to n - 1.
    let (r, s) = signature.split_at(len);
    let (Some(r), Some(s)) = (
        Scalar::<C, N>::from_be_bytes(r),
        Scalar::<C, N>::from_be_bytes(s),
    ) else {
        return false;
    };
    if (r.is_zero() | s.is_zero()) == 1 {
        return false;
    }

    // Steps 3 to 6: e, then s^-1, u = e s^-1 and v = r s^-1, and the point
    // R1 = u * G + v * Q.
    let e = digest_to_scalar::<C, N>(digest);
    let w = s.invert();
    let mut buffer = [0u8; MAX_LEN];
    (e * w).write_be_bytes(&mut buffer[..len]);
    let from_generator = C::base_table().mul(&buffer[..len]);
    (r * w).write_be_bytes(&mut buffer[..len]);
    let from_key = q.mul(&buffer[..len]);

    // Steps 6 to 9: the signature is good if R1 is not the point at infinity and
    // its x-coordinate, modulo n, is r.
    let Some((x, _)) = from_generator.add(&from_key).to_affine() else {
        return false;
    };
    x.write_be_bytes(&mut buffer[..len]);
    Scalar::<C, N>::from_be_bytes_below_double(&buffer[..len]).is_some_and(|v| v.eq(&r) == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::field::Fe;
    use crate::ec::{P224, P256, P384, P521};

    /// A source of candidates that gives the ones it was given, in order.
    struct Script(Vec<Vec<u8>>);

    impl Nonces for Script {
        fn candidate(&mut self, out: &mut [u8]) {
            out.copy_from_slice(&self.0.remove(0));
        }
    }

    #[test]
    fn shifts_move_bits_across_bytes() {
        let mut bytes = [0b1010_1111, 0b0000_0001, 0b1100_0011];
        shift_right(&mut bytes, 0);
        assert_eq!(bytes, [0b1010_1111, 0b0000_0001, 0b1100_0011]);
        shift_right(&mut bytes, 1);
        assert_eq!(bytes, [0b0101_0111, 0b1000_0000, 0b1110_0001]);
        shift_right(&mut bytes, 7);
        // 0x57 80 e1 >> 7 = 0x00 AF 01 (the low seven bits fall off).
        assert_eq!(bytes, [0b0000_0000, 0b1010_1111, 0b0000_0001]);

        // The 7 bits of P-521: a 66-byte digest keeps its leftmost 521 bits.
        let mut digest = [0xffu8; 66];
        shift_right(&mut digest, 7);
        assert_eq!(digest[0], 0x01);
        assert!(digest[1..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn order_and_field_have_the_same_length() {
        // `sign_once` writes a coordinate into a buffer as long as a scalar.
        fn check<C: Weierstrass<N>, const N: usize>() {
            assert_eq!(Fe::<C, N>::BYTES, C::ORDER.len());
            assert_eq!(Scalar::<C, N>::BYTES, C::ORDER.len());
        }
        check::<P224, 4>();
        check::<P256, 4>();
        check::<P384, 6>();
        check::<P521, 9>();
        assert_eq!(excess_bits::<P224, 4>(), 0);
        assert_eq!(excess_bits::<P256, 4>(), 0);
        assert_eq!(excess_bits::<P384, 6>(), 0);
        assert_eq!(excess_bits::<P521, 9>(), 7);
    }

    /// A string of `len` bytes that is a number above `n` but short enough for
    /// the digest rules, and the rules themselves: longer digests are cut to the
    /// leftmost bits, shorter ones are used whole.
    fn check_digest_rules<C: Weierstrass<N>, const N: usize>() {
        let len = C::ORDER.len();
        let octets = |digest: &[u8]| {
            let mut out = vec![0; len];
            digest_to_octets::<C, N>(digest, &mut out);
            out
        };

        // Short: the number itself, left-padded.
        assert_eq!(octets(&[0x12, 0x34])[len - 2..], [0x12, 0x34]);
        assert!(octets(&[0x12, 0x34])[..len - 2].iter().all(|&b| b == 0));

        // A digest of exactly `len` bytes, all ones, is above the order and is
        // reduced; the shift of P-521 first brings it to 521 bits.
        let ones = octets(&vec![0xff; len]);
        let mut expect = vec![0xff; len];
        shift_right(&mut expect, excess_bits::<C, N>());
        // expect < 2n, so one subtraction of n is all that reduces it.
        let reduced: Vec<u8> = {
            let mut diff = expect.clone();
            let mut borrow = 0i16;
            for i in (0..len).rev() {
                let v = i16::from(diff[i]) - i16::from(C::ORDER[i]) - borrow;
                diff[i] = v.rem_euclid(256) as u8;
                borrow = i16::from(v < 0);
            }
            assert_eq!(borrow, 0, "the all-ones string is at least n");
            diff
        };
        assert_eq!(ones, reduced);

        // Anything after the first `len` bytes is ignored.
        let mut longer = vec![0xff; len];
        longer.extend_from_slice(&[0x00; 20]);
        assert_eq!(octets(&longer), ones);
        let mut longer = vec![0xff; len];
        longer.extend_from_slice(&[0xaa; 20]);
        assert_eq!(octets(&longer), ones);
    }

    #[test]
    fn digests_are_cut_and_reduced() {
        check_digest_rules::<P224, 4>();
        check_digest_rules::<P256, 4>();
        check_digest_rules::<P384, 6>();
        check_digest_rules::<P521, 9>();
    }

    /// The branch of FIPS 186-5, section 6.4.1, step 6 that a random `k` does
    /// not reach in a lifetime: `s` is zero when `e = -r d`, and the algorithm
    /// must ask for another `k`.
    fn check_zero_s<C: Weierstrass<N>, const N: usize>() {
        let len = C::ORDER.len();
        let mut d_bytes = vec![0; len];
        d_bytes[len - 1] = 7;
        let mut k = vec![0; len];
        k[len - 1] = 3;

        let d = Scalar::<C, N>::from_be_bytes(&d_bytes).unwrap();
        // Any e gives a signature for this k...
        let e = Scalar::<C, N>::from_be_bytes_below_double(&[0x55; 8]).unwrap();
        let (r, s) = sign_once::<C, N>(&d, &e, &k).expect("a signature");
        assert!(s.is_zero() == 0 && r.is_zero() == 0);

        // ...and e = -r d gives s = 0.
        let minus_rd = Scalar::<C, N>::ZERO - r * d;
        assert!(sign_once::<C, N>(&d, &minus_rd, &k).is_none());
    }

    #[test]
    fn a_zero_s_asks_for_another_nonce() {
        check_zero_s::<P224, 4>();
        check_zero_s::<P256, 4>();
        check_zero_s::<P384, 6>();
        check_zero_s::<P521, 9>();
    }

    /// FIPS 186-5, section 6.4.1, step 11, through `sign` and not only `sign_once`:
    /// a candidate for which `s` comes out zero is thrown away, and the next one
    /// gives the signature. The digest is `-r * d` for the first candidate, which
    /// makes `e + r * d` zero.
    #[test]
    fn sign_draws_again_after_a_zero_s() {
        type C = P256;
        let len = 32;
        let (mut d_bytes, mut bad, mut good) = (vec![0; len], vec![0; len], vec![0; len]);
        (d_bytes[len - 1], bad[len - 1], good[len - 1]) = (7, 3, 4);

        let d = Scalar::<C, 4>::from_be_bytes(&d_bytes).unwrap();
        let some_e = Scalar::<C, 4>::from_be_bytes_below_double(&[0x55; 8]).unwrap();
        let (r, _) = sign_once::<C, 4>(&d, &some_e, &bad).unwrap();
        let mut digest = vec![0; len];
        (Scalar::<C, 4>::ZERO - r * d).write_be_bytes(&mut digest);
        let e = digest_to_scalar::<C, 4>(&digest);
        assert!(sign_once::<C, 4>(&d, &e, &bad).is_none(), "s is zero");
        assert!(sign_once::<C, 4>(&d, &e, &good).is_some());

        let mut script = Script(vec![bad.clone(), good.clone()]);
        let mut got = vec![0; 2 * len];
        sign::<C, 4>(&d_bytes, &digest, &mut script, &mut got);
        assert!(script.0.is_empty(), "both candidates were drawn");

        let mut direct = vec![0; 2 * len];
        sign::<C, 4>(&d_bytes, &digest, &mut Script(vec![good]), &mut direct);
        assert_eq!(got, direct);
    }

    /// The bound on refused candidates in a row is 64: 63 are put up with, and the
    /// 64th gives up. (A working generator refuses one with a probability of 2^-32
    /// at most, so neither is ever reached by one.)
    #[test]
    fn sixty_three_refused_candidates_in_a_row_are_put_up_with() {
        type C = P256;
        let len = 32;
        let mut d_bytes = vec![0; len];
        d_bytes[len - 1] = 7;
        let mut good = vec![0; len];
        good[len - 1] = 3;

        let mut candidates = vec![vec![0; len]; 63];
        candidates.push(good.clone());
        let mut script = Script(candidates);
        let mut got = vec![0; 2 * len];
        sign::<C, 4>(&d_bytes, &[0x42; 32], &mut script, &mut got);
        assert!(script.0.is_empty());

        let mut direct = vec![0; 2 * len];
        sign::<C, 4>(&d_bytes, &[0x42; 32], &mut Script(vec![good]), &mut direct);
        assert_eq!(got, direct);
    }

    #[test]
    #[should_panic(expected = "does not produce a number from 1 to n - 1")]
    fn the_sixty_fourth_refused_candidate_in_a_row_is_too_many() {
        let len = 32;
        let mut good = vec![0; len];
        good[len - 1] = 3;
        let mut candidates = vec![vec![0; len]; 64];
        candidates.push(good);
        let mut out = vec![0; 2 * len];
        sign::<P256, 4>(&[7; 32], &[0x42; 32], &mut Script(candidates), &mut out);
    }

    /// A generator that only ever gives numbers that are not keys, as one built
    /// on a broken hash would, ends in a panic that says so, not in a loop.
    #[test]
    #[should_panic(expected = "does not produce a number from 1 to n - 1")]
    fn a_generator_that_never_works_is_reported() {
        struct Zeros;
        impl Nonces for Zeros {
            fn candidate(&mut self, out: &mut [u8]) {
                out.fill(0);
            }
        }
        let mut out = [0u8; 64];
        sign::<P256, 4>(&[7; 32], &[0x42; 32], &mut Zeros, &mut out);
    }

    /// `sign` skips a candidate that is not a number from 1 to n - 1, and one
    /// for which `s` is zero, and takes the next.
    #[test]
    fn candidates_are_tried_until_one_works() {
        type C = P256;
        let len = 32;
        let mut d_bytes = vec![0; len];
        d_bytes[len - 1] = 7;
        let digest = [0x42u8; 32];

        let mut good = vec![0; len];
        good[len - 1] = 3;
        let mut script = Script(vec![
            vec![0; len],                          // zero
            <C as Weierstrass<4>>::ORDER.to_vec(), // n
            vec![0xff; len],                       // above n
            good.clone(),
        ]);
        let mut with_script = vec![0; 2 * len];
        sign::<C, 4>(&d_bytes, &digest, &mut script, &mut with_script);
        assert!(script.0.is_empty(), "every candidate was drawn");

        let mut direct = vec![0; 2 * len];
        sign::<C, 4>(
            &d_bytes,
            &digest,
            &mut Script(vec![good.clone()]),
            &mut direct,
        );
        assert_eq!(with_script, direct);
    }
}
