//! Expanding seeds into polynomials with SHAKE (FIPS 204, section 7.3,
//! algorithms 29 to 34): the public matrix `A`, the secret vectors `s1` and
//! `s2`, the masking vector `y` and the challenge `c`.
//!
//! The samplers that take a seed which may be secret (`bounded_poly` and
//! `mask_poly`) are rejection samplers: how many bytes they read depends on
//! the bytes. What that tells an attacker is which of the candidates were
//! thrown away, and not the ones that were kept, which is how the designers of
//! the scheme accept it. `sample_in_ball` takes a hash that is published in
//! the signature.

use super::field::{N, Poly, Q};
use super::pack;
use super::params::sealed::Sealed;
use crate::sha3::{Shake128, Shake256};

/// `RejNTTPoly` (algorithm 30), with the seed of `ExpandA` (algorithm 32) for
/// the entry in row `row` and column `column`: a polynomial of the transform
/// domain whose 256 coefficients are uniform in `[0, q)`.
///
/// Three bytes of SHAKE128 make one candidate of 23 bits, and a candidate of
/// `q` or more is dropped, which happens once in a thousand.
pub(super) fn matrix_entry(rho: &[u8; 32], column: u8, row: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.absorb(rho);
    xof.absorb(&[column, row]);

    let mut a = [0; N];
    let mut filled = 0;
    // One block of SHAKE128 holds 56 candidates.
    let mut block = [0u8; 168];
    while filled < N {
        xof.read(&mut block);
        for bytes in block.chunks_exact(3) {
            let candidate =
                i32::from(bytes[0]) | i32::from(bytes[1]) << 8 | i32::from(bytes[2] & 0x7f) << 16;
            if candidate < Q {
                a[filled] = candidate;
                filled += 1;
                if filled == N {
                    break;
                }
            }
        }
    }
    a
}

/// `RejBoundedPoly` (algorithm 31), with the seed of `ExpandS` (algorithm 33):
/// a polynomial whose coefficients are uniform in `[-eta, eta]`, from
/// `SHAKE256(rho_prime || index)` with `index` as two bytes, least significant
/// first.
///
/// Each byte gives two candidates of four bits, and one that is out of range
/// (15 for `eta = 2`, 9 to 15 for `eta = 4`) is dropped.
pub(super) fn bounded_poly<P: Sealed>(rho_prime: &[u8; 64], index: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.absorb(rho_prime);
    xof.absorb(&index.to_le_bytes());

    let mut s = [0; N];
    let mut filled = 0;
    let mut block = [0u8; 136];
    while filled < N {
        xof.read(&mut block);
        for &byte in &block {
            for nibble in [i32::from(byte & 15), i32::from(byte >> 4)] {
                if filled < N
                    && let Some(coefficient) = coefficient_from_half_byte::<P>(nibble)
                {
                    s[filled] = coefficient;
                    filled += 1;
                }
            }
        }
    }
    s
}

/// `CoeffFromHalfByte` (algorithm 15): `eta - nibble mod 5` for `eta = 2` and
/// `nibble` below 15, `eta - nibble` for `eta = 4` and `nibble` below 9, and
/// nothing otherwise.
#[inline(always)]
fn coefficient_from_half_byte<P: Sealed>(nibble: i32) -> Option<i32> {
    if P::ETA == 2 {
        // `nibble mod 5` for `nibble` below 16, without a division: 205 / 1024
        // is a little over a fifth.
        (nibble < 15).then(|| 2 - (nibble - 5 * ((nibble * 205) >> 10)))
    } else {
        debug_assert_eq!(P::ETA, 4);
        (nibble < 9).then(|| 4 - nibble)
    }
}

/// One polynomial of `ExpandMask` (algorithm 34): `SHAKE256(rho_second ||
/// counter)` unpacked into 256 coefficients in `[-gamma1 + 1, gamma1]`.
pub(super) fn mask_poly<P: Sealed>(rho_second: &[u8; 64], counter: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.absorb(rho_second);
    xof.absorb(&counter.to_le_bytes());

    // The longest of the two sizes, 20 bits for 256 coefficients.
    let mut bytes = [0u8; 640];
    xof.read(&mut bytes[..P::Z_LEN]);
    pack::unpack_z::<P>(&bytes[..P::Z_LEN])
}

/// `SampleInBall` (algorithm 29): a polynomial with `tau` coefficients that are
/// `1` or `-1` and the others zero, from the commitment hash `seed`.
///
/// The first eight bytes of `SHAKE256(seed)` give the signs, and the bytes after
/// them the positions, by a Fisher-Yates shuffle that fills the polynomial from
/// the top.
pub(super) fn sample_in_ball<P: Sealed>(seed: &[u8]) -> Poly {
    let mut xof = Shake256::new();
    xof.absorb(seed);

    let mut block = [0u8; 136];
    xof.read(&mut block);
    let mut signs = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut next = 8;

    let mut c = [0; N];
    for i in N - P::TAU..N {
        // A position from 0 to `i`: bytes above it are dropped.
        let j = loop {
            if next == block.len() {
                xof.read(&mut block);
                next = 0;
            }
            let byte = usize::from(block[next]);
            next += 1;
            if byte <= i {
                break byte;
            }
        };
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i32;
        signs >>= 1;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlDsa44, MlDsa65, MlDsa87};
    use super::*;
    use crate::sha3::shake256;

    #[test]
    fn matrix_entry_is_uniform_looking_and_in_range() {
        let rho = [3u8; 32];
        let a = matrix_entry(&rho, 1, 2);
        assert!(a.iter().all(|&c| (0..Q).contains(&c)));
        // The entries for different positions are different polynomials, and
        // the same position gives the same one.
        assert_ne!(a, matrix_entry(&rho, 2, 1));
        assert_eq!(a, matrix_entry(&rho, 1, 2));
        assert_ne!(a, matrix_entry(&[4u8; 32], 1, 2));
    }

    /// The candidates are three bytes with the top bit of the last cleared,
    /// least significant first, and are taken in order: rebuilt from the same
    /// stream with plain code.
    #[test]
    fn matrix_entry_follows_algorithm_30() {
        let rho: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut input = rho.to_vec();
        input.extend([5, 6]);
        let mut stream = vec![0u8; 168 * 8];
        crate::sha3::shake128(&input, &mut stream);

        let mut expected = Vec::new();
        for bytes in stream.chunks_exact(3) {
            let candidate =
                u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2] & 0x7f) << 16;
            if candidate < Q as u32 {
                expected.push(candidate as i32);
            }
            if expected.len() == N {
                break;
            }
        }
        assert_eq!(expected.len(), N);
        assert_eq!(matrix_entry(&rho, 5, 6).to_vec(), expected);
    }

    fn bounded<P: Sealed>() {
        let rho_prime: [u8; 64] = core::array::from_fn(|i| (i * 3) as u8);
        let mut seen = [false; 9];
        for index in 0..32 {
            let s = bounded_poly::<P>(&rho_prime, index);
            for &c in &s {
                assert!((-P::ETA..=P::ETA).contains(&c), "{c}");
                seen[(c + 4) as usize] = true;
            }
        }
        // Every value of the range comes up in 8192 draws.
        for v in -P::ETA..=P::ETA {
            assert!(seen[(v + 4) as usize], "{v} never drawn");
        }

        // The stream is SHAKE256(rho' || index), nibble by nibble, low first.
        let index = 7u16;
        let mut input = rho_prime.to_vec();
        input.extend(index.to_le_bytes());
        let mut stream = vec![0u8; 136 * 4];
        shake256(&input, &mut stream);
        let mut expected = Vec::new();
        'bytes: for &byte in &stream {
            for nibble in [i32::from(byte & 15), i32::from(byte >> 4)] {
                let accepted = if P::ETA == 2 {
                    (nibble < 15).then(|| 2 - nibble % 5)
                } else {
                    (nibble < 9).then(|| 4 - nibble)
                };
                if let Some(c) = accepted {
                    expected.push(c);
                    if expected.len() == N {
                        break 'bytes;
                    }
                }
            }
        }
        assert_eq!(bounded_poly::<P>(&rho_prime, index).to_vec(), expected);
    }

    #[test]
    fn bounded_poly_follows_algorithm_31() {
        bounded::<MlDsa44>();
        bounded::<MlDsa65>();
        bounded::<MlDsa87>();
    }

    /// `205 / 1024` as the division by 5 holds for every nibble.
    #[test]
    fn nibble_mod_5() {
        for nibble in 0..16 {
            assert_eq!(nibble - 5 * ((nibble * 205) >> 10), nibble % 5);
        }
    }

    fn ball<P: Sealed>() {
        for seed_byte in 0..40u8 {
            let seed = vec![seed_byte; P::C_TILDE_LEN];
            let c = sample_in_ball::<P>(&seed);
            let nonzero = c.iter().filter(|&&x| x != 0).count();
            assert_eq!(nonzero, P::TAU);
            assert!(c.iter().all(|&x| (-1..=1).contains(&x)));
        }

        // Algorithm 29, written out for one seed.
        let seed: Vec<u8> = (0..P::C_TILDE_LEN as u8).collect();
        let mut stream = vec![0u8; 8 + 136 * 8];
        shake256(&seed, &mut stream);
        let signs = u64::from_le_bytes(stream[..8].try_into().unwrap());
        let mut c = [0i32; N];
        let mut bytes = stream[8..].iter();
        for i in N - P::TAU..N {
            let j = loop {
                let &b = bytes.next().unwrap();
                if usize::from(b) <= i {
                    break usize::from(b);
                }
            };
            c[i] = c[j];
            let bit = (signs >> (i + P::TAU - N)) & 1;
            c[j] = if bit == 0 { 1 } else { -1 };
        }
        assert_eq!(sample_in_ball::<P>(&seed), c);
    }

    #[test]
    fn sample_in_ball_follows_algorithm_29() {
        ball::<MlDsa44>();
        ball::<MlDsa65>();
        ball::<MlDsa87>();
    }
}
