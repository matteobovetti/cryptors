//! Sampling polynomials from SHAKE (FIPS 203, section 4.2.2): `SampleNTT` for
//! the public matrix `A` and `SamplePolyCBD` for the small secret and noise
//! polynomials.
//!
//! `sample_ntt` is a rejection sampler: how many bytes it reads depends on the
//! bytes. It only ever takes the public seed `rho`, so that tells nothing.
//! `sample_cbd` reads a fixed number of bytes, and turns each group of bits into
//! a coefficient with additions and shifts only: its seed is secret.

use super::field::{N, Poly, Q};
use crate::sha3::{Shake128, shake256};
use crate::wipe::wipe_bytes;

/// The longest output of `PRF`: `64 * eta` bytes for `eta` up to 3.
const MAX_PRF_LEN: usize = 192;

/// `SampleNTT(rho || j || i)` (algorithm 7): the entry `A[i][j]` of the
/// matrix, 256 numbers from 0 to `q - 1`, uniform.
///
/// SHAKE128 is read three bytes at a time, and each group makes two candidates
/// of 12 bits. A candidate of `q` or more is dropped, which happens one time in
/// five.
pub(super) fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.absorb(rho);
    xof.absorb(&[j, i]);

    let mut a = [0; N];
    let mut filled = 0;
    // A block of SHAKE128 holds 56 groups; 256 numbers take about 3 blocks.
    let mut block = [0u8; 168];
    while filled < N {
        xof.read(&mut block);
        for group in block.chunks_exact(3) {
            let d1 = u16::from(group[0]) | u16::from(group[1] & 0x0f) << 8;
            let d2 = u16::from(group[1] >> 4) | u16::from(group[2]) << 4;
            for candidate in [d1, d2] {
                if filled < N && i32::from(candidate) < Q {
                    a[filled] = candidate as i16;
                    filled += 1;
                }
            }
        }
    }
    a
}

/// `PRF_eta(seed, counter)` (equation 4.3) followed by `SamplePolyCBD_eta`
/// (algorithm 8): a polynomial whose coefficients are each the difference of
/// two sums of `eta` bits, so between `-eta` and `eta`. `eta` is 2 or 3.
#[inline(always)]
pub(super) fn sample_cbd(seed: &[u8; 32], counter: u8, eta: usize) -> Poly {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = counter;

    let mut bytes = [0u8; MAX_PRF_LEN];
    shake256(&input, &mut bytes[..64 * eta]);
    let f = cbd(&bytes[..64 * eta], eta);

    // The bytes are the secret polynomial, and the input holds its seed.
    wipe_bytes(&mut bytes);
    wipe_bytes(&mut input);
    f
}

/// `SamplePolyCBD_eta` of `64 * eta` bytes (algorithm 8).
///
/// A coefficient is made of `2 * eta` bits `b`: `x - y` for `x` the sum of the
/// first `eta` and `y` the sum of the last `eta`. All of them are summed at
/// once: the bits at every `eta`-th place are added into a field of the same
/// width in the same word, which the sum of `eta` bits cannot overflow.
#[inline(always)]
fn cbd(bytes: &[u8], eta: usize) -> Poly {
    debug_assert_eq!(bytes.len(), 64 * eta);
    let mut f = [0; N];
    match eta {
        // Four bytes, eight coefficients of four bits each.
        2 => {
            for (bytes, f) in bytes.chunks_exact(4).zip(f.chunks_exact_mut(8)) {
                let t = u32::from_le_bytes(bytes.try_into().unwrap());
                let sums = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
                for (j, c) in f.iter_mut().enumerate() {
                    let x = (sums >> (4 * j)) & 3;
                    let y = (sums >> (4 * j + 2)) & 3;
                    *c = x as i16 - y as i16;
                }
            }
        }
        // Three bytes, four coefficients of six bits each.
        3 => {
            for (bytes, f) in bytes.chunks_exact(3).zip(f.chunks_exact_mut(4)) {
                let t = u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16;
                let sums = (t & 0x24_9249) + ((t >> 1) & 0x24_9249) + ((t >> 2) & 0x24_9249);
                for (j, c) in f.iter_mut().enumerate() {
                    let x = (sums >> (6 * j)) & 7;
                    let y = (sums >> (6 * j + 3)) & 7;
                    *c = x as i16 - y as i16;
                }
            }
        }
        _ => unreachable!("eta is 2 or 3"),
    }
    f
}

#[cfg(test)]
mod tests {
    use super::super::testutil::Prng;
    use super::*;
    use crate::sha3::shake128;

    /// `SampleNTT` as algorithm 7 writes it, from the first 4,000 bytes of the
    /// one-shot SHAKE128 (the longest the "unlucky" vectors of C2SP need is
    /// under 2,000).
    fn spec_sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
        let mut input = rho.to_vec();
        input.extend([j, i]);
        let mut stream = [0u8; 4000];
        shake128(&input, &mut stream);

        let mut a = [0; N];
        let (mut count, mut at) = (0, 0);
        while count < N {
            let c = &stream[at..at + 3];
            at += 3;
            let d1 = i32::from(c[0]) + 256 * (i32::from(c[1]) % 16);
            let d2 = i32::from(c[1]) / 16 + 16 * i32::from(c[2]);
            if d1 < Q {
                a[count] = d1 as i16;
                count += 1;
            }
            if d2 < Q && count < N {
                a[count] = d2 as i16;
                count += 1;
            }
        }
        a
    }

    /// `SamplePolyCBD` as algorithm 8 writes it: the bit string of the bytes
    /// (`BytesToBits`), and for each coefficient a sum of `eta` bits less a
    /// sum of the next `eta`.
    fn spec_cbd(bytes: &[u8], eta: usize) -> Poly {
        let bit = |k: usize| i16::from((bytes[k / 8] >> (k % 8)) & 1);
        core::array::from_fn(|i| {
            let x: i16 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
            let y: i16 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
            x - y
        })
    }

    #[test]
    fn sample_ntt_matches_the_specification() {
        let mut prng = Prng(31337);
        for _ in 0..40 {
            let rho: [u8; 32] = prng.bytes(32).try_into().unwrap();
            let (j, i) = (prng.below(4) as u8, prng.below(4) as u8);
            let a = sample_ntt(&rho, j, i);
            assert_eq!(a, spec_sample_ntt(&rho, j, i));
            assert!(a.iter().all(|&c| (0..Q).contains(&i32::from(c))));
        }
        // Seeds that no other test has: the all-zero and all-ones ones.
        for rho in [[0u8; 32], [0xff; 32]] {
            assert_eq!(sample_ntt(&rho, 1, 2), spec_sample_ntt(&rho, 1, 2));
        }
    }

    #[test]
    fn cbd_matches_the_specification() {
        let mut prng = Prng(2718);
        for eta in [2, 3] {
            for round in 0..200 {
                let bytes = match round {
                    0 => vec![0u8; 64 * eta],
                    1 => vec![0xff; 64 * eta],
                    2 => vec![0x55; 64 * eta],
                    3 => vec![0xaa; 64 * eta],
                    _ => prng.bytes(64 * eta),
                };
                let f = cbd(&bytes, eta);
                assert_eq!(f, spec_cbd(&bytes, eta), "eta {eta}");
                assert!(f.iter().all(|c| c.unsigned_abs() as usize <= eta));
            }
        }
    }

    /// The seed and the counter are hashed as `seed || counter`: the PRF of
    /// equation 4.3 on SHAKE256.
    #[test]
    fn sample_cbd_hashes_the_seed_and_the_counter() {
        let seed = [9u8; 32];
        for eta in [2, 3] {
            let mut input = seed.to_vec();
            input.push(5);
            let mut bytes = vec![0u8; 64 * eta];
            shake256(&input, &mut bytes);
            assert_eq!(sample_cbd(&seed, 5, eta), spec_cbd(&bytes, eta));
            assert_ne!(sample_cbd(&seed, 5, eta), sample_cbd(&seed, 6, eta));
        }
    }
}
