//! Key generation, signing and verifying as FIPS 204 writes them, on byte
//! strings (section 6, algorithms 6 to 8: `ML-DSA.KeyGen_internal`,
//! `ML-DSA.Sign_internal` and `ML-DSA.Verify_internal`), for any parameter set.
//!
//! These are the functions of the "internal" interface. What the standard calls
//! the message `M'` has been hashed into `mu` by the caller, and the 32 random
//! bytes `rnd` of a hedged signature are given, so every function here is
//! deterministic and the tests can pin it to the known answers.

use super::field::{
    N, Poly, add_assign, caddq_all, exceeds, inv_ntt_to_mont, multiply_accumulate,
    multiply_subtract, ntt, pointwise, reduce, reduce_sums, reduce_to_positive, sub_assign,
};
use super::pack::{pack_hint, pack_t1, pack_w1, pack_z, unpack_hint, unpack_t1, unpack_z};
use super::params::{MAX_K, MAX_L, Parameters};
use super::rounding::{D, decompose, make_hint, power2round, use_hint};
use super::sample::{bounded_poly, mask_poly, matrix_entry, sample_in_ball};
use crate::sha3::Shake256;
use crate::wipe::wipe;
use core::marker::PhantomData;

/// Bytes of a packed polynomial of `t1`.
pub(super) const T1_LEN: usize = 320;

/// What signing works from: the key `K` that makes the masks, the hash `tr` of
/// the public key, and the polynomials, already in the transform domain, that
/// signing multiplies by: the matrix `A` (public), and `s1`, `s2` and `t0`
/// (secret).
///
/// Making them once is most of what a private key costs to build, and every
/// signature uses all of them.
pub(super) struct Expanded<P: Parameters> {
    rho: [u8; 32],
    key: [u8; 32],
    pub(super) tr: [u8; 64],
    /// `A` (`k * l`, row by row), `s1` (`l`), `s2` (`k`) and `t0` (`k`), all in
    /// the transform domain.
    polys: Box<[Poly]>,
    parameters: PhantomData<P>,
}

impl<P: Parameters> Expanded<P> {
    const S1: usize = P::K * P::L;
    const S2: usize = Self::S1 + P::L;
    const T0: usize = Self::S2 + P::K;
    const POLYS: usize = Self::T0 + P::K;

    fn matrix(&self) -> &[Poly] {
        &self.polys[..Self::S1]
    }

    fn s1(&self) -> &[Poly] {
        &self.polys[Self::S1..Self::S2]
    }

    fn s2(&self) -> &[Poly] {
        &self.polys[Self::S2..Self::T0]
    }

    fn t0(&self) -> &[Poly] {
        &self.polys[Self::T0..]
    }

    /// The matrix `A` from `rho`, in a block of polynomials for the secret ones
    /// to follow.
    fn with_matrix(rho: &[u8; 32]) -> Box<[Poly]> {
        let mut polys = vec![[0; N]; Self::POLYS].into_boxed_slice();
        for row in 0..P::K {
            for column in 0..P::L {
                polys[row * P::L + column] = matrix_entry(rho, column as u8, row as u8);
            }
        }
        polys
    }

    /// Overwrites the secrets with zeros. `A` and `tr` are derived from the
    /// public key, and stay.
    pub(super) fn wipe_secrets(&mut self) {
        wipe(&mut self.key);
        wipe(self.polys[Self::S1..].as_flattened_mut());
    }

    /// Whether the secrets are all zero, which they are after
    /// [`wipe_secrets`](Self::wipe_secrets).
    #[cfg(test)]
    pub(super) fn secrets_are_zero(&self) -> bool {
        self.key == [0; 32]
            && self.polys[Self::S1..]
                .as_flattened()
                .iter()
                .all(|&c| c == 0)
    }
}

/// The polynomial that a polynomial of the transform domain stands for, with
/// coefficients in `(-q, q)`.
#[cfg(test)]
fn from_transform_domain(hat: &Poly) -> Poly {
    // The transform of 1 is all ones, and a product with it scales by 2^-32,
    // which the inverse transform undoes.
    let mut one = [0; N];
    one[0] = 1;
    ntt(&mut one);
    let mut plain = pointwise(hat, &one);
    inv_ntt_to_mont(&mut plain);
    plain
}

#[cfg(test)]
impl<P: Parameters> Expanded<P> {
    /// The secrets as the standard's key encoding has them (algorithm 24,
    /// `skEncode`), which tests compare with the known answers.
    pub(super) fn to_expanded_bytes(&self) -> Vec<u8> {
        use super::field::centered;
        use super::pack::{T0_LEN, eta_len, pack_eta, pack_t0};

        let small = |hat: &Poly| {
            let mut p = from_transform_domain(hat);
            for c in &mut p {
                *c = centered(reduce_to_positive(*c));
            }
            p
        };
        let mut out = Vec::new();
        out.extend_from_slice(&self.rho);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.tr);
        for hat in self.s1().iter().chain(self.s2()) {
            let mut bytes = vec![0u8; eta_len::<P>()];
            pack_eta::<P>(&mut bytes, &small(hat));
            out.extend(bytes);
        }
        for hat in self.t0() {
            let mut bytes = vec![0u8; T0_LEN];
            pack_t0(&mut bytes, &small(hat));
            out.extend(bytes);
        }
        out
    }

    /// `skDecode` (algorithm 25), then everything signing needs from the
    /// result. Tests use it to sign with the keys of the known answers, which
    /// are given in this form. `None` if `bytes` is not an encoding.
    pub(super) fn from_expanded_bytes(bytes: &[u8]) -> Option<Self> {
        use super::pack::{T0_LEN, eta_len, unpack_eta, unpack_t0};

        let eta = eta_len::<P>();
        if bytes.len() != 128 + (P::L + P::K) * eta + P::K * T0_LEN {
            return None;
        }
        let rho: [u8; 32] = bytes[..32].try_into().unwrap();
        let key = bytes[32..64].try_into().unwrap();
        let tr = bytes[64..128].try_into().unwrap();
        let mut polys = Self::with_matrix(&rho);
        let mut rest = &bytes[128..];
        for slot in Self::S1..Self::T0 {
            let (now, later) = rest.split_at(eta);
            polys[slot] = unpack_eta::<P>(now)?;
            ntt(&mut polys[slot]);
            rest = later;
        }
        for slot in Self::T0..Self::POLYS {
            let (now, later) = rest.split_at(T0_LEN);
            polys[slot] = unpack_t0(now);
            ntt(&mut polys[slot]);
            rest = later;
        }
        Some(Self {
            rho,
            key,
            tr,
            polys,
            parameters: PhantomData,
        })
    }

    /// The public key that these secrets make: `rho` and the high part of
    /// `t = A * s1 + s2`.
    pub(super) fn public_key_bytes(&self) -> Vec<u8> {
        let mut pk = vec![0u8; P::PUBLIC_KEY_LEN];
        pk[..32].copy_from_slice(&self.rho);
        for row in 0..P::K {
            let mut acc = [0i64; N];
            for column in 0..P::L {
                multiply_accumulate(
                    &mut acc,
                    &self.matrix()[row * P::L + column],
                    &self.s1()[column],
                );
            }
            let mut t = reduce_sums(&acc);
            inv_ntt_to_mont(&mut t);
            add_assign(&mut t, &from_transform_domain(&self.s2()[row]));
            let mut t1 = [0; N];
            for (high, c) in t1.iter_mut().zip(&t) {
                *high = power2round(reduce_to_positive(*c)).0;
            }
            pack_t1(&mut pk[32 + T1_LEN * row..][..T1_LEN], &t1);
        }
        pk
    }
}

impl<P: Parameters> Clone for Expanded<P> {
    fn clone(&self) -> Self {
        Self {
            rho: self.rho,
            key: self.key,
            tr: self.tr,
            polys: self.polys.clone(),
            parameters: PhantomData,
        }
    }
}

/// `ML-DSA.KeyGen_internal` (algorithm 6): the key material and the encoded
/// public key for the seed `xi`.
pub(super) fn key_gen<P: Parameters>(seed: &[u8; 32]) -> (Expanded<P>, Vec<u8>) {
    // (rho, rho', K) = H(xi || k || l, 128)
    let mut xof = Shake256::new();
    xof.absorb(seed);
    xof.absorb(&[P::K as u8, P::L as u8]);
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key = [0u8; 32];
    xof.read(&mut rho);
    xof.read(&mut rho_prime);
    xof.read(&mut key);
    drop(xof);

    let mut polys = Expanded::<P>::with_matrix(&rho);

    // s1, s2 and their transforms.
    let mut s2 = [[0; N]; MAX_K];
    for column in 0..P::L {
        let slot = Expanded::<P>::S1 + column;
        polys[slot] = bounded_poly::<P>(&rho_prime, column as u16);
        ntt(&mut polys[slot]);
    }
    for (row, s) in s2.iter_mut().enumerate().take(P::K) {
        let slot = Expanded::<P>::S2 + row;
        *s = bounded_poly::<P>(&rho_prime, (P::L + row) as u16);
        polys[slot] = *s;
        ntt(&mut polys[slot]);
    }
    wipe(&mut rho_prime);

    // t = NTT^-1(A * NTT(s1)) + s2, then t1 and t0 = Power2Round(t).
    let mut pk = vec![0u8; P::PUBLIC_KEY_LEN];
    pk[..32].copy_from_slice(&rho);
    for row in 0..P::K {
        let mut acc = [0i64; N];
        for column in 0..P::L {
            multiply_accumulate(
                &mut acc,
                &polys[row * P::L + column],
                &polys[Expanded::<P>::S1 + column],
            );
        }
        let mut t = reduce_sums(&acc);
        inv_ntt_to_mont(&mut t);
        add_assign(&mut t, &s2[row]);

        let mut t1 = [0; N];
        let mut t0 = [0; N];
        for ((high, low), c) in t1.iter_mut().zip(&mut t0).zip(&t) {
            (*high, *low) = power2round(reduce_to_positive(*c));
        }
        pack_t1(&mut pk[32 + T1_LEN * row..][..T1_LEN], &t1);
        ntt(&mut t0);
        polys[Expanded::<P>::T0 + row] = t0;
    }
    wipe(s2.as_flattened_mut());

    let tr = public_key_hash(&pk);
    (
        Expanded {
            rho,
            key,
            tr,
            polys,
            parameters: PhantomData,
        },
        pk,
    )
}

/// `tr = H(pk, 64)`.
pub(super) fn public_key_hash(public_key: &[u8]) -> [u8; 64] {
    let mut xof = Shake256::new();
    xof.absorb(public_key);
    let mut tr = [0u8; 64];
    xof.read(&mut tr);
    tr
}

/// `mu = H(tr || M', 64)` (algorithm 7 line 6 and algorithm 8 line 7), where
/// `M'` is the concatenation of `parts`.
pub(super) fn message_representative(tr: &[u8; 64], parts: &[&[u8]]) -> [u8; 64] {
    let mut xof = Shake256::new();
    xof.absorb(tr);
    for part in parts {
        xof.absorb(part);
    }
    let mut mu = [0u8; 64];
    xof.read(&mut mu);
    mu
}

/// Why an attempt of [`sign`] was thrown away: which of the four checks failed.
#[derive(Clone, Copy)]
enum Rejection {
    /// `||z||` reached `gamma1 - beta`.
    Z,
    /// The low part of `w - c * s2` reached `gamma2 - beta`.
    LowBits,
    /// `||c * t0||` reached `gamma2`.
    Ct0,
    /// The hint had more than `omega` ones.
    Hint,
}

#[cfg(test)]
thread_local! {
    /// How many attempts this thread's signatures threw away, by reason, so that
    /// the tests can show that each way to reject is reached.
    pub(super) static REJECTIONS: core::cell::Cell<[usize; 4]> =
        const { core::cell::Cell::new([0; 4]) };
}

/// Ends an attempt: there is no signature from it.
#[inline(always)]
fn reject(reason: Rejection) -> Option<Vec<u8>> {
    #[cfg(test)]
    REJECTIONS.with(|counts| {
        let mut all = counts.get();
        all[reason as usize] += 1;
        counts.set(all);
    });
    #[cfg(not(test))]
    let _ = reason;
    None
}

/// Whether `||z||inf >= gamma1 - beta`, for `z` made by `reduce` (algorithm 7
/// line 23, and algorithm 8 line 13): a response that large would say something
/// about `s1`, and a signature that has one is not valid.
fn z_out_of_range<P: Parameters>(z: &Poly) -> bool {
    exceeds(z, P::GAMMA1 - P::BETA)
}

/// Whether `||r0||inf >= gamma2 - beta` for the low part `r0` of `w - c * s2`
/// (algorithm 7 line 23).
fn low_bits_out_of_range<P: Parameters>(r0: &Poly) -> bool {
    exceeds(r0, P::GAMMA2 - P::BETA)
}

/// Whether `||c * t0||inf >= gamma2` (algorithm 7 line 28).
fn ct0_out_of_range<P: Parameters>(ct0: &Poly) -> bool {
    exceeds(ct0, P::GAMMA2)
}

/// Whether a hint of `ones` ones is too heavy to encode: more than `omega`
/// (algorithm 7 line 28).
fn too_many_hints<P: Parameters>(ones: usize) -> bool {
    ones > P::OMEGA
}

/// The values of a signing attempt that would give away the private key if they
/// were left in memory: the seed of the masks, the masks, and what the checks
/// are made on. Wiped when the signature is done, whichever way it ends.
struct Scratch {
    rho_second: [u8; 64],
    y: [Poly; MAX_L],
    y_hat: [Poly; MAX_L],
    z: [Poly; MAX_L],
    w0: [Poly; MAX_K],
}

impl Drop for Scratch {
    fn drop(&mut self) {
        wipe(&mut self.rho_second);
        wipe(self.y.as_flattened_mut());
        wipe(self.y_hat.as_flattened_mut());
        wipe(self.z.as_flattened_mut());
        wipe(self.w0.as_flattened_mut());
    }
}

/// `ML-DSA.Sign_internal` (algorithm 7), from `mu` and the 32 bytes `rnd`: the
/// encoded signature.
///
/// Each pass of the loop is an attempt (the standard's "rejection sampling"):
/// it draws a masking vector `y`, commits to the high part of `A * y`, takes the
/// challenge `c` from the commitment and answers with `z = y + c * s1`. The
/// attempt is thrown away when the answer, or the part of the commitment that the
/// verifier cannot recover, would give something about `s1`, `s2` or `t0` away
/// (the four checks in [`attempt_sign`]). Which check failed, and at which attempt,
/// is not a secret (the Dilithium specification, section 5.5), and a rejected
/// attempt's values never leave this function.
pub(super) fn sign<P: Parameters>(key: &Expanded<P>, mu: &[u8; 64], rnd: &[u8; 32]) -> Vec<u8> {
    let mut scratch = Scratch {
        rho_second: [0; 64],
        y: [[0; N]; MAX_L],
        y_hat: [[0; N]; MAX_L],
        z: [[0; N]; MAX_L],
        w0: [[0; N]; MAX_K],
    };
    // rho'' = H(K || rnd || mu, 64)
    let mut xof = Shake256::new();
    xof.absorb(&key.key);
    xof.absorb(rnd);
    xof.absorb(mu);
    xof.read(&mut scratch.rho_second);
    drop(xof);

    // The counter that numbers the polynomials of `y` is 16 bits, so there are
    // at most 2^16 / l attempts: 9,362 or more for the three sets. The expected
    // number is 4.25, 5.1 and 3.85 (FIPS 204, table 1), and more than 814 are
    // needed with a probability below 2^-256 (appendix C, table 3), which is the
    // lowest limit that the standard allows.
    for attempt in 0..(1u32 << 16) / P::L as u32 {
        if let Some(signature) = attempt_sign(key, mu, &mut scratch, attempt * P::L as u32) {
            return signature;
        }
    }
    unreachable!("ML-DSA: no signature in 2^16 / l attempts, which has probability below 2^-256")
}

/// One pass of the loop of [`sign`], for the masking polynomials numbered
/// `kappa` and up: the signature, or `None` if a check rejected it.
fn attempt_sign<P: Parameters>(
    key: &Expanded<P>,
    mu: &[u8; 64],
    scratch: &mut Scratch,
    kappa: u32,
) -> Option<Vec<u8>> {
    let matrix = key.matrix();
    let (s1, s2, t0) = (key.s1(), key.s2(), key.t0());
    let Scratch {
        rho_second,
        y,
        y_hat,
        z,
        w0,
    } = scratch;

    // y = ExpandMask(rho'', kappa), and its transform.
    for (j, (poly, hat)) in y.iter_mut().zip(y_hat.iter_mut()).take(P::L).enumerate() {
        *poly = mask_poly::<P>(rho_second, (kappa + j as u32) as u16);
        *hat = *poly;
        ntt(hat);
    }

    // w = NTT^-1(A * NTT(y)), split into its high and low parts, and the
    // commitment c_tilde = H(mu || w1Encode(w1), lambda / 4).
    let mut w1 = [[0; N]; MAX_K];
    let mut xof = Shake256::new();
    xof.absorb(mu);
    for row in 0..P::K {
        let mut acc = [0i64; N];
        for column in 0..P::L {
            multiply_accumulate(&mut acc, &matrix[row * P::L + column], &y_hat[column]);
        }
        let mut w = reduce_sums(&acc);
        inv_ntt_to_mont(&mut w);
        caddq_all(&mut w);
        for ((high, low), c) in w1[row].iter_mut().zip(&mut w0[row]).zip(&w) {
            (*high, *low) = decompose::<P>(*c);
        }
        let mut packed = [0u8; 192];
        pack_w1::<P>(&mut packed[..P::W1_LEN], &w1[row]);
        xof.absorb(&packed[..P::W1_LEN]);
    }
    let mut c_tilde = [0u8; 64];
    xof.read(&mut c_tilde[..P::C_TILDE_LEN]);
    let c_tilde = &c_tilde[..P::C_TILDE_LEN];

    // c = SampleInBall(c_tilde), in the transform domain.
    let mut c = sample_in_ball::<P>(c_tilde);
    ntt(&mut c);

    // z = y + c * s1 must stay clear of the end of the range of y.
    for column in 0..P::L {
        let mut cs1 = pointwise(&c, &s1[column]);
        inv_ntt_to_mont(&mut cs1);
        add_assign(&mut cs1, &y[column]);
        reduce(&mut cs1);
        z[column] = cs1;
        if z_out_of_range::<P>(&cs1) {
            wipe(&mut cs1);
            return reject(Rejection::Z);
        }
    }

    // The low part of w - c * s2 must stay clear of the end of its range, so
    // that the verifier, who can only compute w - c * s2 + c * t0, finds the
    // same high part with the help of the hint.
    for row in 0..P::K {
        let mut cs2 = pointwise(&c, &s2[row]);
        inv_ntt_to_mont(&mut cs2);
        sub_assign(&mut w0[row], &cs2);
        wipe(&mut cs2);
        reduce(&mut w0[row]);
        if low_bits_out_of_range::<P>(&w0[row]) {
            return reject(Rejection::LowBits);
        }
    }

    // c * t0 is small, and the hint says where it moves the high part.
    let mut hint = [[false; N]; MAX_K];
    let mut ones = 0;
    for row in 0..P::K {
        let mut ct0 = pointwise(&c, &t0[row]);
        inv_ntt_to_mont(&mut ct0);
        reduce(&mut ct0);
        let too_big = ct0_out_of_range::<P>(&ct0);
        if !too_big {
            for (((h, low), high), ct) in hint[row].iter_mut().zip(&w0[row]).zip(&w1[row]).zip(&ct0)
            {
                *h = make_hint::<P>(*low + *ct, *high);
                ones += usize::from(*h);
            }
        }
        wipe(&mut ct0);
        if too_big {
            return reject(Rejection::Ct0);
        }
    }
    if too_many_hints::<P>(ones) {
        return reject(Rejection::Hint);
    }

    // sigma = c_tilde || BitPack(z) || HintBitPack(h)
    let mut signature = vec![0u8; P::SIGNATURE_LEN];
    signature[..P::C_TILDE_LEN].copy_from_slice(c_tilde);
    let mut rest = &mut signature[P::C_TILDE_LEN..];
    for poly in &z[..P::L] {
        let (now, later) = rest.split_at_mut(P::Z_LEN);
        pack_z::<P>(now, poly);
        rest = later;
    }
    pack_hint::<P>(rest, &hint);
    Some(signature)
}

/// `ML-DSA.Verify_internal` (algorithm 8): whether `signature` is a signature of
/// `mu` under the encoded public key. Both have the lengths of the parameter
/// set.
///
/// Nothing here is secret: the key, the signature and `mu` are public, and an
/// early return does not matter.
pub(super) fn verify<P: Parameters>(public_key: &[u8], mu: &[u8; 64], signature: &[u8]) -> bool {
    debug_assert_eq!(public_key.len(), P::PUBLIC_KEY_LEN);
    debug_assert_eq!(signature.len(), P::SIGNATURE_LEN);

    // sigDecode (algorithm 27).
    let (c_tilde, rest) = signature.split_at(P::C_TILDE_LEN);
    let (z_bytes, hint_bytes) = rest.split_at(P::L * P::Z_LEN);
    let Some(hint) = unpack_hint::<P>(hint_bytes) else {
        return false;
    };
    let mut z_hat = [[0; N]; MAX_L];
    for (poly, bytes) in z_hat.iter_mut().zip(z_bytes.chunks_exact(P::Z_LEN)) {
        *poly = unpack_z::<P>(bytes);
        // ||z||inf < gamma1 - beta
        if z_out_of_range::<P>(poly) {
            return false;
        }
        ntt(poly);
    }

    let (rho, t1_bytes) = public_key.split_at(32);
    let rho: &[u8; 32] = rho.try_into().unwrap();

    // c, in the transform domain.
    let mut c = sample_in_ball::<P>(c_tilde);
    ntt(&mut c);

    // w'approx = NTT^-1(A * NTT(z) - NTT(c) * NTT(t1 * 2^d)), the high part of
    // which the hint corrects to w1', and the commitment that they make.
    let mut xof = Shake256::new();
    xof.absorb(mu);
    for (row, t1_bytes) in t1_bytes.chunks_exact(T1_LEN).enumerate() {
        let mut acc = [0i64; N];
        for (column, z) in z_hat.iter().take(P::L).enumerate() {
            let entry = matrix_entry(rho, column as u8, row as u8);
            multiply_accumulate(&mut acc, &entry, z);
        }
        let mut t1 = unpack_t1(t1_bytes);
        for coefficient in &mut t1 {
            *coefficient <<= D;
        }
        ntt(&mut t1);
        multiply_subtract(&mut acc, &c, &t1);

        let mut w = reduce_sums(&acc);
        inv_ntt_to_mont(&mut w);
        caddq_all(&mut w);
        for (coefficient, &h) in w.iter_mut().zip(&hint[row]) {
            *coefficient = use_hint::<P>(*coefficient, h);
        }
        let mut packed = [0u8; 192];
        pack_w1::<P>(&mut packed[..P::W1_LEN], &w);
        xof.absorb(&packed[..P::W1_LEN]);
    }
    let mut expected = [0u8; 64];
    xof.read(&mut expected[..P::C_TILDE_LEN]);

    // c_tilde = c_tilde'
    expected[..P::C_TILDE_LEN] == *c_tilde
}

#[cfg(test)]
mod tests {
    use super::super::params::sealed::Sealed;
    use super::super::params::{MlDsa44, MlDsa65, MlDsa87};
    use super::*;

    /// The four checks of the loop, at the value where each flips, in each sign
    /// and in each set: a coefficient one below the bound passes and one at the
    /// bound does not. A signature that is at the edge of a bound is too rare for
    /// a known answer to show the difference, so the bounds are pinned here.
    #[test]
    fn the_bounds_of_the_checks() {
        fn at<P: Parameters>(check: fn(&Poly) -> bool, bound: i32, name: &str) {
            for position in [0, 100, N - 1] {
                for sign in [1, -1] {
                    let mut poly = [0; N];
                    poly[position] = sign * (bound - 1);
                    assert!(
                        !check(&poly),
                        "{} {name}: {} below the bound",
                        P::NAME,
                        sign * (bound - 1)
                    );
                    poly[position] = sign * bound;
                    assert!(
                        check(&poly),
                        "{} {name}: {} at the bound",
                        P::NAME,
                        sign * bound
                    );
                }
            }
            assert!(!check(&[0; N]));
        }

        fn all<P: Parameters>() {
            at::<P>(z_out_of_range::<P>, P::GAMMA1 - P::BETA, "z");
            at::<P>(low_bits_out_of_range::<P>, P::GAMMA2 - P::BETA, "low bits");
            at::<P>(ct0_out_of_range::<P>, P::GAMMA2, "ct0");
            assert!(!too_many_hints::<P>(P::OMEGA));
            assert!(too_many_hints::<P>(P::OMEGA + 1));
            assert!(!too_many_hints::<P>(0));
        }
        all::<MlDsa44>();
        all::<MlDsa65>();
        all::<MlDsa87>();
        // The values that the three sets give: gamma1 - beta, gamma2 - beta, gamma2.
        assert_eq!(MlDsa44::GAMMA1 - MlDsa44::BETA, 131_072 - 78);
        assert_eq!(MlDsa65::GAMMA2 - MlDsa65::BETA, 261_888 - 196);
        assert_eq!(MlDsa87::GAMMA1 - MlDsa87::BETA, 524_288 - 120);
    }
}
