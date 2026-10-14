//! K-PKE (FIPS 203, section 5) and the internal algorithms of ML-KEM (section
//! 6): key generation, encapsulation and decapsulation on byte strings and for
//! any parameter set.
//!
//! The functions take what the keys hold already expanded: the matrix `A`, the
//! vectors `t` and `s` as polynomials of the transform domain, and the hash of
//! the encapsulation key. The checks of the inputs (their lengths, the modulus
//! check of the encapsulation key) are the keys' business, in `keypair.rs`.
//!
//! Where a name has a hat in the specification, it is a polynomial of `T_q`
//! here too, and has none in the name: `s` is `s^` in the text.

use super::field::{N, Poly, add, dot, inverse_ntt, ntt, reduce, sub};
use super::pack::{byte_decode, byte_encode, compress_and_encode, decode_and_decompress};
use super::params::{MAX_CIPHERTEXT_LEN, MAX_K, sealed::Sealed};
use super::sample::{sample_cbd, sample_ntt};
use crate::ec::ct;
use crate::sha3::{Shake256, sha3_256, sha3_512};
use crate::wipe::wipe_bytes;

/// What `K-PKE.KeyGen` makes from `d`, besides the bytes of the encapsulation
/// key.
pub(super) struct Generated {
    /// `rho`: the seed of the matrix, the last 32 bytes of the encapsulation key.
    pub(super) rho: [u8; 32],
    /// `A`, row by row: `matrix[i * k + j]` is `A[i][j]`.
    pub(super) matrix: Box<[Poly]>,
    /// `t = A * s + e`.
    pub(super) t: Box<[Poly]>,
    /// The secret `s`.
    pub(super) s: Box<[Poly]>,
}

/// `H`: SHA3-256.
pub(super) fn hash_h(bytes: &[u8]) -> [u8; 32] {
    sha3_256(bytes)
}

/// `G(a || b)` for two strings of 32 bytes, as the two halves of its output:
/// SHA3-512.
pub(super) fn hash_g(a: &[u8; 32], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(a);
    input[32..32 + b.len()].copy_from_slice(b);
    let mut output = sha3_512(&input[..32 + b.len()]);
    let halves = (
        output[..32].try_into().unwrap(),
        output[32..].try_into().unwrap(),
    );
    wipe_bytes(&mut input);
    wipe_bytes(&mut output);
    halves
}

/// `A[i][j] = SampleNTT(rho || j || i)` for the whole matrix (algorithms 13 and
/// 14), row by row.
pub(super) fn expand_matrix<P: Sealed>(rho: &[u8; 32]) -> Box<[Poly]> {
    let mut matrix = vec![[0; N]; P::K * P::K];
    for (index, entry) in matrix.iter_mut().enumerate() {
        *entry = sample_ntt(rho, (index % P::K) as u8, (index / P::K) as u8);
    }
    matrix.into_boxed_slice()
}

/// `K-PKE.KeyGen(d)` (algorithm 13), with the domain separation by `k` that the
/// final standard adds to the hash of `d`: `(rho, sigma) = G(d || k)`.
pub(super) fn key_gen<P: Sealed>(d: &[u8; 32]) -> Generated {
    let (rho, sigma) = hash_g(d, &[P::K as u8]);
    expand_key::<P>(&rho, sigma)
}

/// The rest of `K-PKE.KeyGen` (algorithm 13, from line 2): the keys that `rho`
/// and `sigma` make. `sigma` is overwritten.
pub(super) fn expand_key<P: Sealed>(rho: &[u8; 32], mut sigma: [u8; 32]) -> Generated {
    let matrix = expand_matrix::<P>(rho);

    // `s` and `e` come one after the other from `sigma`, counted from zero.
    let mut counter = 0u8;
    let mut s = vec![[0; N]; P::K];
    for s_i in &mut s {
        *s_i = sample_cbd(&sigma, counter, P::ETA1);
        counter += 1;
        ntt(s_i);
    }
    let mut t = vec![[0; N]; P::K];
    for (i, t_i) in t.iter_mut().enumerate() {
        let mut e_i = sample_cbd(&sigma, counter, P::ETA1);
        counter += 1;
        ntt(&mut e_i);
        *t_i = dot(matrix[i * P::K..(i + 1) * P::K].iter(), &s);
        add(t_i, &e_i);
        reduce(t_i);
    }
    wipe_bytes(&mut sigma);

    Generated {
        rho: *rho,
        matrix,
        t: t.into_boxed_slice(),
        s: s.into_boxed_slice(),
    }
}

/// The encapsulation key: `ByteEncode_12` of each polynomial of `t`, then
/// `rho` (algorithm 13, line 19).
pub(super) fn encode_encapsulation_key<P: Sealed>(t: &[Poly], rho: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![0; P::VECTOR_LEN + 32];
    for (t_i, out) in t.iter().zip(bytes.chunks_exact_mut(384)) {
        byte_encode(t_i, out);
    }
    bytes[P::VECTOR_LEN..].copy_from_slice(rho);
    bytes
}

/// The inverse of [`encode_encapsulation_key`]: `t` and `rho`, or nothing if a
/// coefficient of `t` is not below `q` (the modulus check of section 7.2).
/// `bytes` has the length of an encapsulation key.
pub(super) fn decode_encapsulation_key<P: Sealed>(bytes: &[u8]) -> Option<(Box<[Poly]>, [u8; 32])> {
    debug_assert_eq!(bytes.len(), P::VECTOR_LEN + 32);
    let mut t = vec![[0; N]; P::K];
    let mut valid = true;
    for (t_i, chunk) in t.iter_mut().zip(bytes.chunks_exact(384)) {
        valid &= byte_decode(chunk, t_i);
    }
    let rho = bytes[P::VECTOR_LEN..].try_into().unwrap();
    valid.then(|| (t.into_boxed_slice(), rho))
}

/// `K-PKE.Encrypt(ek, m, r)` (algorithm 14): writes the ciphertext, `P::
/// CIPHERTEXT_LEN` bytes, to `out`.
///
/// `matrix` is `A` and `t` is the vector of `ek`, both already decoded.
pub(super) fn encrypt<P: Sealed>(
    matrix: &[Poly],
    t: &[Poly],
    m: &[u8; 32],
    r: &[u8; 32],
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), P::U_LEN + P::V_LEN);
    let (u_out, v_out) = out.split_at_mut(P::U_LEN);

    // The vector `y`, then `e1` and `e2`, one after the other from `r`.
    let mut counter = 0u8;
    let mut y = [[0; N]; MAX_K];
    for y_i in &mut y[..P::K] {
        *y_i = sample_cbd(r, counter, P::ETA1);
        counter += 1;
        ntt(y_i);
    }
    let mut e1 = [[0; N]; MAX_K];
    for e1_i in &mut e1[..P::K] {
        *e1_i = sample_cbd(r, counter, P::ETA2);
        counter += 1;
    }
    let e2 = sample_cbd(r, counter, P::ETA2);

    // `u = NTT^-1(A^T * y) + e1`: the transpose is the matrix by columns, which
    // is every `k`-th entry from the `i`-th.
    for (i, (e1_i, out)) in e1[..P::K]
        .iter()
        .zip(u_out.chunks_exact_mut(32 * P::DU))
        .enumerate()
    {
        let mut u_i = dot(matrix.iter().skip(i).step_by(P::K), &y[..P::K]);
        inverse_ntt(&mut u_i);
        add(&mut u_i, e1_i);
        compress_and_encode(&u_i, P::DU, out);
    }

    // `v = NTT^-1(t^T * y) + e2 + mu`, with `mu` the message, one bit for each
    // coefficient, as 0 or `q/2` rounded up.
    let mut mu = [0; N];
    decode_and_decompress(m, 1, &mut mu);
    let mut v = dot(t.iter(), &y[..P::K]);
    inverse_ntt(&mut v);
    add(&mut v, &e2);
    add(&mut v, &mu);
    compress_and_encode(&v, P::DV, v_out);
}

/// `K-PKE.Decrypt(dk, c)` (algorithm 15): the message of the ciphertext `c`
/// (`P::CIPHERTEXT_LEN` bytes), where `s` is the secret of the key.
pub(super) fn decrypt<P: Sealed>(s: &[Poly], c: &[u8]) -> [u8; 32] {
    debug_assert_eq!(c.len(), P::U_LEN + P::V_LEN);
    let (u_bytes, v_bytes) = c.split_at(P::U_LEN);

    let mut u = [[0; N]; MAX_K];
    for (u_i, bytes) in u[..P::K].iter_mut().zip(u_bytes.chunks_exact(32 * P::DU)) {
        decode_and_decompress(bytes, P::DU, u_i);
        ntt(u_i);
    }
    let mut v = [0; N];
    decode_and_decompress(v_bytes, P::DV, &mut v);

    // `w = v - NTT^-1(s^T * u)`: the message, plus noise that is small enough
    // for each coefficient to be closer to the right bit than to the other.
    let mut w = dot(s.iter(), &u[..P::K]);
    inverse_ntt(&mut w);
    sub(&mut v, &w);

    let mut m = [0u8; 32];
    compress_and_encode(&v, 1, &mut m);
    m
}

/// `ML-KEM.Encaps_internal(ek, m)` (algorithm 17): writes the ciphertext to
/// `out` and gives the shared secret. `hash` is `H(ek)`.
pub(super) fn encapsulate<P: Sealed>(
    matrix: &[Poly],
    t: &[Poly],
    hash: &[u8; 32],
    m: &[u8; 32],
    out: &mut [u8],
) -> [u8; 32] {
    let (k, mut r) = hash_g(m, hash);
    encrypt::<P>(matrix, t, m, &r, out);
    wipe_bytes(&mut r);
    k
}

/// `ML-KEM.Decaps_internal(dk, c)` (algorithm 18), with the key as its parts: the
/// secret `s`, the public `matrix`, `t` and `hash` (`H(ek)`), and `z`.
///
/// The ciphertext is encrypted again from the message that it decrypts to, and
/// compared with the one received. The secret is `K'` if they are the same and
/// `J(z || c)` if not (implicit rejection, so that a decapsulation always gives
/// a secret and never says whether the ciphertext was good): both are always
/// computed, and the choice is made with a mask.
pub(super) fn decapsulate<P: Sealed>(
    s: &[Poly],
    matrix: &[Poly],
    t: &[Poly],
    hash: &[u8; 32],
    z: &[u8; 32],
    c: &[u8],
) -> [u8; 32] {
    let mut m = decrypt::<P>(s, c);
    let (mut k_prime, mut r) = hash_g(&m, hash);

    let mut again = [0u8; MAX_CIPHERTEXT_LEN];
    let again = &mut again[..c.len()];
    encrypt::<P>(matrix, t, &m, &r, again);

    let mut k_bar = [0u8; 32];
    let mut j = Shake256::new();
    j.absorb(z);
    j.absorb(c);
    j.read(&mut k_bar);

    // 0xff if the ciphertexts are the same and 0x00 if not.
    let same = ct::mask(equal(c, again)) as u8;
    let mut k = [0u8; 32];
    for ((k, &good), &bad) in k.iter_mut().zip(&k_prime).zip(&k_bar) {
        *k = bad ^ (same & (good ^ bad));
    }

    wipe_bytes(&mut m);
    wipe_bytes(&mut k_prime);
    wipe_bytes(&mut r);
    wipe_bytes(&mut k_bar);
    wipe_bytes(again);
    k
}

/// 1 if the strings of the same length are equal and 0 if not, in a time that
/// depends only on the length.
fn equal(a: &[u8], b: &[u8]) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    ct::is_zero(u64::from(difference))
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlKem512, MlKem768, MlKem1024};
    use super::super::testutil::Prng;
    use super::*;

    /// What a message encrypts to decrypts to the message, over all three
    /// sets, for the messages of every kind: the failure of a decryption has
    /// a probability under `2^-138` and so never happens.
    fn round_trip<P: Sealed>() {
        let mut prng = Prng(0xdec0de);
        let d: [u8; 32] = prng.bytes(32).try_into().unwrap();
        let keys = key_gen::<P>(&d);
        let mut messages = vec![[0u8; 32], [0xff; 32], [0x55; 32], [0xaa; 32]];
        for _ in 0..30 {
            messages.push(prng.bytes(32).try_into().unwrap());
        }
        for m in messages {
            let r: [u8; 32] = prng.bytes(32).try_into().unwrap();
            let mut c = vec![0; P::U_LEN + P::V_LEN];
            encrypt::<P>(&keys.matrix, &keys.t, &m, &r, &mut c);
            assert_eq!(decrypt::<P>(&keys.s, &c), m);
        }
    }

    #[test]
    fn k_pke_decrypts_what_it_encrypts() {
        round_trip::<MlKem512>();
        round_trip::<MlKem768>();
        round_trip::<MlKem1024>();
    }

    /// The encapsulation key decodes to the `t` and `rho` that made it, and a
    /// coefficient that is not below `q` anywhere in it is refused.
    #[test]
    fn the_encapsulation_key_encodes_and_decodes() {
        fn check<P: Sealed>() {
            let keys = key_gen::<P>(&[3; 32]);
            let bytes = encode_encapsulation_key::<P>(&keys.t, &keys.rho);
            assert_eq!(bytes.len(), P::VECTOR_LEN + 32);
            assert_eq!(&bytes[P::VECTOR_LEN..], &keys.rho);

            let (t, rho) = decode_encapsulation_key::<P>(&bytes).unwrap();
            assert_eq!(rho, keys.rho);
            // Decoded, the coefficients are from 0 to q - 1: the same numbers
            // modulo q, which encode to the same bytes.
            assert_eq!(encode_encapsulation_key::<P>(&t, &rho), bytes);

            // Every polynomial of t is checked, not only the first.
            for i in 0..P::K {
                let mut bad = bytes.clone();
                bad[384 * i + 1] |= 0x0f;
                bad[384 * i] = 0xff; // 0xfff: 4095
                assert!(decode_encapsulation_key::<P>(&bad).is_none(), "{i}");
            }
        }
        check::<MlKem512>();
        check::<MlKem768>();
        check::<MlKem1024>();
    }

    /// What key generation gives is in the ranges that the products are sized for
    /// (`dot` takes coefficients up to `q` in absolute value): the matrix is from
    /// 0 to `q - 1`, as `SampleNTT` makes it, and `s` and `t` are reduced, between
    /// `-1664` and `1664`. A `t` that is not reduced would still encode to the same
    /// key, so only a look at it tells.
    #[test]
    fn key_generation_gives_polynomials_in_range() {
        fn check<P: Sealed>() {
            let keys = key_gen::<P>(&[9; 32]);
            for entry in keys.matrix.iter() {
                assert!(entry.iter().all(|&c| (0..3329).contains(&c)));
            }
            for poly in keys.s.iter().chain(keys.t.iter()) {
                assert!(poly.iter().all(|c| c.abs() <= 1664));
            }
            assert_eq!(keys.matrix.len(), P::K * P::K);
            assert_eq!((keys.s.len(), keys.t.len()), (P::K, P::K));
        }
        check::<MlKem512>();
        check::<MlKem768>();
        check::<MlKem1024>();
    }
}
