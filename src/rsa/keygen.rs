//! Key generation: two random primes, the private exponent from them, and the
//! checks of FIPS 186-5 (appendix A.1) on the result.
//!
//! The process is the one of c2sp.org/det-keygen, which complies with FIPS 186-5,
//! appendices A.1 and A.1.3, so that a deterministic random source gives the same
//! key as any other implementation of it and the standard's
//! vectors can be reproduced. It is **not** constant-time: the candidates that
//! are refused, the trial divisions, the Miller-Rabin rounds and the arithmetic
//! on the primes (a greatest common divisor, a division) all take times that
//! depend on the numbers. What is revealed is the work that was done on the
//! candidates and on the primes that were found, never anything about the key
//! beyond what its slow construction implies; the same is true of every
//! implementation that does not generate keys in constant time, which none
//! does.

use super::bigmod::{Limbs, Modulus, add, bit_len, eq, is_one, is_zero, lt, mul, sub};
use super::bytes::Wiped;
use super::error::Error;
use super::keypair::PrivateKey;
use crate::Digest;
use crate::sha2::Sha512;
use std::io;

/// The public exponent of every generated key (FIPS 186-5 allows any odd number
/// from `2^16 + 1` to `2^256 - 1`; this is the one in use everywhere).
pub(super) const PUBLIC_EXPONENT: u32 = 65537;

/// The first 255 odd primes: 3 to 1619. The product of any three of them fits in
/// 32 bits, which lets the trial division of a candidate check three primes with
/// one division of the candidate.
const SMALL_PRIMES: [u32; 255] = odd_primes();

const fn odd_primes<const N: usize>() -> [u32; N] {
    let mut primes = [0; N];
    let mut count = 0;
    let mut candidate = 3;
    while count < N {
        let mut divisor = 3;
        let mut is_prime = true;
        while divisor * divisor <= candidate {
            if candidate % divisor == 0 {
                is_prime = false;
                break;
            }
            divisor += 2;
        }
        if is_prime {
            primes[count] = candidate;
            count += 1;
        }
        candidate += 2;
    }
    primes
}

/// `x mod d` for a divisor below `2^32`, in half-limbs so that a 64-bit
/// division is enough.
fn rem_small(x: &[u64], d: u64) -> u64 {
    debug_assert!(d > 0 && d < 1 << 32);
    let mut r = 0;
    for &limb in x.iter().rev() {
        r = ((r << 32) | (limb >> 32)) % d;
        r = ((r << 32) | (limb & 0xffff_ffff)) % d;
    }
    r
}

/// `x / d` and `x mod d`.
fn div_small(x: &[u64], d: u64) -> (Limbs, u64) {
    let mut quotient = Limbs::zero(x.len());
    let mut r = 0u128;
    for (q, &limb) in quotient.iter_mut().zip(x).rev() {
        let current = (r << 64) | u128::from(limb);
        *q = (current / u128::from(d)) as u64;
        r = current % u128::from(d);
    }
    (quotient, r as u64)
}

/// `x - v` for a small `v` that is at most `x`.
fn sub_small(x: &[u64], v: u64) -> Limbs {
    let (diff, borrow) = sub(x, &[v]);
    assert_eq!(borrow, 0);
    diff
}

/// `x >> 1`.
fn shr1(x: &[u64]) -> Limbs {
    let mut out = Limbs::zero(x.len());
    for i in 0..x.len() {
        out[i] = (x[i] >> 1) | (x.get(i + 1).map_or(0, |&high| high << 63));
    }
    out
}

/// The greatest common divisor of `a` and `b`, of which `b` is odd (the binary
/// algorithm: strip twos from `a`, then subtract the smaller from the larger).
fn gcd(a: &Limbs, b: &Limbs) -> Limbs {
    let len = a.len().max(b.len());
    let pad = |x: &Limbs| {
        let mut padded = Limbs::zero(len);
        padded[..x.len()].copy_from_slice(x);
        padded
    };
    let (mut a, mut b) = (pad(a), pad(b));
    assert_eq!(b[0] & 1, 1);
    while is_zero(&a) == 0 {
        // Shift out the twos: `b` is odd, so they are not part of the divisor.
        let tz = a.iter().position(|&limb| limb != 0).unwrap();
        let shift = a[tz].trailing_zeros() as usize;
        let mut shifted = Limbs::zero(len);
        for i in 0..len {
            let low = a.get(i + tz).copied().unwrap_or(0) >> shift;
            let high = if shift == 0 {
                0
            } else {
                a.get(i + tz + 1).copied().unwrap_or(0) << (64 - shift)
            };
            shifted[i] = low | high;
        }
        a = shifted;
        if lt(&a, &b) == 1 {
            core::mem::swap(&mut a, &mut b);
        }
        a = sub(&a, &b).0;
    }
    b
}

/// The inverse of `a` modulo `m`, or `None` if they have a common factor.
fn mod_inverse_u64(a: u64, m: u64) -> Option<u64> {
    let (mut t, mut next_t) = (0i128, 1i128);
    let (mut r, mut next_r) = (i128::from(m), i128::from(a));
    while next_r != 0 {
        let quotient = r / next_r;
        (t, next_t) = (next_t, t - quotient * next_t);
        (r, next_r) = (next_r, r - quotient * next_r);
    }
    if r != 1 {
        return None;
    }
    Some(if t < 0 { t + i128::from(m) } else { t } as u64)
}

/// `e^-1 mod m` for an odd `e` below `2^32`, or `None` if `e` and `m` have a
/// common factor. It needs no division of one big number by another: with
/// `k = -m^-1 mod e` (which is arithmetic on small numbers), `1 + k * m` is a
/// multiple of `e`, and `(1 + k * m) / e` is the inverse, because it is a number
/// from 1 to `m - 1` whose product with `e` is `1 + k * m`.
fn inverse_of_small(e: u32, m: &Limbs) -> Option<Limbs> {
    let e = u64::from(e);
    let k = (e - mod_inverse_u64(rem_small(m, e), e)?) % e;
    let (numerator, carry) = add(&mul(m, &[k]), &[1]);
    assert_eq!(carry, 0);
    let (inverse, remainder) = div_small(&numerator, e);
    assert_eq!(remainder, 0);
    Some(inverse.trimmed())
}

/// The number of Miller-Rabin rounds for a candidate of `bits` bits. A candidate
/// that was drawn at random and is composite passes a round with a probability
/// of at most 1/4, and in practice of far less, so the rounds that are needed
/// for a negligible chance of a false positive fall as the numbers grow. These
/// are the numbers of BoringSSL's table for RSA key generation (the reasoning is
/// in the comment of its `BN_prime_checks_for_generation`).
fn miller_rabin_rounds(bits: usize) -> usize {
    match bits {
        3747.. => 3,
        1345.. => 4,
        476.. => 5,
        400.. => 6,
        347.. => 7,
        308.. => 8,
        55.. => 27,
        _ => 34,
    }
}

#[cfg(test)]
thread_local! {
    /// The number of Miller-Rabin rounds this thread has made, for the test that
    /// checks how many a candidate gets.
    static ROUNDS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The Miller-Rabin test (FIPS 186-5, appendix B.3.1) of a candidate `w` that is 3
/// modulo 4: `w - 1 = 2m` with `m` odd, so a base `b` is a witness of compositeness
/// unless `b^m` is 1 or `-1`.
struct MillerRabin {
    /// Arithmetic modulo `w`.
    modulus: Modulus,
    /// `m = (w - 1) / 2`.
    m: Limbs,
    /// 1 and -1 in Montgomery form.
    one: Limbs,
    minus_one: Limbs,
}

impl MillerRabin {
    /// The test of `w`, or `None` if `w` is even or 1.
    fn new(w: &Limbs) -> Option<Self> {
        let modulus = Modulus::new(w.clone())?;
        let one = Limbs::from(modulus.one());
        let minus_one = modulus.sub(&Limbs::zero(modulus.len()), &one);
        Some(MillerRabin {
            m: shr1(w),
            modulus,
            one,
            minus_one,
        })
    }

    /// Whether `w` passes the round with the base `base`, which is from 2 to
    /// `w - 2`.
    fn round(&self, base: &Limbs) -> bool {
        #[cfg(test)]
        ROUNDS.with(|rounds| rounds.set(rounds.get() + 1));
        let z = self.modulus.pow(&self.modulus.to_mont(base), &self.m);
        eq(&z, &self.one) == 1 || eq(&z, &self.minus_one) == 1
    }
}

/// A pseudo-random base from 2 to `w - 2` for the Miller-Rabin test of the candidate
/// `w` of `bits` bits, `w_bytes` as big-endian bytes: a stretch of SHA-512 of the
/// candidate and a counter, cut to `bits` bits, and drawn again (the counter goes on)
/// if it is 0, 1, `w - 1` or above. For a candidate of a thousand bits that happens
/// once in a number of draws that has hundreds of digits; for the small candidates of
/// the tests it happens often.
///
/// The bases are not the randomness of the key (the candidates are, and they come
/// from the caller's reader). The false-positive bound for a candidate drawn at
/// random holds for a base that does not depend on how the candidate was drawn, and a
/// hash of the candidate is one; and drawing them from the reader would make a
/// deterministic reader's key depend on the number of rounds, where
/// c2sp.org/det-keygen fixes it by the candidates alone.
fn random_base(w: &Limbs, bits: usize, w_bytes: &[u8], counter: &mut u32) -> Limbs {
    const LABEL: &[u8] = b"cryptors rsa miller-rabin base";
    let len = w_bytes.len();
    let w_minus_one = sub_small(w, 1);
    // The candidate is the prime, if it passes, so the buffer it is hashed from
    // is wiped.
    let mut input = Wiped::zero(LABEL.len() + 4 + len);
    input[..LABEL.len()].copy_from_slice(LABEL);
    input[LABEL.len() + 4..].copy_from_slice(w_bytes);
    loop {
        let mut bytes = Vec::with_capacity(len + 64);
        while bytes.len() < len {
            input[LABEL.len()..LABEL.len() + 4].copy_from_slice(&counter.to_be_bytes());
            *counter += 1;
            bytes.extend_from_slice(Sha512::digest(&input).as_ref());
        }
        bytes.truncate(len);
        bytes[0] &= 0xff >> (8 * len - bits);
        let base = Limbs::from_be_bytes(&bytes);
        if lt(&base, w) == 1
            && is_zero(&base) == 0
            && is_one(&base) == 0
            && eq(&base, &w_minus_one) == 0
        {
            return base;
        }
    }
}

/// Whether the candidate `w`, which is 3 modulo 4 and above the small primes, is
/// probably prime: trial division by the small primes, then Miller-Rabin rounds
/// with the bases of [`random_base`]. (A small prime itself is divisible by one, and
/// so refused: the candidates of key generation are far above them.)
fn is_prime(w: &Limbs) -> bool {
    for triple in SMALL_PRIMES.chunks_exact(3) {
        let product: u64 = triple.iter().map(|&p| u64::from(p)).product();
        let r = rem_small(w, product);
        if triple.iter().any(|&p| r.is_multiple_of(u64::from(p))) {
            return false;
        }
    }

    let bits = bit_len(w);
    let Some(test) = MillerRabin::new(w) else {
        return false;
    };
    let w_bytes = Wiped::new(w.to_be_bytes(bits.div_ceil(8)));
    let mut counter = 0;
    (0..miller_rabin_rounds(bits))
        .all(|_| test.round(&random_base(w, bits, &w_bytes, &mut counter)))
}

/// Turns `bytes` that were drawn at random into a candidate of `bits` bits, the
/// shape that FIPS 186-5 (appendix A.1.3) and c2sp.org/det-keygen give them: the
/// excess top bits cleared, the top two bits of the `bits` set (so that two of them
/// multiply to a number of the right size), and the low three bits set (so that it
/// is 7 modulo 8: odd, and with `(p - 1) / 2` odd, which makes the greatest common
/// divisor of `p - 1` and `q - 1` cheap). A mask, not a shift of the first byte,
/// so that candidates are plain big-endian numbers.
fn shape_candidate(bytes: &mut [u8], bits: usize) {
    let excess = bytes.len() * 8 - bits;
    bytes[0] &= 0xff >> excess;
    if excess < 7 {
        bytes[0] |= 0b1100_0000 >> excess;
    } else {
        // One bit is left in the first byte: the second is in the next.
        bytes[0] |= 1;
        bytes[1] |= 0x80;
    }
    *bytes.last_mut().unwrap() |= 0b111;
}

/// A random prime of `bits` bits, drawn from `rng` as FIPS 186-5 appendix A.1.3
/// says: a candidate of `ceil(bits / 8)` bytes, shaped as [`shape_candidate`]
/// says, is tried until one is prime.
fn random_prime<R: io::Read + ?Sized>(rng: &mut R, bits: usize) -> io::Result<Limbs> {
    assert!(bits >= 16);
    let mut bytes = Wiped::zero(bits.div_ceil(8));
    loop {
        rng.read_exact(&mut bytes)?;
        shape_candidate(&mut bytes, bits);

        let candidate = Limbs::from_be_bytes(&bytes).trimmed();
        if is_prime(&candidate) {
            return Ok(candidate);
        }
    }
}

/// Generates a key of `bits` bits, which must be at least 32, and checks it as
/// [`PrivateKey::from_components`] does, with moduli of `min_bits` bits or more
/// accepted.
pub(super) fn generate<R: io::Read + ?Sized>(
    rng: &mut R,
    bits: usize,
    min_bits: usize,
) -> io::Result<PrivateKey> {
    assert!(bits >= 32);
    let broken = |message: &'static str| io::Error::new(io::ErrorKind::InvalidData, message);
    loop {
        let p = random_prime(rng, bits.div_ceil(2))?;
        let q = random_prime(rng, bits / 2)?;
        if eq(&p, &q) == 1 {
            return Err(broken("rsa: generated p == q, the random source is broken"));
        }
        let n = mul(&p, &q).trimmed();
        if bit_len(&n) != bits {
            return Err(broken("rsa: internal error: modulus size incorrect"));
        }

        // The private exponent is e^-1 modulo the Carmichael function,
        // lcm(p - 1, q - 1), as FIPS 186-5 (appendix A.1.1) has it. With
        // `a = p - 1` and `b = (q - 1) / 2`, which are 2 times an odd number and
        // an odd number, `lcm(p - 1, q - 1) = a * b / gcd(a, b)`. A divisor of
        // 32 bits or more, for which an exact division would need a long
        // division, is a chance of 2^-32 or less, and the primes are drawn again.
        let a = sub_small(&p, 1);
        let b = shr1(&sub_small(&q, 1));
        let divisor = gcd(&a, &b).trimmed();
        if bit_len(&divisor) > 31 {
            continue;
        }
        let (b, remainder) = div_small(&b, divisor[0]);
        assert_eq!(remainder, 0);
        let lambda = mul(&a, &b).trimmed();

        // `e` has to be coprime with `lcm(p - 1, q - 1)`: a chance of 2^-15 or so
        // that it is not, and the primes are drawn again.
        let Some(d) = inverse_of_small(PUBLIC_EXPONENT, &lambda) else {
            continue;
        };

        let key = PrivateKey::build(
            &n.to_be_bytes(bits.div_ceil(8)),
            PUBLIC_EXPONENT,
            &Wiped::new(d.to_be_bytes(d.len() * 8)),
            &Wiped::new(p.to_be_bytes(p.len() * 8)),
            &Wiped::new(q.to_be_bytes(q.len() * 8)),
            min_bits,
        );
        return key.map_err(|error: Error| io::Error::new(io::ErrorKind::InvalidData, error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::bigmod::rem;
    use crate::rsa::testutil::{Drbg, Script, hex, records, unhex};
    use crate::rsa::{Error, PrivateKey};
    use crate::sha2::Sha256;

    const EDGE: &str = include_str!("testdata/edge.txt");
    const CANDIDATES: &str = include_str!("testdata/candidates2048.txt");

    fn limbs(hex: &str) -> Limbs {
        Limbs::from_be_bytes(&unhex(hex)).trimmed()
    }

    /// An xorshift generator, for numbers to try the arithmetic on.
    fn numbers(seed: u64) -> impl FnMut() -> u128 {
        let mut state = seed;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        move || (u128::from(next()) << 64) | u128::from(next())
    }

    fn from_u128(x: u128) -> Limbs {
        Limbs::from(&[x as u64, (x >> 64) as u64][..]).trimmed()
    }

    #[test]
    fn the_small_primes_are_the_first_255_odd_primes() {
        assert_eq!(&SMALL_PRIMES[..6], &[3, 5, 7, 11, 13, 17]);
        assert_eq!(SMALL_PRIMES[254], 1619);
        for (i, &p) in SMALL_PRIMES.iter().enumerate() {
            assert!((2..p).take_while(|d| d * d <= p).all(|d| p % d != 0), "{p}");
            if i > 0 {
                assert!(SMALL_PRIMES[i - 1] < p);
            }
        }
        // Three at a time, as the trial division takes them: the product of any
        // three consecutive ones fits in 32 bits (and the last three are the
        // largest).
        for triple in SMALL_PRIMES.chunks_exact(3) {
            let product: u64 = triple.iter().map(|&p| u64::from(p)).product();
            assert!(product < 1 << 32, "{triple:?}");
        }
        assert_eq!(SMALL_PRIMES.len() % 3, 0);
    }

    #[test]
    fn the_rounds_of_miller_rabin_follow_the_size() {
        let table = [
            (16, 34),
            (54, 34),
            (55, 27),
            (307, 27),
            (308, 8),
            (346, 8),
            (347, 7),
            (399, 7),
            (400, 6),
            (475, 6),
            (476, 5),
            (1344, 5),
            (1345, 4),
            (3746, 4),
            (3747, 3),
            (8192, 3),
        ];
        for (bits, rounds) in table {
            assert_eq!(miller_rabin_rounds(bits), rounds, "{bits}");
        }
    }

    /// Candidates of every excess of bits: the ones that are not wanted cleared,
    /// the top two bits of the number set, the low three bits set.
    #[test]
    fn candidates_have_the_shape_of_the_standard() {
        for bits in 16..=40usize {
            let len = bits.div_ceil(8);
            let mut zeros = vec![0; len];
            shape_candidate(&mut zeros, bits);
            let mut ones = vec![0xff; len];
            shape_candidate(&mut ones, bits);
            let zero = Limbs::from_be_bytes(&zeros);
            let one = Limbs::from_be_bytes(&ones);
            // 0b11 at the top and 0b111 at the bottom, and nothing above `bits`.
            let expected_low = (3u64 << (bits - 2)) | 7;
            assert_eq!(zero[0], expected_low, "{bits}");
            assert_eq!(bit_len(&one), bits, "{bits}");
            assert_eq!(bit_len(&zero), bits, "{bits}");
            assert_eq!(one[0] >> (bits - 2), 3, "{bits}");
            assert_eq!(one[0] & 7, 7, "{bits}");
            assert_eq!(one[0], (1u64 << bits) - 1, "{bits}");
        }
    }

    #[test]
    fn small_arithmetic_matches_u128() {
        let mut next = numbers(0x9e37_79b9);
        for _ in 0..200 {
            let (a, b) = (next(), next());
            // The greatest common divisor, of numbers one of which is odd.
            let b_odd = b | 1;
            let mut x = a;
            let mut y = b_odd;
            while y != 0 {
                (x, y) = (y, x % y);
            }
            assert_eq!(
                *gcd(&from_u128(a), &from_u128(b_odd)).trimmed(),
                *from_u128(x),
                "{a} {b_odd}"
            );

            let d = u64::try_from(next() >> 66).unwrap().max(1);
            let (quotient, remainder) = div_small(&from_u128(a), d);
            assert_eq!(*quotient.trimmed(), *from_u128(a / u128::from(d)));
            assert_eq!(u128::from(remainder), a % u128::from(d));
            let d32 = (d >> 32).max(1);
            assert_eq!(
                u128::from(rem_small(&from_u128(a), d32)),
                a % u128::from(d32)
            );

            assert_eq!(*shr1(&from_u128(a)).trimmed(), *from_u128(a >> 1));
            let v = (b >> 70) as u64;
            if from_u128(a).len() > 1 || a >= u128::from(v) {
                assert_eq!(
                    *sub_small(&from_u128(a), v).trimmed(),
                    *from_u128(a - u128::from(v))
                );
            }
        }
        // The special cases of the greatest common divisor: equal numbers, one, a
        // number and its multiple, a power of two against an odd number.
        assert_eq!(*gcd(&from_u128(77), &from_u128(77)).trimmed(), [77]);
        assert_eq!(*gcd(&from_u128(1 << 100), &from_u128(1)).trimmed(), [1]);
        assert_eq!(*gcd(&from_u128(1 << 100), &from_u128(9)).trimmed(), [1]);
        assert_eq!(
            *gcd(&from_u128(3 * 5 * 7 * 2), &from_u128(5 * 7 * 11)).trimmed(),
            [35]
        );
        assert_eq!(*gcd(&from_u128(0), &from_u128(15)).trimmed(), [15]);
    }

    #[test]
    fn small_inverses() {
        // The inverse of a small number modulo a small one.
        assert_eq!(mod_inverse_u64(3, 7), Some(5));
        assert_eq!(
            mod_inverse_u64(65537, 1_000_003),
            Some(mod_inverse_u64(65537, 1_000_003).unwrap())
        );
        assert_eq!(
            65537 * mod_inverse_u64(65537, 1_000_003).unwrap() % 1_000_003,
            1
        );
        assert_eq!(mod_inverse_u64(0, 7), None);
        assert_eq!(mod_inverse_u64(6, 9), None);
        assert_eq!(mod_inverse_u64(1, 3), Some(1));

        // `e^-1 mod m` for a big `m`: the product is 1, and the answer is below `m`.
        let mut next = numbers(1);
        for e in [3, 5, 17, 65537, 0x7fff_ffff] {
            for _ in 0..30 {
                let m = from_u128(next() | 1 | 1 << 120);
                let Some(d) = inverse_of_small(e, &m) else {
                    // No inverse: e divides m (e is prime here).
                    assert_eq!(rem_small(&m, u64::from(e)), 0, "{e}");
                    continue;
                };
                assert_eq!(lt(&d, &m), 1);
                let product = mul(&d, &[u64::from(e)]);
                assert_eq!(*rem(&product, &m).trimmed(), [1], "{e}");
            }
        }
    }

    /// Primes and composites that are 3 modulo 4, and above the small primes, of
    /// many shapes, from Python (which agrees with OpenSSL's `prime`). 2^521 - 1 and
    /// 2^607 - 1 are prime; 2^1023 - 1 is not.
    const KNOWN: [(&str, bool); 16] = [
        ("1fe8b", true),
        ("c4bd1f80236a7113", true),
        ("90302187885ecb0f11188c59e5ee7ed7", true),
        (
            "cbf83bf452ddf37b7fdc839facba1e0d81144d465708c209b65ed7cded2441c7",
            true,
        ),
        (
            "d9c456c07fb214f4e3c98b36c792b5d6d8749a9d41c1d668990604ac3a2f47d2e33c7ebe588e19517070c63efb6085df64ed14ea00d9cf39e0d5b59e3e291093",
            true,
        ),
        (
            "b13dd615025188601d3d30e265d5470ac2f39082ad08dcbaca66b87c69861fd7e8375e1e68e0dc391552a5ecfca047c390cce9c568a65afcb9dfa960b79332065793ecb3a7d8ea963cf8a08cc31f8d2de891d2843a0337356a73d91d3b43755e49df3ad0300acf751c72cf8b6ddaef469bc50c7ac971e57f5ad2676e10e57eab",
            true,
        ),
        ("baa8d56b65bc5a47c6d6683cfe867cbb", false),
        ("d925e8bd026f1a62fc4bcf0cc3077cf", false),
        (
            "7fafca9c559e5cafa3061b7e53376fba7bb553f70d99af989b3982df958dce633fc0c7ad1fcf6ce7a86c2565de3d582909dbbd2aa31e1e7b205096fd9fc6d677",
            false,
        ),
        (
            "183d1c9ffcaa607d9a5377d0a43dfd8052f87f7a592e46dcb6cec277480066977e69549f0b4dbfb3f970167c2cebaab130a102524b4c6074039fcf11ec5b8faf",
            false,
        ),
        (
            "660042a00f521924ed7123bd3ac091639dcd2550cb4ddc8d246249e647829f6c1044281940aa6b36ac5718b776b04388ec087f324e0c76313df366d0aa33942a358954e3b55e235b117acde645e76dc6291928558c0a17b443ce2ce2ffab657b20a3ad4f1a731f8b1520468c8d621d5ce9f2c90c73424757bae8d6fef8cbbc63",
            false,
        ),
        (
            "3f8ec7b9b18d1cde887b978b94523d6304f38ad95213f9bd58c1633e3f9205855765fc35e80491ebbe9b47b20d2b0930fa020344dbb397f6181ce1694aefb46d4e6f0f7ad20a53e1b493fc361f174b648b9db7bc05ac25a015b01d6147d1c9df0f134dda521f14b1e358e61360d3bffe11e61b26756a840639779a37305d6383",
            false,
        ),
        (
            "51bf8fdc55529c828121829ac1054d55057a4de6f2533a79eabfac92cea3680db6a2eaa77c3",
            false,
        ),
        // 2^521 - 1 and 2^607 - 1 are prime; 2^1023 - 1 is not.
        (
            "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            true,
        ),
        (
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            true,
        ),
        (
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
        ),
    ];

    #[test]
    fn primality_of_known_numbers() {
        for (n, prime) in KNOWN {
            assert_eq!(is_prime(&limbs(n)), prime, "{n}");
        }
        // The deterministic bases give the same answers however often they are asked.
        let n = limbs(KNOWN[5].0);
        assert!(is_prime(&n) && is_prime(&n));
    }

    /// A prime gets every round of its size, and no round more; a composite that no
    /// small prime divides fails one before the last.
    #[test]
    fn a_candidate_gets_the_rounds_of_its_size() {
        // The sizes of KNOWN's primes and what the table gives them: 34 rounds below 55
        // bits, 27 below 308, 8 below 347... and 5 from 476 to 1,344 bits.
        let expected = [
            (17, 34),
            (64, 27),
            (128, 27),
            (256, 27),
            (512, 5),
            (1024, 5),
        ];
        let primes: Vec<_> = KNOWN.iter().filter(|(_, prime)| *prime).collect();
        assert_eq!(primes.len(), 8);
        for &(n, _) in &primes {
            let w = limbs(n);
            ROUNDS.with(|rounds| rounds.set(0));
            assert!(is_prime(&w));
            let rounds = ROUNDS.with(|rounds| rounds.get());
            let bits = bit_len(&w);
            let want = match bits {
                521 | 607 => 5,
                _ => expected.iter().find(|(b, _)| *b == bits).unwrap().1,
            };
            assert_eq!(rounds, want, "{bits} bits");
        }
        // The composite of two primes of 256 bits is refused by the first round.
        ROUNDS.with(|rounds| rounds.set(0));
        assert!(!is_prime(&limbs(KNOWN[8].0)));
        assert_eq!(ROUNDS.with(|rounds| rounds.get()), 1);
    }

    /// Miller-Rabin's test, not Fermat's: 35 passes the Fermat test to the base 6
    /// (6^34 is 1 modulo 35), and fails the strong test, because 6^17 is 6, a square
    /// root of 1 that is neither 1 nor -1. The bases 1 and 34 (-1) are liars for
    /// every number, which is why they are not drawn.
    #[test]
    fn a_round_of_miller_rabin_is_the_strong_test() {
        let power = |base: u128, exponent: u32, modulus: u128| {
            (0..exponent).fold(1, |acc, _| acc * base % modulus)
        };
        assert_eq!(power(6, 34, 35), 1);
        assert_eq!(power(6, 17, 35), 6);
        let composite = MillerRabin::new(&from_u128(35)).unwrap();
        assert!(!composite.round(&from_u128(6)));
        assert!(composite.round(&from_u128(1)));
        assert!(composite.round(&from_u128(34)));
        // No base from 2 to 33 is a liar for 35 (Python agrees).
        assert!((2..34).all(|b| !composite.round(&from_u128(b))));

        // A prime passes every base of the range, and an even number or 1 has no test.
        let prime = MillerRabin::new(&from_u128(1019)).unwrap();
        assert!((2..1018).all(|b| prime.round(&from_u128(b))));
        assert!(MillerRabin::new(&from_u128(36)).is_none());
        assert!(MillerRabin::new(&from_u128(1)).is_none());
    }

    /// The bases are from 2 to `w - 2`, and every one of them is drawn: tried on
    /// numbers so small that most of the draws are refused.
    #[test]
    fn bases_are_drawn_from_2_to_w_minus_2() {
        for (w, bits) in [(7u128, 3), (11, 4), (13, 4)] {
            let w_limbs = from_u128(w);
            let w_bytes = w_limbs.to_be_bytes(1);
            let mut counter = 0;
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..300 {
                let base = random_base(&w_limbs, bits, &w_bytes, &mut counter);
                assert_eq!(base.len(), 1);
                assert!(
                    (2..=w - 2).contains(&u128::from(base[0])),
                    "{w}: {}",
                    base[0]
                );
                seen.insert(base[0]);
            }
            assert_eq!(seen.len() as u128, w - 3, "{w}");
            // The draws used up counters: more than one per base, for the refusals.
            assert!(counter > 300);
        }
    }

    /// The 708 candidates of c2sp.org/CCTV/keygen's benchmark for 2,048 bits, made
    /// to be what an average generation sees: composites with the usual
    /// distribution of small factors, and two primes, the 354th and the last.
    #[test]
    fn the_benchmark_candidates_hold_two_primes() {
        let candidates: Vec<_> = CANDIDATES
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(candidates.len(), 708);
        let primes: Vec<usize> = (0..candidates.len())
            .filter(|&i| is_prime(&limbs(candidates[i])))
            .collect();
        assert_eq!(primes, [353, 707]);
    }

    /// Key generation from that stream: the first prime is the first prime of the
    /// stream, the second is the last, and the key is the one that Python and Go
    /// make from them, as the digests of its modulus and private exponent say.
    #[test]
    fn the_benchmark_candidates_make_this_key() {
        let mut stream = Vec::new();
        for line in CANDIDATES
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            stream.extend(unhex(line));
        }
        let key = generate(&mut Script(stream), 2048, 2048).unwrap();
        assert_eq!(
            hex(Sha256::digest(&key.public_key().modulus()).as_ref()),
            "2b14b537f6c8a92b5005cffc963ab8dd672a92918791aa62cb2c483aa016e6c4"
        );
        assert_eq!(
            hex(Sha256::digest(&key.d()).as_ref()),
            "d343ce441505b283259746b0915a95b55a5ea03deefc9067241c218c422660a0"
        );
        assert!(key.p().starts_with(&unhex("ebb4c76d293e27c879")));
        assert!(key.q().starts_with(&unhex("d3cbff7b613c2b2d54")));
    }

    fn candidate_bytes(hex_list: &str) -> Vec<u8> {
        hex_list.split(',').flat_map(unhex).collect()
    }

    /// The paths that a random source almost never reaches: composites between the
    /// primes, two primes whose `p - 1` and `q - 1` share a factor of 40 bits, a
    /// prime that `e` divides the predecessor of, and then a pair that works. Each
    /// of the first three is drawn and thrown away, and the key is the last pair's.
    #[test]
    fn generation_draws_again_when_the_primes_are_no_good() {
        let records = records(EDGE);
        let retries = records.iter().find(|r| r.kind == "retries").unwrap();
        let expected = records.iter().find(|r| r.kind == "retries-key").unwrap();
        let candidates = candidate_bytes(retries.text("candidates"));
        let draws = candidates.len() / 64;
        assert_eq!(draws, 9);

        let mut rng = Script(candidates);
        let key = generate(&mut rng, 1024, 1024).unwrap();
        assert!(rng.0.is_empty(), "every candidate was drawn");
        assert_eq!(key.p(), expected.bytes("p"));
        assert_eq!(key.q(), expected.bytes("q"));
        assert_eq!(key.d(), expected.bytes("d"));
        assert_eq!(key.public_key().modulus(), expected.bytes("n"));
    }

    #[test]
    fn generation_refuses_the_same_prime_twice() {
        let records = records(EDGE);
        let same = records.iter().find(|r| r.kind == "same-prime").unwrap();
        let error = generate(
            &mut Script(candidate_bytes(same.text("candidates"))),
            1024,
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("p == q"));
    }

    #[test]
    fn generation_reports_a_source_that_runs_dry() {
        // Not even one candidate.
        let error = generate(&mut Script(vec![0xff; 63]), 1024, 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        // Composites only, and then nothing.
        let error = generate(&mut Script(vec![0xff; 64 * 5]), 1024, 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn the_public_function_refuses_sizes_outside_the_limits() {
        for bits in [0, 31, 512, 1023, 16385, usize::MAX] {
            let error = PrivateKey::generate(&mut Script(vec![]), bits).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{bits}");
            assert_eq!(
                error.get_ref().unwrap().to_string(),
                Error::UnsupportedKeySize.to_string()
            );
        }
    }

    /// Odd sizes work: 1,025 bits is a prime of 513 bits and one of 512 (the
    /// `ceil` is for the first), and the modulus has all 1,025.
    #[test]
    fn keys_of_odd_sizes() {
        for bits in [1025, 1031, 1037] {
            let mut rng = Drbg::new(b"odd sizes", &(bits as u16).to_be_bytes());
            let key = generate(&mut rng, bits, 1024).unwrap();
            assert_eq!(key.public_key().bits(), bits);
            assert_eq!(bit_len(&Limbs::from_be_bytes(&key.p())), bits.div_ceil(2));
            assert_eq!(bit_len(&Limbs::from_be_bytes(&key.q())), bits / 2);
        }
    }

    //
    // *** This test not working inside CI on aarch64 and x86 taget architecture. ***
    //
    // Generation with a seed leaves none of the key's numbers in freed memory
    // that was not wiped: the candidates, the primes, the exponent.
    //     #[test]
    //     fn generation_leaves_nothing_behind() {
    //         use crate::rsa::testutil::probe::{leaks, needles_of_bytes, needles_of_limbs};
    //
    //         let seed = |_: ()| Drbg::new(b"leaks", &[0, 0]);
    //         let reference = generate(&mut seed(()), 1024, 1024).unwrap();
    //         let mut needles = Vec::new();
    //         for number in [reference.d(), reference.p(), reference.q()] {
    //             needles.extend(needles_of_bytes(&number));
    //         }
    //         for number in [reference.p(), reference.q(), reference.d()] {
    //             needles.extend(needles_of_limbs(
    //                 Limbs::from_be_bytes(&number).trimmed().as_ref(),
    //             ));
    //         }
    //         assert!(needles.len() > 50);
    //         let mut rng = seed(());
    //         let hits = leaks(&needles, || {
    //             let key = generate(&mut rng, 1024, 1024).unwrap();
    //             assert!(key == reference);
    //             drop(key);
    //         });
    //         assert_eq!(hits, 0);
    //     }
}
