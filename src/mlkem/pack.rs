//! `Compress` and `Decompress` (FIPS 203, definitions 4.7 and 4.8) and the
//! encodings of polynomials in bytes, `ByteEncode_d` and `ByteDecode_d`
//! (algorithms 5 and 6).
//!
//! `d` is a parameter of these functions and not of their types. They are
//! `inline(always)`, and every caller passes a constant, so each call is the
//! function for that `d`.
//!
//! The compression of a coefficient is made with a multiplication and a shift in
//! place of a division by `q`, so that the time it takes does not depend on
//! the coefficient: the ciphertext is computed from a secret message.

use super::field::{N, Poly, Q, to_unsigned};

/// `ceil(2^35 / q)`: `x * RECIPROCAL >> 35` is `x / q` rounded down, exactly,
/// for every `x` below `2^23`. The error of the approximation is `x * e / (q *
/// 2^35)` with `e = RECIPROCAL * q - 2^35 < q`, which is under `2^-12` for
/// such `x`, and under `1 / q` so that it cannot carry into the next integer.
const RECIPROCAL: u64 = (1u64 << 35).div_ceil(Q as u64);

/// `Compress_d(x) = round(2^d * x / q) mod 2^d` (definition 4.7), for `x`
/// between 0 and `q - 1`, with halves rounded up.
///
/// Since `q` is odd the rounding is `floor((2^d * x + (q - 1) / 2) / q)`; `2^d *
/// x` is under `2^23` for every `d` up to 11.
#[inline(always)]
pub(super) fn compress(x: u16, d: usize) -> u16 {
    let numerator = (u64::from(x) << d) + (Q as u64 - 1) / 2;
    (((numerator * RECIPROCAL) >> 35) & ((1 << d) - 1)) as u16
}

/// `Decompress_d(y) = round(q * y / 2^d)` (definition 4.8), for `y` below `2^d`,
/// with halves rounded up.
#[inline(always)]
pub(super) fn decompress(y: u16, d: usize) -> u16 {
    ((u32::from(y) * Q as u32 + (1 << (d - 1))) >> d) as u16
}

/// Packs 256 numbers of `d` bits each into `32 * d` bytes, least significant
/// bit first (the bit string of algorithm 5, as bytes): eight of them make
/// exactly `d` bytes.
#[inline(always)]
fn pack(values: &[u16; N], d: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d);
    for (group, bytes) in values.chunks_exact(8).zip(out.chunks_exact_mut(d)) {
        let mut word = 0u128;
        for (i, &value) in group.iter().enumerate() {
            word |= u128::from(value) << (d * i);
        }
        bytes.copy_from_slice(&word.to_le_bytes()[..d]);
    }
}

/// The inverse of [`pack`] (algorithm 6, before the reduction modulo `m`).
#[inline(always)]
fn unpack(bytes: &[u8], d: usize) -> [u16; N] {
    debug_assert_eq!(bytes.len(), 32 * d);
    let mask = (1u128 << d) - 1;
    let mut values = [0; N];
    for (group, bytes) in values.chunks_exact_mut(8).zip(bytes.chunks_exact(d)) {
        let mut buffer = [0u8; 16];
        buffer[..d].copy_from_slice(bytes);
        let word = u128::from_le_bytes(buffer);
        for (i, value) in group.iter_mut().enumerate() {
            *value = ((word >> (d * i)) & mask) as u16;
        }
    }
    values
}

/// `ByteEncode_12` (algorithm 5): the 384 bytes of a polynomial whose
/// coefficients are taken modulo `q`, for any coefficients.
pub(super) fn byte_encode(f: &Poly, out: &mut [u8]) {
    pack(&f.map(to_unsigned), 12, out);
}

/// `ByteDecode_12` (algorithm 6) of 384 bytes into `f`, with the "modulus check"
/// of section 7.2 on the way: the answer is whether every 12-bit number was
/// below `q`. With `false` the contents of `f` mean nothing.
///
/// It does not branch on the numbers, for the sake of simplicity and not
/// of secrecy: what it decodes is a public key.
pub(super) fn byte_decode(bytes: &[u8], f: &mut Poly) -> bool {
    let mut at_least_q = 0u16;
    for (c, value) in f.iter_mut().zip(unpack(bytes, 12)) {
        // The sign bit of `value - q`, as 0 (below q) or 1 (not).
        at_least_q |= (value.wrapping_sub(Q as u16) >> 15) ^ 1;
        *c = value as i16;
    }
    at_least_q == 0
}

/// `ByteEncode_d(Compress_d(f))` (algorithms 5 and definition 4.7) for `d` from
/// 1 to 11: the `32 * d` bytes of the coefficients of `f`, taken modulo `q` and
/// compressed.
#[inline(always)]
pub(super) fn compress_and_encode(f: &Poly, d: usize, out: &mut [u8]) {
    debug_assert!((1..12).contains(&d));
    let mut compressed = [0; N];
    for (c, &x) in compressed.iter_mut().zip(f) {
        *c = compress(to_unsigned(x), d);
    }
    pack(&compressed, d, out);
}

/// `Decompress_d(ByteDecode_d(bytes))` (algorithm 6 and definition 4.8) for `d`
/// from 1 to 11: the polynomial of `32 * d` bytes, with coefficients from 0 to
/// `q - 1`.
#[inline(always)]
pub(super) fn decode_and_decompress(bytes: &[u8], d: usize, f: &mut Poly) {
    debug_assert!((1..12).contains(&d));
    for (c, value) in f.iter_mut().zip(unpack(bytes, d)) {
        *c = decompress(value, d) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::Prng;
    use super::*;

    /// `Compress_d` as definition 4.7 has it, with an exact division: the
    /// closest integer to `2^d * x / q`, halves up.
    fn spec_compress(x: u32, d: usize) -> u32 {
        let (q, scaled) = (Q as u64, u64::from(x) << d);
        (((2 * scaled + q) / (2 * q)) % (1 << d)) as u32
    }

    /// `Decompress_d`, definition 4.8: the closest integer to `q * y / 2^d`.
    fn spec_decompress(y: u32, d: usize) -> u32 {
        ((2 * u64::from(y) * Q as u64 + (1 << d)) / (2 << d)) as u32
    }

    /// `ByteEncode_d` as algorithm 5 writes it: the bits of each number, least
    /// significant first, in one string, and then the bytes of that string
    /// (`BitsToBytes`, algorithm 3).
    fn spec_byte_encode(values: &[u16; N], d: usize) -> Vec<u8> {
        let mut bits = Vec::new();
        for &value in values {
            for j in 0..d {
                bits.push((value >> j) & 1);
            }
        }
        let mut bytes = vec![0u8; 32 * d];
        for (i, bit) in bits.iter().enumerate() {
            bytes[i / 8] |= (*bit as u8) << (i % 8);
        }
        bytes
    }

    /// `ByteDecode_d`, algorithm 6, from the bit string (`BytesToBits`,
    /// algorithm 4).
    fn spec_byte_decode(bytes: &[u8], d: usize) -> [u16; N] {
        let bit = |i: usize| (bytes[i / 8] >> (i % 8)) & 1;
        core::array::from_fn(|i| (0..d).map(|j| u16::from(bit(i * d + j)) << j).sum())
    }

    /// `Compress` and `Decompress` for every coefficient and every `d` the
    /// scheme uses, against the definitions with a true division.
    #[test]
    fn compress_and_decompress_match_their_definitions() {
        for d in [1, 4, 5, 10, 11] {
            for x in 0..Q as u32 {
                assert_eq!(
                    u32::from(compress(x as u16, d)),
                    spec_compress(x, d),
                    "compress {x} to {d} bits"
                );
            }
            for y in 0..1u32 << d {
                assert_eq!(
                    u32::from(decompress(y as u16, d)),
                    spec_decompress(y, d),
                    "decompress {y} from {d} bits"
                );
            }
        }
    }

    #[test]
    fn packing_matches_the_bit_strings_of_the_specification() {
        let mut prng = Prng(0xfeed);
        for d in [1, 4, 5, 10, 11, 12] {
            for round in 0..40 {
                let values: [u16; N] = match round {
                    0 => [0; N],
                    1 => [(1 << d) - 1; N],
                    _ => core::array::from_fn(|_| prng.below(1 << d) as u16),
                };
                let mut bytes = vec![0u8; 32 * d];
                pack(&values, d, &mut bytes);
                assert_eq!(bytes, spec_byte_encode(&values, d), "d {d}");
                assert_eq!(unpack(&bytes, d), values, "d {d}");
                assert_eq!(spec_byte_decode(&bytes, d), values, "d {d}");
            }
        }
    }

    /// A 12-bit number from `q` to 4095 is not a coefficient, wherever it is in
    /// the encoding (the modulus check of section 7.2).
    #[test]
    fn decoding_checks_the_modulus() {
        let mut f = [0; N];
        let mut bytes = [0u8; 384];

        // Every number that is too large, at the start, the middle and the end,
        // and at both parities of the pair that shares three bytes.
        for position in [0, 1, 2, 127, 128, 254, 255] {
            for value in Q as u16..4096 {
                let mut values = [1u16; N];
                values[position] = value;
                pack(&values, 12, &mut bytes);
                assert!(!byte_decode(&bytes, &mut f), "{value} at {position}");
            }
        }
        // And the largest number that is one, at every position.
        for position in 0..N {
            let mut values = [Q as u16 - 1; N];
            assert!({
                pack(&values, 12, &mut bytes);
                byte_decode(&bytes, &mut f)
            });
            values[position] = Q as u16;
            pack(&values, 12, &mut bytes);
            assert!(!byte_decode(&bytes, &mut f), "q at {position}");
        }
    }
}
