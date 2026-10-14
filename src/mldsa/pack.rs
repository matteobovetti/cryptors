//! The encodings of FIPS 204, section 7.1 (algorithms 16 to 28): polynomials as
//! strings of bits packed least significant bit first, and the hint.
//!
//! A polynomial of 256 coefficients of `w` bits takes `32 * w` bytes. The
//! packers take the values already shifted into `[0, 2^w)`, as the algorithms
//! write them (`b - coefficient`), and the unpackers give those values back;
//! the callers undo the shift.

use super::field::N;
use super::field::Poly;
use super::params::MAX_K;
use super::params::sealed::Sealed;

/// Writes the low `W` bits of each of 256 values into `out`, which is `32 * W`
/// bytes, the first value in the lowest bits of the first byte.
#[inline(always)]
fn pack_bits<const W: u32>(out: &mut [u8], values: impl Iterator<Item = u32>) {
    debug_assert_eq!(out.len(), 32 * W as usize);
    let mut acc = 0u64;
    let mut bits = 0;
    let mut position = 0;
    for value in values {
        debug_assert!(value < 1 << W);
        acc |= u64::from(value) << bits;
        bits += W;
        while bits >= 8 {
            out[position] = acc as u8;
            position += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    debug_assert_eq!(position, out.len());
}

/// The 256 values of `W` bits in `bytes`, which is `32 * W` bytes, in the
/// order `pack_bits` wrote them.
#[inline(always)]
fn unpack_bits<const W: u32>(bytes: &[u8]) -> [u32; N] {
    debug_assert_eq!(bytes.len(), 32 * W as usize);
    let mut values = [0; N];
    let mut acc = 0u64;
    let mut bits = 0;
    let mut input = bytes.iter();
    for value in &mut values {
        while bits < W {
            acc |= u64::from(*input.next().unwrap()) << bits;
            bits += 8;
        }
        *value = (acc & ((1 << W) - 1)) as u32;
        acc >>= W;
        bits -= W;
    }
    values
}

/// `SimpleBitPack(t1, 2^10 - 1)` (algorithm 16): 10 bits per coefficient, for
/// coefficients in `[0, 2^10)`. 320 bytes.
pub(super) fn pack_t1(out: &mut [u8], t1: &Poly) {
    pack_bits::<10>(out, t1.iter().map(|&c| c as u32));
}

/// `SimpleBitUnpack(v, 2^10 - 1)` (algorithm 18).
pub(super) fn unpack_t1(bytes: &[u8]) -> Poly {
    unpack_bits::<10>(bytes).map(|v| v as i32)
}

/// `BitPack(z, gamma1 - 1, gamma1)` (algorithm 17): `gamma1 - z` in 18 or 20
/// bits, for `z` in `[-gamma1 + 1, gamma1]`.
pub(super) fn pack_z<P: Sealed>(out: &mut [u8], z: &Poly) {
    if P::GAMMA1_BITS == 17 {
        pack_bits::<18>(out, z.iter().map(|&c| (P::GAMMA1 - c) as u32));
    } else {
        pack_bits::<20>(out, z.iter().map(|&c| (P::GAMMA1 - c) as u32));
    }
}

/// `BitUnpack(v, gamma1 - 1, gamma1)` (algorithm 19), in `[-gamma1 + 1,
/// gamma1]`. Every string of the right length is valid.
pub(super) fn unpack_z<P: Sealed>(bytes: &[u8]) -> Poly {
    if P::GAMMA1_BITS == 17 {
        unpack_bits::<18>(bytes).map(|v| P::GAMMA1 - v as i32)
    } else {
        unpack_bits::<20>(bytes).map(|v| P::GAMMA1 - v as i32)
    }
}

/// `w1Encode` (algorithm 28): 6 bits per coefficient for `gamma2 = (q - 1) / 88`
/// and 4 for `(q - 1) / 32`, for coefficients in `[0, 44)` and `[0, 16)`.
pub(super) fn pack_w1<P: Sealed>(out: &mut [u8], w1: &Poly) {
    if P::W1_LEN == 192 {
        pack_bits::<6>(out, w1.iter().map(|&c| c as u32));
    } else {
        pack_bits::<4>(out, w1.iter().map(|&c| c as u32));
    }
}

#[cfg(test)]
/// The bytes of a packed polynomial of `s1` or `s2`: 3 bits per coefficient
/// for `eta = 2` and 4 for `eta = 4`.
pub(super) const fn eta_len<P: Sealed>() -> usize {
    if P::ETA == 2 { 96 } else { 128 }
}

#[cfg(test)]
/// `BitPack(s, eta, eta)` (algorithm 17): `eta - s`, for `s` in `[-eta, eta]`.
pub(super) fn pack_eta<P: Sealed>(out: &mut [u8], s: &Poly) {
    if P::ETA == 2 {
        pack_bits::<3>(out, s.iter().map(|&c| (P::ETA - c) as u32));
    } else {
        pack_bits::<4>(out, s.iter().map(|&c| (P::ETA - c) as u32));
    }
}

#[cfg(test)]
/// `BitUnpack(v, eta, eta)` (algorithm 19), or `None` for a string with a
/// value that is not `eta - s` for any `s` in `[-eta, eta]`: 5 to 7 for
/// `eta = 2` and 9 to 15 for `eta = 4`.
pub(super) fn unpack_eta<P: Sealed>(bytes: &[u8]) -> Option<Poly> {
    let values = if P::ETA == 2 {
        unpack_bits::<3>(bytes)
    } else {
        unpack_bits::<4>(bytes)
    };
    let mut s = [0; N];
    for (out, v) in s.iter_mut().zip(values) {
        if v > 2 * P::ETA as u32 {
            return None;
        }
        *out = P::ETA - v as i32;
    }
    Some(s)
}

#[cfg(test)]
/// Bytes of a packed polynomial of `t0`: 13 bits per coefficient.
pub(super) const T0_LEN: usize = 416;

#[cfg(test)]
/// `BitPack(t0, 2^12 - 1, 2^12)` (algorithm 17): `2^12 - t0`, for `t0` in
/// `(-2^12, 2^12]`.
pub(super) fn pack_t0(out: &mut [u8], t0: &Poly) {
    pack_bits::<13>(out, t0.iter().map(|&c| ((1 << 12) - c) as u32));
}

#[cfg(test)]
/// `BitUnpack(v, 2^12 - 1, 2^12)` (algorithm 19). Every string is valid.
pub(super) fn unpack_t0(bytes: &[u8]) -> Poly {
    unpack_bits::<13>(bytes).map(|v| (1 << 12) - v as i32)
}

/// The hint of a signature: for each of the `k` polynomials, which of its 256
/// coefficients carry a one.
pub(super) type Hint = [[bool; N]; MAX_K];

/// `HintBitPack` (algorithm 20): the indices of the ones of each polynomial in
/// order, then the running count after each polynomial. `omega + k` bytes. The
/// caller has checked that there are at most `omega` ones in all.
pub(super) fn pack_hint<P: Sealed>(out: &mut [u8], hint: &Hint) {
    debug_assert_eq!(out.len(), P::HINT_LEN);
    out.fill(0);
    let mut index = 0;
    for (i, poly) in hint[..P::K].iter().enumerate() {
        for (j, &one) in poly.iter().enumerate() {
            if one {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[P::OMEGA + i] = index as u8;
    }
}

/// `HintBitUnpack` (algorithm 21), or `None` for an encoding that no signer
/// writes: a running count that falls or goes past `omega`, indices of a
/// polynomial that do not increase, or a byte that is not zero among the
/// unused ones. Accepting any of them would give one signature several
/// encodings.
pub(super) fn unpack_hint<P: Sealed>(bytes: &[u8]) -> Option<Hint> {
    debug_assert_eq!(bytes.len(), P::HINT_LEN);
    let mut hint = [[false; N]; MAX_K];
    let mut index = 0;
    for (i, poly) in hint[..P::K].iter_mut().enumerate() {
        let end = usize::from(bytes[P::OMEGA + i]);
        if end < index || end > P::OMEGA {
            return None;
        }
        let first = index;
        while index < end {
            // Increasing, so that a polynomial's set of indices has one order.
            if index > first && bytes[index - 1] >= bytes[index] {
                return None;
            }
            poly[usize::from(bytes[index])] = true;
            index += 1;
        }
    }
    // The unused indices are zero.
    if bytes[index..P::OMEGA].iter().any(|&b| b != 0) {
        return None;
    }
    Some(hint)
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlDsa44, MlDsa65, MlDsa87};
    use super::super::testutil::Prng;
    use super::*;

    fn random_poly(prng: &mut Prng, low: i32, high: i32) -> Poly {
        core::array::from_fn(|_| low + (prng.next() % (high - low + 1) as u64) as i32)
    }

    #[test]
    fn bit_packing_round_trips_for_every_width() {
        let mut prng = Prng(5);
        macro_rules! round_trip {
            ($w:literal) => {
                let values: [u32; N] = core::array::from_fn(|_| (prng.next() % (1 << $w)) as u32);
                let mut bytes = [0u8; 32 * $w];
                pack_bits::<$w>(&mut bytes, values.iter().copied());
                assert_eq!(unpack_bits::<$w>(&bytes), values, "width {}", $w);
                // The extremes.
                for fill in [0, (1u32 << $w) - 1] {
                    let values = [fill; N];
                    pack_bits::<$w>(&mut bytes, values.iter().copied());
                    assert_eq!(unpack_bits::<$w>(&bytes), values);
                }
            };
        }
        round_trip!(3);
        round_trip!(4);
        round_trip!(6);
        round_trip!(10);
        round_trip!(13);
        round_trip!(18);
        round_trip!(20);
    }

    /// The first bytes of a packing, by hand: the first value is in the lowest
    /// bits of the first byte, and a value that straddles a byte continues in
    /// the next one.
    #[test]
    fn bit_order_is_least_significant_first() {
        let mut values = [0u32; N];
        values[0] = 0b11_0101_0101;
        values[1] = 0b10_0000_0001;
        let mut bytes = [0u8; 320];
        pack_bits::<10>(&mut bytes, values.iter().copied());
        // values[0]: bits 0..10, values[1]: bits 10..20.
        assert_eq!(bytes[0], 0b0101_0101);
        assert_eq!(bytes[1], 0b0000_0011 | (0b01 << 2));
        assert_eq!(bytes[2], 0b0000_1000);
        assert_eq!(&bytes[3..], &[0; 317][..]);
    }

    #[test]
    fn t1_t0_z_round_trip() {
        let mut prng = Prng(9);
        let t1 = random_poly(&mut prng, 0, 1023);
        let mut bytes = [0u8; 320];
        pack_t1(&mut bytes, &t1);
        assert_eq!(unpack_t1(&bytes), t1);

        let t0 = random_poly(&mut prng, -(1 << 12) + 1, 1 << 12);
        let mut bytes = [0u8; T0_LEN];
        pack_t0(&mut bytes, &t0);
        assert_eq!(unpack_t0(&bytes), t0);

        let z = random_poly(&mut prng, -(1 << 17) + 1, 1 << 17);
        let mut bytes = [0u8; 576];
        pack_z::<MlDsa44>(&mut bytes, &z);
        assert_eq!(unpack_z::<MlDsa44>(&bytes), z);
        let z = random_poly(&mut prng, -(1 << 19) + 1, 1 << 19);
        let mut bytes = [0u8; 640];
        pack_z::<MlDsa65>(&mut bytes, &z);
        assert_eq!(unpack_z::<MlDsa65>(&bytes), z);
        pack_z::<MlDsa87>(&mut bytes, &z);
        assert_eq!(unpack_z::<MlDsa87>(&bytes), z);
    }

    #[test]
    fn eta_round_trips_and_refuses_values_out_of_range() {
        let mut prng = Prng(21);
        let s = random_poly(&mut prng, -2, 2);
        let mut bytes = [0u8; 96];
        pack_eta::<MlDsa44>(&mut bytes, &s);
        assert_eq!(unpack_eta::<MlDsa44>(&bytes), Some(s));
        // 5, 6 and 7 are three-bit values that no coefficient has.
        for bad in 5..8u8 {
            let mut broken = bytes;
            broken[0] = (broken[0] & !0b111) | bad;
            assert_eq!(unpack_eta::<MlDsa44>(&broken), None, "{bad}");
        }

        let s = random_poly(&mut prng, -4, 4);
        let mut bytes = [0u8; 128];
        pack_eta::<MlDsa65>(&mut bytes, &s);
        assert_eq!(unpack_eta::<MlDsa65>(&bytes), Some(s));
        for bad in 9..16u8 {
            let mut broken = bytes;
            broken[5] = (broken[5] & !0b1111) | bad;
            assert_eq!(unpack_eta::<MlDsa65>(&broken), None, "{bad}");
        }
        assert_eq!(eta_len::<MlDsa44>(), 96);
        assert_eq!(eta_len::<MlDsa65>(), 128);
    }

    fn hint_from(positions: &[&[usize]]) -> Hint {
        let mut hint = [[false; N]; MAX_K];
        for (i, indices) in positions.iter().enumerate() {
            for &j in *indices {
                hint[i][j] = true;
            }
        }
        hint
    }

    #[test]
    fn hint_round_trips() {
        let hint = hint_from(&[&[0, 3, 255], &[], &[1], &[7, 8, 100, 254]]);
        let mut bytes = [0u8; MlDsa44::HINT_LEN];
        pack_hint::<MlDsa44>(&mut bytes, &hint);
        assert_eq!(&bytes[..8], &[0, 3, 255, 1, 7, 8, 100, 254]);
        assert_eq!(&bytes[80..], &[3, 3, 4, 8]);
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), Some(hint));

        // No hints at all, and the most there can be.
        let none = [[false; N]; MAX_K];
        pack_hint::<MlDsa44>(&mut bytes, &none);
        assert_eq!(bytes, [0; 84]);
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), Some(none));
        let indices: Vec<usize> = (0..80).collect();
        let full = hint_from(&[
            &indices[..20],
            &indices[20..40],
            &indices[40..60],
            &indices[60..],
        ]);
        pack_hint::<MlDsa44>(&mut bytes, &full);
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), Some(full));
    }

    #[test]
    fn hint_refuses_every_encoding_that_is_not_canonical() {
        let hint = hint_from(&[&[5, 9], &[3]]);
        let mut good = [0u8; MlDsa44::HINT_LEN];
        pack_hint::<MlDsa44>(&mut good, &hint);
        assert!(unpack_hint::<MlDsa44>(&good).is_some());

        // Indices that do not increase, or repeat, within a polynomial.
        let mut bytes = good;
        bytes.swap(0, 1);
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        let mut bytes = good;
        bytes[1] = 5;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        // A count that falls, or goes past omega.
        let mut bytes = good;
        bytes[81] = 1;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        let mut bytes = good;
        bytes[83] = 81;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        // A count past omega, with indices that do increase and counts that do
        // not fall, so that this is the only rule it breaks: omega ones in the
        // first polynomial, and a last count of omega + 1.
        let mut bytes = [0u8; MlDsa44::HINT_LEN];
        for (i, byte) in bytes[..80].iter_mut().enumerate() {
            *byte = i as u8;
        }
        bytes[80..].copy_from_slice(&[80, 80, 80, 80]);
        assert!(unpack_hint::<MlDsa44>(&bytes).is_some());
        bytes[83] = 81;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        // A nonzero byte among the unused indices.
        let mut bytes = good;
        bytes[3] = 1;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        let mut bytes = good;
        bytes[79] = 200;
        assert_eq!(unpack_hint::<MlDsa44>(&bytes), None);
        // Indices of a later polynomial may start lower than an earlier one's.
        let mut bytes = [0u8; MlDsa44::HINT_LEN];
        bytes[0] = 9;
        bytes[1] = 2;
        bytes[80..].copy_from_slice(&[1, 2, 2, 2]);
        assert!(unpack_hint::<MlDsa44>(&bytes).is_some());
    }
}
