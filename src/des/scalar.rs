//! Plain, portable DES -- no CPU-specific instructions.
//!
//! No CPU this crate targets has a DES instruction, so this is the only
//! implementation: it runs everywhere, and it is the one the tests check
//! against the standard.
//!
//! DES is a Feistel network. The block goes through the initial permutation
//! `IP` and is split into halves `L` and `R`; sixteen times, `R` becomes
//! `L ^ f(R, K)` and the halves change places; the halves are put back
//! together, swapped, and go through `IP` inverted (FIPS 46-3, "Enciphering").
//! Everything that makes it slow in software is in the cipher function `f`,
//! which expands `R` to 48 bits (`E`), adds the round key, passes six-bit
//! groups through eight S-boxes, and permutes the 32 bits that come out (`P`).
//!
//! Bit by bit that would be hundreds of operations a round, so the three steps
//! that are only movements of bits are folded into the rest:
//!
//! - `E` is eight overlapping windows of six bits of `R`, each starting four
//!   bits after the last, the first one wrapping around the end. Rotating `R`
//!   right by 3 puts windows 0, 2, 4 and 6 on a byte boundary each, and
//!   rotating it right by 7 does the same for 1, 3, 5 and 7, so two rotations
//!   and eight shifts and masks take the windows out. The round key is added to
//!   the rotated words as they are, as two words, see `RoundKey`.
//! - `P` is applied to the output of each S-box separately, in the tables
//!   `SP`, so the S-boxes and `P` together are eight lookups in tables of 64
//!   entries.
//! - `IP` and its inverse are five exchanges of pairs of bits each, with no
//!   table. See `initial_permutation`.
//!
//! A round is then two rotations, two XORs with the key, eight lookups and
//! eight XORs.
//!
//! Triple DES is three of these in a row, and `FP(IP(x)) = x`, so between two
//! of them the inverse permutation of one and the initial permutation of the
//! next cancel. `encrypt3` and `decrypt3` skip both: only the very first and the
//! very last permutation are done.
//!
//! The lookups are indexed by bits of the state, which depend on the key and the
//! message. The time they take depends on what the CPU has cached, and that
//! leaks (see the Security section of the module documentation). The tables are
//! 2 KiB in all, but that does not remove the problem, only shrinks it.

use super::schedule::{RoundKey, Schedule};
use super::tables::SP;

/// The cipher function `f(R, K)` (FIPS 46-3, "The Cipher Function f").
#[inline(always)]
fn f(r: u32, key: &RoundKey) -> u32 {
    // Window `i` of `E(R)`, for `i` = 0 to 7, is the six bits of `R` that start
    // at bit `4 * i` in the standard's numbering, which counts from 1 at the
    // top and wraps around: window 0 is bits 32, 1, 2, 3, 4 and 5, and window 7
    // is bits 28 to 32 and 1. After `rotate_right(3)`, windows 0, 2, 4 and 6 are
    // the low six bits of the top, second, third and bottom byte of the word;
    // after `rotate_right(7)`, windows 1, 3, 5 and 7 are those of the second,
    // third, bottom and top byte.
    let a = r.rotate_right(3) ^ key[0];
    let b = r.rotate_right(7) ^ key[1];

    SP[0][(a >> 24) as usize & 63]
        ^ SP[2][(a >> 16) as usize & 63]
        ^ SP[4][(a >> 8) as usize & 63]
        ^ SP[6][a as usize & 63]
        ^ SP[1][(b >> 16) as usize & 63]
        ^ SP[3][(b >> 8) as usize & 63]
        ^ SP[5][b as usize & 63]
        ^ SP[7][(b >> 24) as usize & 63]
}

/// The sixteen rounds, from `(L0, R0)` to `(L16, R16)`. Encryption takes the
/// round keys in order, decryption in reverse (FIPS 46-3, "Deciphering").
///
/// The rounds go two at a time. In the standard each round swaps the halves; here
/// the first round of a pair updates `l` from `r`, the second `r` from `l`, and
/// the halves are back in place after both.
#[inline(always)]
fn rounds<const DECRYPT: bool>(mut l: u32, mut r: u32, keys: &[RoundKey; 16]) -> (u32, u32) {
    for pair in 0..8 {
        let (first, second) = if DECRYPT {
            (&keys[15 - 2 * pair], &keys[14 - 2 * pair])
        } else {
            (&keys[2 * pair], &keys[2 * pair + 1])
        };
        l ^= f(r, first);
        r ^= f(l, second);
    }
    (l, r)
}

/// The five exchanges `IP` is made of, as a mask and a shift: for every set bit
/// `i` of the mask, bits `i` and `i + shift` of the word trade places.
///
/// `IP` moves the bit at position `p` of the 64-bit block (counting from 0 at
/// the least significant end) to a position whose six bits are some of the six
/// bits of `p`, rearranged. Any such rearrangement is a product of exchanges of
/// two of those six bits, and each exchange is a "delta swap": all the pairs of
/// positions that differ in exactly those two bits swap, in one go. Five are
/// enough here, once the block is read with its first byte as the least
/// significant (`from_le_bytes`), which takes care of the byte order for free.
const EXCHANGES: [(u64, u32); 5] = [
    (0x2222_2222_2222_2222, 1),
    (0x00aa_00aa_00aa_00aa, 7),
    (0x0c0c_0c0c_0c0c_0c0c, 2),
    (0x0000_cccc_0000_cccc, 14),
    (0x0000_0000_f0f0_f0f0, 28),
];

/// Trades the bit pairs of one exchange in `x`.
#[inline(always)]
fn exchange(x: u64, mask: u64, shift: u32) -> u64 {
    let t = ((x >> shift) ^ x) & mask;
    x ^ t ^ (t << shift)
}

/// The initial permutation `IP` of a block, returned as the halves `(L0, R0)`.
#[inline(always)]
fn initial_permutation(block: &[u8; 8]) -> (u32, u32) {
    let mut x = u64::from_le_bytes(*block);
    for (mask, shift) in EXCHANGES {
        x = exchange(x, mask, shift);
    }
    // With the block read this way, `IP` puts `L0` in the low word and `R0` in
    // the high one.
    (x as u32, (x >> 32) as u32)
}

/// The inverse of `IP` applied to the halves `(L16, R16)`, which is what the
/// standard writes as `IP^-1(R16 L16)`: the preoutput block has the halves the
/// other way round, and the exchanges of `IP`, undone in reverse order, expect
/// the same swap.
#[inline(always)]
fn final_permutation(l: u32, r: u32) -> [u8; 8] {
    let mut x = u64::from(l) << 32 | u64::from(r);
    for (mask, shift) in EXCHANGES.into_iter().rev() {
        x = exchange(x, mask, shift);
    }
    x.to_le_bytes()
}

/// Encrypts one block (`DES` in FIPS 46-3 notation: `E_K`).
pub(super) fn encrypt(schedule: &Schedule, block: &[u8; 8]) -> [u8; 8] {
    let (l, r) = initial_permutation(block);
    let (l, r) = rounds::<false>(l, r, &schedule.keys);
    final_permutation(l, r)
}

/// Decrypts one block (`D_K`).
pub(super) fn decrypt(schedule: &Schedule, block: &[u8; 8]) -> [u8; 8] {
    let (l, r) = initial_permutation(block);
    let (l, r) = rounds::<true>(l, r, &schedule.keys);
    final_permutation(l, r)
}

/// The TDEA encryption operation, `E_K3(D_K2(E_K1(block)))`.
///
/// Each stage after the first starts from the halves the one before ended with,
/// exchanged: that is what `IP(IP^-1(R16 L16))` leaves.
pub(super) fn encrypt3(schedules: &[Schedule; 3], block: &[u8; 8]) -> [u8; 8] {
    let (l, r) = initial_permutation(block);
    let (l, r) = rounds::<false>(l, r, &schedules[0].keys);
    let (l, r) = rounds::<true>(r, l, &schedules[1].keys);
    let (l, r) = rounds::<false>(r, l, &schedules[2].keys);
    final_permutation(l, r)
}

/// The TDEA decryption operation, `D_K1(E_K2(D_K3(block)))`.
pub(super) fn decrypt3(schedules: &[Schedule; 3], block: &[u8; 8]) -> [u8; 8] {
    let (l, r) = initial_permutation(block);
    let (l, r) = rounds::<true>(l, r, &schedules[2].keys);
    let (l, r) = rounds::<false>(r, l, &schedules[1].keys);
    let (l, r) = rounds::<true>(r, l, &schedules[0].keys);
    final_permutation(l, r)
}
