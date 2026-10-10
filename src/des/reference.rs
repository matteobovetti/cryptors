//! A deliberately naive DES, for the tests to check the real one against.
//!
//! It is written as the text of FIPS 46-3 reads: a block is a vector of bits,
//! every permutation is "take bit `p` of the input as the next bit of the
//! output", and nothing is folded into anything else. It shares with the real
//! implementation only the tables of the standard that the real one also reads
//! (`S`, `P`, `PC1`, `PC2` and the shifts); the permutations `IP` and `IP^-1`
//! and the expansion `E`, which the real one replaces by other means, are
//! tables here.

use super::schedule::RoundKey;
use super::tables::{P, PC1, PC2, S, SHIFTS};

#[rustfmt::skip]
/// The initial permutation `IP`.
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
];

#[rustfmt::skip]
/// Its inverse, `IP^-1`.
const FP: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
];

#[rustfmt::skip]
/// The expansion `E`: the bit-selection table.
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
];

/// Bits, the first bit of the standard first: each element is 0 or 1.
type Bits = Vec<u8>;

/// The bits of `bytes`, most significant bit of each byte first.
fn bits(bytes: &[u8]) -> Bits {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
        .collect()
}

/// The bytes that `bits` (a multiple of eight of them) spell out.
fn bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| chunk.iter().fold(0, |byte, bit| byte << 1 | bit))
        .collect()
}

/// A permutation or selection table of the standard, as the standard words it:
/// the first bit of the output is bit `table[0]` of the input, and so on.
fn permute(input: &[u8], table: &[u8]) -> Bits {
    table.iter().map(|&p| input[usize::from(p) - 1]).collect()
}

fn xor(a: &[u8], b: &[u8]) -> Bits {
    a.iter().zip(b).map(|(a, b)| a ^ b).collect()
}

/// The sixteen round keys `K1` to `K16` of `key`, 48 bits each (`KS`).
pub(super) fn subkeys(key: &[u8; 8]) -> Vec<Bits> {
    let cd = permute(&bits(key), &PC1);
    let (mut c, mut d) = (cd[..28].to_vec(), cd[28..].to_vec());
    SHIFTS
        .iter()
        .map(|&shift| {
            c.rotate_left(usize::from(shift));
            d.rotate_left(usize::from(shift));
            permute(&[c.as_slice(), d.as_slice()].concat(), &PC2)
        })
        .collect()
}

/// The 48 bits of a round key as the real implementation stores them.
pub(super) fn unpack(key: &RoundKey) -> Bits {
    // Group `i` (0 for `B1`) is in this byte of the first or second word.
    let group = |i: usize| {
        let (word, byte) = if i.is_multiple_of(2) {
            (key[0], 3 - i / 2)
        } else {
            (key[1], if i == 7 { 3 } else { 2 - i / 2 })
        };
        (word >> (8 * byte)) & 0xff
    };
    (0..8)
        .flat_map(|i| (0..6).rev().map(move |bit| ((group(i) >> bit) & 1) as u8))
        .collect()
}

/// The cipher function `f(R, K)`.
fn f(r: &[u8], k: &[u8]) -> Bits {
    // `K ^ E(R)` as the eight groups `B1` to `B8` of six bits.
    let b = xor(k, &permute(r, &E));
    let mut out = Vec::new();
    for (i, group) in b.chunks(6).enumerate() {
        // The first and last bit give the row, the four between them the column.
        let row = usize::from(group[0]) << 1 | usize::from(group[5]);
        let column = group[1..5]
            .iter()
            .fold(0, |n, &bit| n << 1 | usize::from(bit));
        let value = S[i][row * 16 + column];
        out.extend((0..4).rev().map(|j| (value >> j) & 1));
    }
    permute(&out, &P)
}

/// Encrypts (or decrypts) one block with the round keys from `subkeys`.
pub(super) fn crypt(block: &[u8; 8], subkeys: &[Bits], decrypt: bool) -> [u8; 8] {
    let permuted = permute(&bits(block), &IP);
    let (mut l, mut r) = (permuted[..32].to_vec(), permuted[32..].to_vec());
    for n in 0..16 {
        let k = if decrypt {
            &subkeys[15 - n]
        } else {
            &subkeys[n]
        };
        let next = xor(&l, &f(&r, k));
        l = r;
        r = next;
    }
    // The preoutput block is `R16 L16`.
    let preoutput = [r, l].concat();
    bytes(&permute(&preoutput, &FP)).try_into().unwrap()
}
