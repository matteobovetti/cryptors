//! Plain, portable AES -- no CPU-specific instructions.
//!
//! This is the trusted reference implementation: it runs on any CPU, and the
//! hardware backends are checked against it by the `matches_scalar_backend`
//! test in the cipher module.
//!
//! A round of AES is SubBytes, ShiftRows, MixColumns and AddRoundKey
//! (FIPS 197 section 5.1). Done one step at a time that is a lot of byte
//! shuffling, so this implementation uses the table-lookup form that the
//! designers of Rijndael describe for 32-bit processors: SubBytes and
//! MixColumns together act on each byte of a column independently, and the
//! column is the XOR of the contributions. `TE[r]` is a table of 256 words
//! that holds what a byte contributes when it comes from row `r` of its
//! column. The four tables are the same word rotated by 0 to 3 bytes; keeping
//! all four, instead of one table and a rotate after each lookup, takes 3 KiB
//! more memory per direction and twelve rotates out of every round, and the
//! rotates sit on the path each round waits on. A round then costs 16 table lookups and a
//! few XORs. Decryption is the same with the inverse tables (`TD`), using the
//! equivalent inverse cipher of section 5.3.5 so that its rounds have the same
//! shape.
//!
//! The S-box and the tables are computed when the crate is compiled, from the
//! definitions in the standard, so no table is typed in by hand.
//!
//! The lookups are indexed by the state, which depends on the key and the
//! message. The time they take depends on what the CPU has cached, and that
//! leaks. The hardware backends have no such lookups; this one is the fallback
//! for CPUs that have none of them.

use super::schedule::{Schedule, inverse_keys, key_expansion};

/// Multiplication by `x` in GF(2^8), the field whose elements are the bytes
/// (FIPS 197 section 4.2, `XTIMES()`): shift left, and if a bit fell off the
/// top, XOR in the reduction polynomial `x^8 + x^4 + x^3 + x + 1` (`0x1b`).
const fn xtime(a: u8) -> u8 {
    (a << 1) ^ (0x1b * (a >> 7))
}

/// Multiplication in GF(2^8) (section 4.2): the sum of `a * x^i` over the set
/// bits `i` of `b`.
const fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    product
}

/// The S-box (section 5.1.1): the multiplicative inverse in GF(2^8), with `0`
/// mapped to `0`, followed by the affine transformation of that section, which
/// is `b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63` on the
/// byte as a whole.
const fn build_sbox() -> [u8; 256] {
    // `3` generates the multiplicative group, so its powers visit every
    // non-zero byte once. With the powers and their logarithms, the inverse of
    // `3^i` is `3^(255 - i)`.
    let mut exp = [0u8; 255];
    let mut log = [0u8; 256];
    let mut power = 1u8;
    let mut i = 0;
    while i < 255 {
        exp[i] = power;
        log[power as usize] = i as u8;
        power ^= xtime(power); // times 3 = times x, plus once itself
        i += 1;
    }

    let mut sbox = [0u8; 256];
    let mut a = 0;
    while a < 256 {
        let inverse = if a == 0 {
            0
        } else {
            exp[(255 - log[a] as usize) % 255]
        };
        sbox[a] = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
        a += 1;
    }
    sbox
}

/// The inverse S-box (section 5.3.2): the table of `SBOX` read backwards.
const fn build_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inverse[sbox[i] as usize] = i as u8;
        i += 1;
    }
    inverse
}

/// What a byte `x` from row `r` of a column adds to the column after SubBytes
/// and MixColumns, for `r` = 0 to 3: `S[x]` times column `r` of the MixColumns
/// matrix. Column 0 is `2, 1, 1, 3`, and each next column is the one before it
/// moved down a row, which on a word stored as the column's four bytes read
/// little-endian, like everything else in this file, is a rotate left by 8
/// bits.
const fn build_te(sbox: &[u8; 256]) -> [[u32; 256]; 4] {
    let mut te = [[0u32; 256]; 4];
    let mut x = 0;
    while x < 256 {
        let s = sbox[x];
        let word = u32::from_le_bytes([mul(s, 2), s, s, mul(s, 3)]);
        let mut row = 0;
        while row < 4 {
            te[row][x] = word.rotate_left(8 * row as u32);
            row += 1;
        }
        x += 1;
    }
    te
}

/// The same for decryption: `InvS[x]` times column `r` of the InvMixColumns
/// matrix, whose first column is `14, 9, 13, 11`.
const fn build_td(inv_sbox: &[u8; 256]) -> [[u32; 256]; 4] {
    let mut td = [[0u32; 256]; 4];
    let mut x = 0;
    while x < 256 {
        let s = inv_sbox[x];
        let word = u32::from_le_bytes([mul(s, 14), mul(s, 9), mul(s, 13), mul(s, 11)]);
        let mut row = 0;
        while row < 4 {
            td[row][x] = word.rotate_left(8 * row as u32);
            row += 1;
        }
        x += 1;
    }
    td
}

pub(super) static SBOX: [u8; 256] = build_sbox();
pub(super) static INV_SBOX: [u8; 256] = build_inv_sbox(&SBOX);
static TE: [[u32; 256]; 4] = build_te(&SBOX);
static TD: [[u32; 256]; 4] = build_td(&INV_SBOX);

/// Byte `i` of `word` (0 is the least significant), as a table index.
#[inline(always)]
fn byte(word: u32, i: u32) -> usize {
    usize::from((word >> (8 * i)) as u8)
}

/// The four columns of a block or round key, each as a little-endian word.
#[inline(always)]
fn columns(block: &[u8; 16]) -> [u32; 4] {
    let mut cols = [0u32; 4];
    for (col, bytes) in cols.iter_mut().zip(block.as_chunks::<4>().0) {
        *col = u32::from_le_bytes(*bytes);
    }
    cols
}

/// The inverse of `columns`.
#[inline(always)]
fn to_bytes(cols: [u32; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    for (bytes, col) in block.as_chunks_mut::<4>().0.iter_mut().zip(cols) {
        *bytes = col.to_le_bytes();
    }
    block
}

/// One column after SubBytes, ShiftRows and MixColumns, given the four columns
/// its bytes come from. ShiftRows takes the byte of row `r` from the column `r`
/// places to the right, so the caller passes the columns in that order, rotated
/// to start at the column being computed.
#[inline(always)]
fn te_column(c0: u32, c1: u32, c2: u32, c3: u32) -> u32 {
    TE[0][byte(c0, 0)] ^ TE[1][byte(c1, 1)] ^ TE[2][byte(c2, 2)] ^ TE[3][byte(c3, 3)]
}

/// One column after InvSubBytes, InvShiftRows and InvMixColumns. InvShiftRows
/// takes the byte of row `r` from the column `r` places to the left.
#[inline(always)]
fn td_column(c0: u32, c1: u32, c2: u32, c3: u32) -> u32 {
    TD[0][byte(c0, 0)] ^ TD[1][byte(c1, 1)] ^ TD[2][byte(c2, 2)] ^ TD[3][byte(c3, 3)]
}

/// One column after the S-box and ShiftRows alone, for the last round, which
/// has no MixColumns.
#[inline(always)]
fn sub_column(sbox: &[u8; 256], c0: u32, c1: u32, c2: u32, c3: u32) -> u32 {
    u32::from_le_bytes([
        sbox[byte(c0, 0)],
        sbox[byte(c1, 1)],
        sbox[byte(c2, 2)],
        sbox[byte(c3, 3)],
    ])
}

/// `SubWord()` (section 5.2): the S-box applied to each byte of a word.
fn sub_word(word: u32) -> u32 {
    u32::from_le_bytes(word.to_le_bytes().map(|b| SBOX[usize::from(b)]))
}

/// `InvMixColumns()` on a round key. `TD` already includes the inverse S-box,
/// so the S-box is applied first to cancel it.
fn inv_mix_columns(key: &[u8; 16]) -> [u8; 16] {
    let mix = |c: u32| {
        TD[0][usize::from(SBOX[byte(c, 0)])]
            ^ TD[1][usize::from(SBOX[byte(c, 1)])]
            ^ TD[2][usize::from(SBOX[byte(c, 2)])]
            ^ TD[3][usize::from(SBOX[byte(c, 3)])]
    };
    to_bytes(columns(key).map(mix))
}

/// Expands `key` into the round keys of both directions.
pub(super) fn expand_key<const K: usize, const N: usize>(key: &[u8; K]) -> Schedule<N> {
    let enc = key_expansion::<K, N>(key, sub_word);
    let dec = inverse_keys(&enc, inv_mix_columns);
    Schedule { enc, dec }
}

/// Encrypts one block with the round keys `keys` (`Cipher()`, section 5.1).
pub(super) fn encrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let k = columns(&keys[0]);
    let b = columns(block);
    let mut s = [b[0] ^ k[0], b[1] ^ k[1], b[2] ^ k[2], b[3] ^ k[3]];

    for key in &keys[1..N - 1] {
        let k = columns(key);
        s = [
            te_column(s[0], s[1], s[2], s[3]) ^ k[0],
            te_column(s[1], s[2], s[3], s[0]) ^ k[1],
            te_column(s[2], s[3], s[0], s[1]) ^ k[2],
            te_column(s[3], s[0], s[1], s[2]) ^ k[3],
        ];
    }

    let k = columns(&keys[N - 1]);
    to_bytes([
        sub_column(&SBOX, s[0], s[1], s[2], s[3]) ^ k[0],
        sub_column(&SBOX, s[1], s[2], s[3], s[0]) ^ k[1],
        sub_column(&SBOX, s[2], s[3], s[0], s[1]) ^ k[2],
        sub_column(&SBOX, s[3], s[0], s[1], s[2]) ^ k[3],
    ])
}

/// Decrypts one block with the round keys `keys` of the equivalent inverse
/// cipher (`EqInvCipher()`, section 5.3.5).
pub(super) fn decrypt<const N: usize>(keys: &[[u8; 16]; N], block: &[u8; 16]) -> [u8; 16] {
    let k = columns(&keys[0]);
    let b = columns(block);
    let mut s = [b[0] ^ k[0], b[1] ^ k[1], b[2] ^ k[2], b[3] ^ k[3]];

    for key in &keys[1..N - 1] {
        let k = columns(key);
        s = [
            td_column(s[0], s[3], s[2], s[1]) ^ k[0],
            td_column(s[1], s[0], s[3], s[2]) ^ k[1],
            td_column(s[2], s[1], s[0], s[3]) ^ k[2],
            td_column(s[3], s[2], s[1], s[0]) ^ k[3],
        ];
    }

    let k = columns(&keys[N - 1]);
    to_bytes([
        sub_column(&INV_SBOX, s[0], s[3], s[2], s[1]) ^ k[0],
        sub_column(&INV_SBOX, s[1], s[0], s[3], s[2]) ^ k[1],
        sub_column(&INV_SBOX, s[2], s[1], s[0], s[3]) ^ k[2],
        sub_column(&INV_SBOX, s[3], s[2], s[1], s[0]) ^ k[3],
    ])
}
