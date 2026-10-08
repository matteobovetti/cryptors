//! The key schedule: the parts of FIPS 197 that every backend shares.
//!
//! Only the S-box (`SubWord`) and the inverse of `MixColumns` differ between
//! backends, so [`key_expansion`] and [`inverse_keys`] take those as
//! parameters. Everything else, which round key goes where and in what order,
//! is written once, here.

use core::sync::atomic::{Ordering, compiler_fence};

/// The round keys of one key, in the two orders the cipher uses them.
///
/// `N` is the number of round keys, `Nr + 1` in the standard's notation: 11,
/// 13 or 15. A round key is 16 bytes in state order (column by column), the
/// layout every backend can load as it is.
///
/// The keys are overwritten with zeros when the schedule is dropped.
#[derive(Clone)]
pub(super) struct Schedule<const N: usize> {
    /// The round keys of `Cipher()` (FIPS 197 section 5.2), `enc[r]` being the
    /// key added in round `r`.
    pub(super) enc: [[u8; 16]; N],
    /// The round keys of `EqInvCipher()` (section 5.3.5), in the order the
    /// decryption rounds use them. See [`inverse_keys`].
    pub(super) dec: [[u8; 16]; N],
}

impl<const N: usize> Drop for Schedule<N> {
    fn drop(&mut self) {
        wipe(&mut self.enc);
        wipe(&mut self.dec);
    }
}

/// Overwrites `values` with zeros in a way the compiler may not remove.
///
/// A plain store to memory that is never read again is dead as far as the
/// compiler is concerned, and gets deleted. Volatile stores are not.
fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: `value` is a valid, aligned, exclusive reference to a `T`.
        unsafe { core::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// FIPS 197 section 5.2, `KeyExpansion()`: expands a key of `K` bytes into the
/// `N` round keys of the cipher.
///
/// A word is four bytes of the key, read little-endian so that the first byte
/// is the least significant: a round key is then its four words stored one
/// after the other, which is its byte layout. With that convention `RotWord`
/// (which turns `[a0, a1, a2, a3]` into `[a1, a2, a3, a0]`) is a rotate right
/// by 8 bits, and a round constant `[rc, 0, 0, 0]` is the word `rc`.
///
/// `sub_word` is `SubWord()`: the S-box applied to each byte of a word.
#[inline(always)]
pub(super) fn key_expansion<const K: usize, const N: usize>(
    key: &[u8; K],
    sub_word: impl Fn(u32) -> u32,
) -> [[u8; 16]; N] {
    // AES-128, AES-192 and AES-256 are the only key sizes; they need 11, 13
    // and 15 round keys.
    const { assert!(K == 16 || K == 24 || K == 32) };
    const { assert!(N == K / 4 + 7) };

    // `Nk`: the length of the key in words.
    let nk = K / 4;

    // 60 words is the most there can be: 4 * 15 for AES-256.
    let mut w = [0u32; 60];
    for (word, bytes) in w.iter_mut().zip(key.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    // `Rcon[i / Nk]` is x^(i / Nk - 1) in GF(2^8), that is 1, 2, 4, ..., doubling
    // (with the reduction of section 4.2) once per use.
    let mut rcon = 1u8;
    for i in nk..4 * N {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_right(8)) ^ u32::from(rcon);
            rcon = (rcon << 1) ^ (0x1b * (rcon >> 7));
        } else if nk > 6 && i % nk == 4 {
            // Only the 256-bit key has this extra substitution.
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    let mut keys = [[0u8; 16]; N];
    for (key, words) in keys.iter_mut().zip(w.chunks_exact(4)) {
        for (bytes, word) in key.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *bytes = word.to_le_bytes();
        }
    }

    // `w` held the key and every round key; do not leave it on the stack.
    wipe(&mut w);
    keys
}

/// FIPS 197 section 5.3.5: the round keys of the equivalent inverse cipher.
///
/// The inverse cipher of section 5.3 undoes the rounds in reverse order, and
/// each of its rounds adds the round key between `InvSubBytes` and
/// `InvMixColumns`. Because `InvMixColumns` is linear, it can be applied to the
/// round key instead, which moves the key addition to the end of the round.
/// Decryption rounds then have the same shape as encryption rounds (a lookup
/// step followed by one XOR with the key), and `AESD`/`AESDEC` and the table
/// lookups can do each in one go.
///
/// The price is that round keys `1` to `Nr - 1` go through `InvMixColumns`
/// first (`inv_mix_columns`), and decryption takes all of them back to front:
/// the first key it uses is the last one of the cipher, and the last is its
/// first.
#[inline(always)]
pub(super) fn inverse_keys<const N: usize>(
    enc: &[[u8; 16]; N],
    inv_mix_columns: impl Fn(&[u8; 16]) -> [u8; 16],
) -> [[u8; 16]; N] {
    let mut dec = *enc;
    dec[0] = enc[N - 1];
    dec[N - 1] = enc[0];
    for i in 1..N - 1 {
        dec[i] = inv_mix_columns(&enc[N - 1 - i]);
    }
    dec
}
