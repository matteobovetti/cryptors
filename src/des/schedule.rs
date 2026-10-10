//! The key schedule: the sixteen round keys of one DES key (FIPS 46-3,
//! Appendix 1).

use core::sync::atomic::{Ordering, compiler_fence};

use super::tables::{PC1, PC2, SHIFTS, permute};

/// One round key `Kn`, the 48 bits the standard has the cipher function add to
/// the expanded half-block, kept as the two words that `scalar::f` adds to the
/// two rotations of the half-block it works on.
///
/// Cut `Kn` into eight groups of six bits, `B1` to `B8` from the left. The
/// first word holds `B1`, `B3`, `B5` and `B7` in its four bytes, from the
/// most significant, and the second holds `B8`, `B2`, `B4` and `B6`. Each group
/// is in the low six bits of its byte; the top two bits of every byte are zero.
pub(super) type RoundKey = [u32; 2];

/// The sixteen round keys of one key, in the order encryption uses them.
/// Decryption uses the same keys in the opposite order.
///
/// The keys are overwritten with zeros when the schedule is dropped.
#[derive(Clone)]
pub(super) struct Schedule {
    pub(super) keys: [RoundKey; 16],
}

impl Drop for Schedule {
    fn drop(&mut self) {
        wipe(&mut self.keys);
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

/// The key schedule `KS` of the standard: expands a key of eight bytes into the
/// sixteen round keys.
///
/// The key is 64 bits, of which the algorithm uses 56. The other eight, the
/// last bit of every byte, are there for error detection and have no effect
/// here, so two keys that differ only in them give the same schedule.
pub(super) fn key_schedule(key: &[u8; 8]) -> Schedule {
    // PC-1 drops the parity bits and splits the rest into the halves `C` and
    // `D` of 28 bits each.
    let cd = permute(u64::from_be_bytes(*key), 64, &PC1);
    let (mut c, mut d) = ((cd >> 28) as u32, (cd & 0x0fff_ffff) as u32);

    let mut keys = [[0; 2]; 16];
    for (round_key, shift) in keys.iter_mut().zip(SHIFTS) {
        c = rotate_left_28(c, shift);
        d = rotate_left_28(d, shift);
        // PC-2 takes the 48 bits of `Kn` out of `Cn Dn`.
        let k = permute(u64::from(c) << 28 | u64::from(d), 56, &PC2);
        *round_key = split(k);
    }
    Schedule { keys }
}

/// Rotates the low 28 bits of `x` left by `n` places.
fn rotate_left_28(x: u32, n: u8) -> u32 {
    ((x << n) | (x >> (28 - n))) & 0x0fff_ffff
}

/// Lays out the 48 bits of a round key as a [`RoundKey`].
fn split(k: u64) -> RoundKey {
    // `B1` is the leading six of the 48 bits, `B8` the trailing six.
    let group = |i: u32| ((k >> (42 - 6 * i)) & 0x3f) as u32;
    [
        group(0) << 24 | group(2) << 16 | group(4) << 8 | group(6),
        group(7) << 24 | group(1) << 16 | group(3) << 8 | group(5),
    ]
}
