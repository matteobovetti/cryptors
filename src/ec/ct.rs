//! Branch-free helpers for data that must not steer the control flow.
//!
//! Secret values (a private scalar, the coordinates of a point derived from
//! it) are only ever combined here with shifts, masks and arithmetic, so that
//! neither a branch nor a memory address depends on them. A mask is `0` or
//! `u64::MAX`, and `select` picks between two words by it.
//!
//! The compiler is free to turn a mask-and-merge back into a conditional jump
//! when it can see that the mask came from a single bit. `black_box` hides the
//! origin of the mask, which is the best the language offers: it promises
//! nothing, and the generated code is the thing to inspect. `mask` is where the
//! barrier sits, so that every secret-dependent choice in this module goes
//! through it.

use core::hint::black_box;

/// All ones if `bit` is 1 and all zeros if it is 0. `bit` must be 0 or 1.
#[inline(always)]
pub(crate) const fn mask(bit: u64) -> u64 {
    debug_assert!(bit <= 1);
    black_box(0u64.wrapping_sub(bit))
}

/// 1 if `x` is zero and 0 otherwise.
#[inline(always)]
pub(crate) const fn is_zero(x: u64) -> u64 {
    // The top bit of `x | -x` is set exactly when `x` is not zero.
    ((x | x.wrapping_neg()) >> 63) ^ 1
}

/// 1 if `a == b` and 0 otherwise.
#[inline(always)]
pub(crate) const fn eq(a: u64, b: u64) -> u64 {
    is_zero(a ^ b)
}

/// `a` if `mask` is all ones, `b` if it is all zeros.
#[inline(always)]
pub(crate) const fn select(mask: u64, a: u64, b: u64) -> u64 {
    b ^ (mask & (a ^ b))
}

/// Whether the byte strings are equal, in a time that depends only on their
/// length. Strings of different lengths are never equal.
pub(crate) fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    is_zero(u64::from(diff)) == 1
}

/// Whether `bytes` is all zeros, in a time that depends only on the length.
pub(crate) fn bytes_are_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for byte in bytes {
        acc |= byte;
    }
    is_zero(u64::from(acc)) == 1
}

/// Whether the big-endian integer `a` is less than `b`, in a time that depends
/// only on the length. The two must have the same length.
pub(crate) fn bytes_lt(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    // The borrow out of `a - b`, taken from the least significant byte up: it
    // is 1 exactly when `a < b`.
    let mut borrow = 0u16;
    for (x, y) in a.iter().zip(b).rev() {
        let diff = u16::from(*x).wrapping_sub(u16::from(*y) + borrow);
        borrow = diff >> 15;
    }
    borrow == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_helpers() {
        assert_eq!(mask(0), 0);
        assert_eq!(mask(1), u64::MAX);

        assert_eq!(is_zero(0), 1);
        for x in [1, 2, 1 << 63, u64::MAX] {
            assert_eq!(is_zero(x), 0, "{x:#x}");
        }

        assert_eq!(eq(7, 7), 1);
        assert_eq!(eq(7, 8), 0);
        assert_eq!(eq(0, 1 << 63), 0);

        assert_eq!(select(u64::MAX, 3, 5), 3);
        assert_eq!(select(0, 3, 5), 5);
    }

    #[test]
    fn byte_string_helpers() {
        assert!(bytes_eq(b"abc", b"abc"));
        // A difference in any one position, first, middle or last, is seen.
        assert!(!bytes_eq(b"abc", b"abd"));
        assert!(!bytes_eq(b"abc", b"xbc"));
        assert!(!bytes_eq(b"abc", b"axc"));
        assert!(!bytes_eq(b"abc", b"ab"));
        assert!(bytes_eq(b"", b""));

        assert!(bytes_are_zero(&[0; 66]));
        assert!(!bytes_are_zero(&[0, 0, 1]));
        assert!(!bytes_are_zero(&[0x80, 0, 0]));

        // Borrows have to travel through bytes of 0x00 and 0xff alike.
        assert!(bytes_lt(&[0, 0xff], &[1, 0]));
        assert!(!bytes_lt(&[1, 0], &[0, 0xff]));
        assert!(!bytes_lt(&[1, 0], &[1, 0]));
        assert!(bytes_lt(&[1, 0], &[1, 1]));
        assert!(bytes_lt(&[0x7f, 0xff], &[0x80, 0x00]));
        assert!(!bytes_lt(&[0x80, 0x00], &[0x7f, 0xff]));
    }
}
