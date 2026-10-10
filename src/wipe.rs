//! Overwriting secrets before their memory is released.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrites `values` with zeros in a way the compiler may not remove.
///
/// A plain store to memory that is never read again is dead as far as the
/// compiler is concerned, and gets deleted. Volatile stores are not.
pub(crate) fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: `value` is a valid, aligned, exclusive reference to a `T`.
        unsafe { core::ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites `bytes` with zeros like [`wipe`], sixteen bytes per store.
///
/// `wipe` stores one element at a time, and for bytes that is one volatile
/// store per byte: about 3 GB/s on an Apple M1 Pro. That is a measurable part
/// of a short HMAC tag, which wipes two hash states of a few hundred bytes
/// each. Here the middle of the slice, aligned to 16 bytes, is viewed as
/// `u128`s and wiped one per store, which costs a few percent of the same
/// work; only the bytes before and after it are wiped one at a time.
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    // SAFETY: every bit pattern is a valid `u128`, and a `u128` is nothing
    // but bytes, so viewing aligned groups of 16 bytes as `u128`s is sound.
    // The three views borrow `bytes` exclusively.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<u128>() };
    wipe(head);
    wipe(words);
    wipe(tail);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wipe_bytes` handles the bytes before and after the aligned middle on
    /// its own, so check every start offset and length around a few words,
    /// and that nothing outside the slice is touched.
    #[test]
    fn wipe_bytes_zeroes_every_byte() {
        let mut buf = [0xffu8; 80];
        for start in 0..16 {
            for len in 0..=buf.len() - start {
                buf.fill(0xff);
                wipe_bytes(&mut buf[start..start + len]);
                let (before, rest) = buf.split_at(start);
                let (inside, after) = rest.split_at(len);
                assert!(before.iter().all(|&b| b == 0xff), "{start}, {len}");
                assert!(inside.iter().all(|&b| b == 0), "{start}, {len}");
                assert!(after.iter().all(|&b| b == 0xff), "{start}, {len}");
            }
        }
    }

    #[test]
    fn wipe_zeroes_every_element() {
        let mut bytes = [0xa5u8; 37];
        wipe(&mut bytes);
        assert_eq!(bytes, [0; 37]);

        let mut words = [u64::MAX; 9];
        wipe(&mut words);
        assert_eq!(words, [0; 9]);
    }
}
