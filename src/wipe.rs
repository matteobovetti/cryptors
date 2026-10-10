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

/// The bytes of `value` where it lies in memory, read once before it is
/// dropped there and once after: what its `Drop` leaves behind. For the tests
/// that check a type wipes itself.
///
/// # Safety
///
/// `T` must have no padding, so that every byte read has been written.
#[cfg(test)]
pub(crate) unsafe fn bytes_around_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let mut slot = core::mem::MaybeUninit::new(value);
    // One raw pointer does the dropping and the reading, so that the drop does
    // not invalidate the pointer the reads go through.
    let ptr = slot.as_mut_ptr();
    let bytes = ptr.cast::<u8>();
    let read = || -> Vec<u8> {
        (0..size_of::<T>())
            // SAFETY: the slot is alive, and by the caller's promise every byte
            // of it was written, first by `T`'s constructor and then, if the
            // drop works, by `wipe`.
            .map(|i| unsafe { bytes.add(i).read() })
            .collect()
    };
    let before = read();
    // SAFETY: the slot holds an initialised value, dropped only here.
    unsafe { ptr.drop_in_place() };
    (before, read())
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
