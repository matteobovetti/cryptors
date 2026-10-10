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

#[cfg(test)]
mod tests {
    use super::*;

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
