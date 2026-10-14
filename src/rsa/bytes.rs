//! A buffer of bytes that is overwritten with zeros when it is dropped.

use crate::wipe::wipe_bytes;
use core::fmt;
use core::ops::{Deref, DerefMut};

/// The padded block of a message, the seed and the data block of OAEP, and the
/// other byte strings that hold or are derived from a plaintext or a key: they
/// are overwritten with zeros when they go out of scope, like the numbers of
/// [`bigmod`](super::bigmod).
pub(super) struct Wiped(Vec<u8>);

impl Wiped {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Wiped(bytes)
    }

    /// `len` zero bytes.
    pub(super) fn zero(len: usize) -> Self {
        Wiped(vec![0; len])
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

impl Deref for Wiped {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Wiped {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for Wiped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Wiped(..)")
    }
}
