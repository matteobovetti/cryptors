//! Secret bytes of a length known only at run time, overwritten with zeros
//! when they are dropped.

use crate::wipe::wipe;

/// The most bytes a [`Secret`] holds: the two Diffie-Hellman outputs of
/// P-521's authenticated modes, 66 bytes each. Every key, shared secret and
/// pseudorandom key in HPKE fits.
const CAPACITY: usize = 132;

/// Up to 132 secret bytes: a pseudorandom key, a Diffie-Hellman output, a KEM
/// shared secret, an AEAD key.
///
/// The bytes live inline, not on the heap, and are overwritten with zeros when
/// the value is dropped.
#[derive(Clone)]
pub(super) struct Secret {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl Secret {
    /// `len` zero bytes, to be filled through [`as_mut_bytes`](Self::as_mut_bytes).
    ///
    /// Every length in HPKE is a constant of the suite (`Nh`, `Nk`, `Nsecret`),
    /// never a caller's input, so a length over 132 is a bug here and panics.
    pub(super) fn zeroed(len: usize) -> Self {
        assert!(len <= CAPACITY, "a secret of {len} bytes does not fit");
        Self {
            bytes: [0; CAPACITY],
            len,
        }
    }

    /// A copy of `bytes`.
    pub(super) fn from_slice(bytes: &[u8]) -> Self {
        let mut secret = Self::zeroed(bytes.len());
        secret.as_mut_bytes().copy_from_slice(bytes);
        secret
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub(super) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dropping a secret must leave none of its bytes behind.
    #[test]
    fn dropping_wipes_the_bytes() {
        let secret = Secret::from_slice(&[0x5a; 48]);
        // SAFETY: a secret is a byte array and a `usize`, with no padding.
        let (before, after) = unsafe { crate::wipe::bytes_around_drop(secret) };
        let bytes = core::mem::offset_of!(Secret, bytes);
        assert!(before[bytes..][..48].iter().all(|&b| b == 0x5a));
        assert_eq!(
            after[bytes..][..CAPACITY],
            [0; CAPACITY],
            "the bytes survive the drop"
        );
    }
}
