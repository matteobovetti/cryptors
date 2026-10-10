//! A STAND-IN for HMAC (RFC 2104), with only what HKDF needs. Delete it when
//! `crate::hmac` lands.
//!
//! HMAC is being written as a module of its own, `crate::hmac`, on another
//! branch. Until it is merged, HKDF needs one type of it, and this file has that
//! type and nothing else: [`Keyed`], with the two functions of
//! `crate::hmac::Hmac` that HKDF calls, `new` and `mac_parts`, under the same
//! signatures. Moving to `crate::hmac` is then deleting this file and its `mod`
//! line in `mod.rs`, and changing the one `use` of it in `kdf.rs` to
//! `use crate::hmac::Hmac as Keyed;`.
//!
//! What it cannot do is what `crate::hmac::Hmac` will: hash the padded key once
//! and start every message from the state that leaves. `Digest` hashes a whole
//! message in one call, so here each `mac_parts` hashes the padded key again,
//! twice: four calls of the compression function for a block of HKDF output,
//! where two would do.

use core::marker::PhantomData;

use crate::Digest;
use crate::wipe::wipe;

/// A message that fits in this many bytes together with the padded key is put
/// together on the stack, so that Expand does not allocate for every block; a
/// longer one goes on the heap.
const STACK_LEN: usize = 512;

/// HMAC-`D` (RFC 2104 section 2) under one key, for any number of messages.
pub(super) struct Keyed<D> {
    /// `K`: the key padded with zeros to the hash's block, or, if the key is
    /// longer than a block, its digest padded the same way. Overwritten with
    /// zeros when dropped.
    padded_key: Vec<u8>,
    hash: PhantomData<D>,
}

impl<D: Digest> Keyed<D> {
    /// Prepares HMAC under `key`, which may be of any length.
    pub(super) fn new(key: &[u8]) -> Self {
        // Allocated at its final size, so that it never moves and leaves a copy.
        let mut padded_key = Vec::with_capacity(D::BLOCK_LEN);
        if key.len() > D::BLOCK_LEN {
            padded_key.extend_from_slice(D::digest(key).as_ref());
        } else {
            padded_key.extend_from_slice(key);
        }
        padded_key.resize(D::BLOCK_LEN, 0);
        Self {
            padded_key,
            hash: PhantomData,
        }
    }

    /// The HMAC of the concatenation of `parts`:
    /// `H((K ^ opad) | H((K ^ ipad) | message))`, where `ipad` and `opad` are
    /// blocks of `0x36` and `0x5c` bytes.
    pub(super) fn mac_parts(&self, parts: &[&[u8]]) -> D::Output {
        // `Digest` hashes one buffer in one call, so the padded key and what
        // follows it have to be put together first. One buffer, sized for the
        // longer of the two, serves both hashes.
        let message_len: usize = parts.iter().map(|part| part.len()).sum();
        let len = D::BLOCK_LEN + message_len.max(D::OUTPUT_LEN);
        let mut stack = [0; STACK_LEN];
        let mut heap = Vec::new();
        let buf = if len <= STACK_LEN {
            &mut stack[..len]
        } else {
            heap.resize(len, 0);
            &mut heap[..]
        };

        let (pad, rest) = buf.split_at_mut(D::BLOCK_LEN);
        for (byte, key) in pad.iter_mut().zip(&self.padded_key) {
            *byte = key ^ 0x36;
        }
        let mut at = 0;
        for part in parts {
            rest[at..][..part.len()].copy_from_slice(part);
            at += part.len();
        }
        let inner = D::digest(&buf[..D::BLOCK_LEN + message_len]);

        let (pad, rest) = buf.split_at_mut(D::BLOCK_LEN);
        for (byte, key) in pad.iter_mut().zip(&self.padded_key) {
            *byte = key ^ 0x5c;
        }
        rest[..D::OUTPUT_LEN].copy_from_slice(inner.as_ref());
        let tag = D::digest(&buf[..D::BLOCK_LEN + D::OUTPUT_LEN]);

        // The padded key is secret, and so is HKDF's message: the previous block.
        wipe(buf);
        tag
    }
}

impl<D> Clone for Keyed<D> {
    fn clone(&self) -> Self {
        Self {
            padded_key: self.padded_key.clone(),
            hash: PhantomData,
        }
    }
}

impl<D> Drop for Keyed<D> {
    fn drop(&mut self) {
        wipe(&mut self.padded_key);
    }
}
