//! Hashing a message that arrives in pieces: the crate-internal incremental
//! interface of the fixed-output hashes.
//!
//! [`Digest::digest`] takes the whole message in one slice. The crate's own
//! constructions sometimes have it in several pieces, or need to hash a prefix
//! once and carry on from it many times: HMAC hashes each padded key once and
//! starts every tag from the result (FIPS 198-1 section 6). [`Incremental`]
//! does that. A [`State`] takes the message a piece at a time and gives the
//! digest at the end, and it can be cloned at any point to carry on from there.
//!
//! The interface is not public. Code that is generic over `D: Digest` reaches
//! it through [`Digest::INCREMENTAL`], a hidden constant that the crate's eight
//! hashes set and that is `None` for any other implementation of the trait.
//!
//! All eight are Merkle-Damgard hashes, so one [`State`] serves them all: the
//! chaining value of up to eight words, the bytes of a block not complete yet,
//! and the length so far. [`State::absorb`] hands whole blocks to the hash's
//! compression function straight from the caller's slice, through the same
//! backend dispatch as the one-shot `digest`, and copies only the bytes that do
//! not fill a block. [`State::finish`] pads the message as the one-shot paths
//! do. What differs between the hashes, the initial state, the compression
//! function, the encoding of the length and of the output, stays in each hash's
//! `digest.rs`.

use crate::Digest;
use crate::wipe::{wipe, wipe_bytes};

/// The longest block a [`State`] can hold.
///
/// 128 bytes would cover every hash in the crate. 144 is the rate of SHA3-224,
/// which HMAC uses as its block, and the longest block among the hashes NIST
/// approves for HMAC: HMAC accepts any `Digest` with a block up to that long,
/// and keeps its padded key in a state.
pub(crate) const MAX_BLOCK_LEN: usize = 144;

/// A hash that can be given its input a piece at a time. Implemented by the
/// crate's eight fixed-output hashes.
pub(crate) trait Incremental: Digest {
    /// A state that has hashed nothing yet.
    fn init() -> State;

    /// Hashes `input` as the next bytes of the message.
    fn update(state: &mut State, input: &[u8]);

    /// Pads the message hashed so far, and returns its digest.
    fn finish(state: State) -> Self::Output;
}

/// The functions of a hash's [`Incremental`] implementation, as
/// [`Digest::INCREMENTAL`] carries them to code that only knows `D: Digest`.
///
/// Nameable only inside the crate: the module is private.
pub struct IncrementalFns<D: Digest + ?Sized> {
    pub(crate) init: fn() -> State,
    pub(crate) update: fn(&mut State, &[u8]),
    pub(crate) finish: fn(State) -> D::Output,
}

/// The functions of `D`'s implementation, for `D`'s [`Digest::INCREMENTAL`].
pub(crate) const fn fns_of<D: Incremental>() -> IncrementalFns<D> {
    IncrementalFns {
        init: D::init,
        update: D::update,
        finish: D::finish,
    }
}

impl<D: Digest + ?Sized> Clone for IncrementalFns<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D: Digest + ?Sized> Copy for IncrementalFns<D> {}

/// A hash part of the way through a message.
///
/// The same type for all eight hashes, so that code generic over the hash can
/// hold one without knowing which. Only the hash that started a state (with
/// [`Incremental::init`]) may be given it.
///
/// A state can hold secrets: HMAC's states, after the first block, are worth
/// as much as its key, and the pending bytes are part of the message. So
/// dropping a state overwrites it with zeros.
#[derive(Clone)]
pub struct State {
    /// The chaining value: four (MD5), five (SHA-1) or eight (SHA-224,
    /// SHA-256) 32-bit words, each in the low half of a slot, or eight 64-bit
    /// words (SHA-384, SHA-512 and SHA-512/t). The slots a hash does not use
    /// stay zero.
    chaining: [u64; 8],
    /// The bytes of the block that is not complete yet, in its first
    /// `pending_len` bytes.
    pending: [u8; MAX_BLOCK_LEN],
    /// Always less than the hash's block length.
    pending_len: usize,
    /// How many bytes of message the state has taken, modulo 2^64.
    total_len: u64,
}

impl State {
    /// A state that has hashed nothing, with the chaining value `chaining`:
    /// the hash's initial state, in the layout of [`State::chaining`].
    pub(crate) fn new(chaining: [u64; 8]) -> Self {
        Self {
            chaining,
            pending: [0; MAX_BLOCK_LEN],
            pending_len: 0,
            total_len: 0,
        }
    }

    /// A state that holds `prefix` without hashing it, for a hash with no
    /// incremental form: HMAC keeps a padded key this way, and puts it in
    /// front of every message before it hashes the two in one go. Such a state
    /// is only ever read back with [`held`](Self::held), never given to a
    /// hash.
    ///
    /// `prefix` is at most [`MAX_BLOCK_LEN`] bytes long; HMAC checks that at
    /// compile time.
    pub(crate) fn holding(prefix: &[u8]) -> Self {
        let mut state = Self::new([0; 8]);
        state.pending[..prefix.len()].copy_from_slice(prefix);
        state.pending_len = prefix.len();
        state.total_len = prefix.len() as u64;
        state
    }

    /// The bytes a state made by [`holding`](Self::holding) holds.
    pub(crate) fn held(&self) -> &[u8] {
        &self.pending[..self.pending_len]
    }

    /// How many bytes of message the state has taken, modulo 2^64.
    pub(crate) fn message_len(&self) -> u64 {
        self.total_len
    }

    /// Takes `input` as the next bytes of the message, for a hash with blocks
    /// of `BLOCK` bytes.
    ///
    /// Bytes that complete a pending block are copied into it, and the block
    /// goes to `compress`. Every whole block after that goes to `compress` in
    /// one call, straight from `input`, and what is left over waits in the
    /// state for the next call. `compress` is the hash's compression function,
    /// given the chaining value and a whole number of blocks.
    pub(crate) fn absorb<const BLOCK: usize>(
        &mut self,
        mut input: &[u8],
        mut compress: impl FnMut(&mut [u64; 8], &[u8]),
    ) {
        const { assert!(BLOCK > 0 && BLOCK <= MAX_BLOCK_LEN) };
        self.total_len = self.total_len.wrapping_add(input.len() as u64);

        if self.pending_len > 0 {
            let take = (BLOCK - self.pending_len).min(input.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&input[..take]);
            self.pending_len += take;
            input = &input[take..];
            if self.pending_len < BLOCK {
                return;
            }
            compress(&mut self.chaining, &self.pending[..BLOCK]);
            self.pending_len = 0;
        }

        let whole = input.len() - input.len() % BLOCK;
        if whole > 0 {
            compress(&mut self.chaining, &input[..whole]);
        }
        let rest = &input[whole..];
        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
    }

    /// Pads the message and returns the final chaining value, for a hash with
    /// blocks of `BLOCK` bytes.
    ///
    /// The padding is the one all eight hashes share: a `0x80` byte, zeros, and
    /// `length` at the very end of the last block. `length` is the message
    /// length in bits, encoded as the hash wants it (8 bytes little-endian for
    /// MD5, 8 or 16 bytes big-endian for SHA-1 and SHA-2), from
    /// [`message_len`](Self::message_len). The padding is written in the pending
    /// block itself, which takes one block or, when the length does not fit
    /// after the marker, two.
    pub(crate) fn finish<const BLOCK: usize>(
        mut self,
        length: &[u8],
        mut compress: impl FnMut(&mut [u64; 8], &[u8]),
    ) -> [u64; 8] {
        const { assert!(BLOCK > 0 && BLOCK <= MAX_BLOCK_LEN) };
        let length_at = BLOCK - length.len();

        let mut end = self.pending_len;
        self.pending[end] = 0x80;
        end += 1;
        if end > length_at {
            self.pending[end..BLOCK].fill(0);
            compress(&mut self.chaining, &self.pending[..BLOCK]);
            end = 0;
        }
        self.pending[end..length_at].fill(0);
        self.pending[length_at..BLOCK].copy_from_slice(length);
        compress(&mut self.chaining, &self.pending[..BLOCK]);

        // `self` is wiped when it goes out of scope; the copy returned is the
        // digest, before the hash cuts or encodes it.
        self.chaining
    }
}

/// 32-bit chaining words in the layout of a [`State`]: one per slot, in the
/// low half, and the slots after them zero.
pub(crate) fn to_slots<const N: usize>(words: &[u32; N]) -> [u64; 8] {
    const { assert!(N <= 8) };
    let mut slots = [0; 8];
    for (slot, &word) in slots.iter_mut().zip(words) {
        *slot = u64::from(word);
    }
    slots
}

/// The first `N` chaining words of a [`State`] that holds 32-bit words.
pub(crate) fn from_slots<const N: usize>(slots: &[u64; 8]) -> [u32; N] {
    const { assert!(N <= 8) };
    // The high halves are zero: every word was put there by `to_slots`.
    core::array::from_fn(|i| slots[i] as u32)
}

impl Drop for State {
    fn drop(&mut self) {
        wipe(&mut self.chaining);
        wipe_bytes(&mut self.pending);
        wipe(core::slice::from_mut(&mut self.pending_len));
        wipe(core::slice::from_mut(&mut self.total_len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::md5::Md5;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    /// A deterministic message that does not repeat within a block.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Hashes `message` in the pieces `cuts` marks, through
    /// [`Digest::INCREMENTAL`] as generic code sees it.
    fn in_pieces<D: Digest>(message: &[u8], cuts: &[usize]) -> D::Output {
        let fns = D::INCREMENTAL.expect("the crate's hashes are incremental");
        let mut state = (fns.init)();
        let mut start = 0;
        for &cut in cuts.iter().chain([&message.len()]) {
            (fns.update)(&mut state, &message[start..cut]);
            start = cut;
        }
        assert_eq!(state.message_len(), message.len() as u64);
        (fns.finish)(state)
    }

    /// Checks, for one hash, that hashing in pieces gives the one-shot digest,
    /// for messages around every block and padding boundary, split at every
    /// byte.
    fn check_splits<D: Digest>(name: &str) {
        let block = D::BLOCK_LEN;
        // The marker byte and the length field: 9 bytes for a 64-byte block,
        // 17 for a 128-byte one. A remainder longer than `block - padding`
        // pushes the length into a block of its own.
        let padding = if block == 128 { 17 } else { 9 };
        let mut lengths = vec![0, 1];
        for blocks in 1..=2 {
            let end = blocks * block;
            lengths.extend([end - padding, end - padding + 1, end - 1, end, end + 1]);
        }

        for len in lengths {
            let message = pattern(len);
            let one_shot = D::digest(&message);
            for cut in 0..=len {
                assert_eq!(
                    in_pieces::<D>(&message, &[cut]).as_ref(),
                    one_shot.as_ref(),
                    "{name}, {len} bytes split at {cut}"
                );
            }
            let bytes: Vec<usize> = (1..len).collect();
            assert_eq!(
                in_pieces::<D>(&message, &bytes).as_ref(),
                one_shot.as_ref(),
                "{name}, {len} bytes one at a time"
            );
        }
    }

    #[test]
    fn pieces_match_one_shot_at_every_split() {
        check_splits::<Md5>("MD5");
        check_splits::<Sha1>("SHA-1");
        check_splits::<Sha224>("SHA-224");
        check_splits::<Sha256>("SHA-256");
        check_splits::<Sha384>("SHA-384");
        check_splits::<Sha512>("SHA-512");
        check_splits::<Sha512_224>("SHA-512/224");
        check_splits::<Sha512_256>("SHA-512/256");
    }

    /// A long message in pieces of uneven sizes, so that `compress` is called
    /// on many blocks at once from the caller's slice (which is what makes a
    /// hardware backend run its main loop), and so that blocks start at
    /// every kind of offset in a piece.
    #[test]
    fn long_message_in_uneven_pieces() {
        fn check<D: Digest>(name: &str) {
            let message = pattern(100_000);
            let sizes = [1, 63, 64, 65, 127, 128, 129, 1000, 4096, 7];
            let mut cuts = Vec::new();
            let mut at = 0;
            for size in sizes.iter().cycle() {
                at += size;
                if at >= message.len() {
                    break;
                }
                cuts.push(at);
            }
            assert_eq!(
                in_pieces::<D>(&message, &cuts).as_ref(),
                D::digest(&message).as_ref(),
                "{name}"
            );
        }

        check::<Md5>("MD5");
        check::<Sha1>("SHA-1");
        check::<Sha224>("SHA-224");
        check::<Sha256>("SHA-256");
        check::<Sha384>("SHA-384");
        check::<Sha512>("SHA-512");
        check::<Sha512_224>("SHA-512/224");
        check::<Sha512_256>("SHA-512/256");
    }

    /// A cloned state carries on as the original would, which is what HMAC
    /// relies on when it starts every tag from the same state.
    #[test]
    fn a_clone_carries_on_from_the_same_point() {
        let message = pattern(300);
        let fns = Sha256::INCREMENTAL.unwrap();
        let mut prefix = (fns.init)();
        (fns.update)(&mut prefix, &message[..64]);
        for end in [64, 100, 128, 300] {
            let mut state = prefix.clone();
            (fns.update)(&mut state, &message[64..end]);
            assert_eq!(
                (fns.finish)(state),
                Sha256::digest(&message[..end]),
                "{end}"
            );
        }
    }

    /// Dropping a state must leave nothing of it behind.
    #[test]
    fn dropping_wipes_the_state() {
        use core::mem::MaybeUninit;
        use core::ptr::addr_of;

        let fns = Sha512::INCREMENTAL.unwrap();
        let mut state = (fns.init)();
        (fns.update)(&mut state, &pattern(200));
        let mut slot = MaybeUninit::new(state);
        let state = slot.as_mut_ptr();
        // Reads each field through the one raw pointer that also does the
        // dropping, so that the drop does not invalidate it.
        let read = || {
            // SAFETY: the slot is alive and every field was written, first by
            // `update` and then, if the drop works, by `wipe`.
            unsafe {
                (
                    addr_of!((*state).chaining).read(),
                    addr_of!((*state).pending).read(),
                    addr_of!((*state).pending_len).read(),
                    addr_of!((*state).total_len).read(),
                )
            }
        };
        let (chaining, pending, pending_len, total_len) = read();
        assert!(chaining.iter().any(|&w| w != 0));
        assert!(pending[..pending_len].iter().any(|&b| b != 0));
        assert_eq!((pending_len, total_len), (72, 200));

        // SAFETY: the slot holds an initialised state, dropped only here.
        unsafe { state.drop_in_place() };
        let (chaining, pending, pending_len, total_len) = read();
        assert_eq!(chaining, [0; 8]);
        assert_eq!(pending, [0; MAX_BLOCK_LEN]);
        assert_eq!((pending_len, total_len), (0, 0));
    }
}
