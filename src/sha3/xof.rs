//! SHAKE128 and SHAKE256 that take their input in pieces and give their output
//! in pieces, for the algorithms of the crate that need a stream of bytes from a
//! hash: ML-DSA hashes a message that arrives in parts, and draws from one
//! sponge as many bytes as a rejection sampler turns out to need.
//!
//! The public `shake128` and `shake256` functions are one call for a whole
//! message and a known length of output. These are the same sponge (FIPS 202
//! Section 6.2) with the two phases left open: [`Shake::absorb`] any number of
//! times, then [`Shake::read`] any number of times. The permutation is the one
//! that the one-shot functions use, so a stream runs on whichever backend the
//! CPU has.

use super::digest::{RATE_SHAKE128, RATE_SHAKE256, SUFFIX_SHAKE, permute};
use crate::wipe::wipe;

/// SHAKE128: rate 168 bytes.
pub(crate) type Shake128 = Shake<RATE_SHAKE128>;

/// SHAKE256: rate 136 bytes.
pub(crate) type Shake256 = Shake<RATE_SHAKE256>;

/// A SHAKE sponge with a `RATE`-byte rate, absorbing and then squeezing.
///
/// The first [`read`](Shake::read) ends the input: it pads the last block and
/// permutes, and from then on [`absorb`](Shake::absorb) is a programming error
/// and panics.
pub(crate) struct Shake<const RATE: usize> {
    state: [u64; 25],
    /// While absorbing, how many bytes of the current block have been XORed
    /// into the state. While squeezing, how many bytes of the current block
    /// have been read out of it.
    pos: usize,
    squeezing: bool,
}

impl<const RATE: usize> Shake<RATE> {
    pub(crate) const fn new() -> Self {
        Self {
            state: [0; 25],
            pos: 0,
            squeezing: false,
        }
    }

    /// Appends `data` to the input.
    ///
    /// # Panics
    ///
    /// If output has been read already.
    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "SHAKE: absorb after read");

        // Finish the block that an earlier call left open.
        if self.pos != 0 {
            let take = (RATE - self.pos).min(data.len());
            xor_into(&mut self.state, self.pos, &data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == RATE {
                permute(&mut self.state);
                self.pos = 0;
            }
        }

        // Whole blocks straight from the caller's memory.
        let mut blocks = data.chunks_exact(RATE);
        for block in &mut blocks {
            xor_into(&mut self.state, 0, block);
            permute(&mut self.state);
        }

        // What is left starts a block, which is the only way that `pos` is
        // not zero: a full block is permuted at once.
        let rest = blocks.remainder();
        if !rest.is_empty() {
            xor_into(&mut self.state, 0, rest);
            self.pos = rest.len();
        }
    }

    /// Fills `out` with the next bytes of output.
    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            // pad10*1 with the SHAKE suffix (FIPS 202 Section 5.1 and 6.2):
            // the suffix bits and the first padding bit go right after the
            // input, the last padding bit ends the block.
            self.state[self.pos / 8] ^= u64::from(SUFFIX_SHAKE) << (8 * (self.pos % 8));
            self.state[(RATE - 1) / 8] ^= 0x80 << (8 * ((RATE - 1) % 8));
            permute(&mut self.state);
            self.pos = 0;
            self.squeezing = true;
        }

        while !out.is_empty() {
            if self.pos == RATE {
                permute(&mut self.state);
                self.pos = 0;
            }
            let take = (RATE - self.pos).min(out.len());
            let (now, later) = out.split_at_mut(take);
            copy_from(&self.state, self.pos, now);
            self.pos += take;
            out = later;
        }
    }
}

impl<const RATE: usize> Drop for Shake<RATE> {
    /// The state may hold a secret seed or the bytes that are derived from one.
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}

/// XORs `data` into the state starting at byte `offset`, with the bytes of a
/// lane in little-endian order (FIPS 202 Section B.1). The caller keeps
/// `offset + data.len()` within the state.
fn xor_into(state: &mut [u64; 25], mut offset: usize, mut data: &[u8]) {
    // The rest of a lane that an earlier call began.
    if !offset.is_multiple_of(8) {
        let take = (8 - offset % 8).min(data.len());
        let mut word = [0u8; 8];
        word[offset % 8..offset % 8 + take].copy_from_slice(&data[..take]);
        state[offset / 8] ^= u64::from_le_bytes(word);
        offset += take;
        data = &data[take..];
    }

    // Whole lanes.
    let mut lanes = data.chunks_exact(8);
    let first = offset / 8;
    let mut count = 0;
    for (lane, chunk) in state[first..].iter_mut().zip(&mut lanes) {
        *lane ^= u64::from_le_bytes(chunk.try_into().unwrap());
        count += 1;
    }

    // A last, partial lane.
    let tail = lanes.remainder();
    if !tail.is_empty() {
        let mut word = [0u8; 8];
        word[..tail.len()].copy_from_slice(tail);
        state[first + count] ^= u64::from_le_bytes(word);
    }
}

/// Copies `out.len()` bytes of the state, starting at byte `offset`, with the
/// bytes of a lane in little-endian order.
fn copy_from(state: &[u64; 25], mut offset: usize, mut out: &mut [u8]) {
    if !offset.is_multiple_of(8) {
        let take = (8 - offset % 8).min(out.len());
        let word = state[offset / 8].to_le_bytes();
        let (now, later) = out.split_at_mut(take);
        now.copy_from_slice(&word[offset % 8..offset % 8 + take]);
        offset += take;
        out = later;
    }

    let first = offset / 8;
    let mut count = 0;
    let mut lanes = out.chunks_exact_mut(8);
    for (chunk, lane) in (&mut lanes).zip(&state[first..]) {
        chunk.copy_from_slice(&lane.to_le_bytes());
        count += 1;
    }

    let tail = lanes.into_remainder();
    if !tail.is_empty() {
        let word = state[first + count].to_le_bytes();
        tail.copy_from_slice(&word[..tail.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::{shake128, shake256};

    /// A message with no pattern a sponge could line up with.
    fn message(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(131) ^ (i >> 3)) as u8)
            .collect()
    }

    /// The input cut at `cuts`, the output read in `reads`-sized pieces, and
    /// the same input and length through the one-shot function.
    fn check<const RATE: usize>(
        one_shot: fn(&[u8], &mut [u8]),
        input: &[u8],
        cuts: &[usize],
        reads: &[usize],
    ) {
        let total: usize = reads.iter().sum();
        let mut expected = vec![0u8; total];
        one_shot(input, &mut expected);

        let mut xof = Shake::<RATE>::new();
        let mut from = 0;
        for &cut in cuts {
            xof.absorb(&input[from..cut]);
            from = cut;
        }
        xof.absorb(&input[from..]);

        let mut got = Vec::new();
        for &len in reads {
            let mut piece = vec![0u8; len];
            xof.read(&mut piece);
            got.extend_from_slice(&piece);
        }
        assert_eq!(
            got,
            expected,
            "rate {RATE}, {} bytes in, cuts {cuts:?}, reads {reads:?}",
            input.len()
        );
    }

    /// The pieces may fall anywhere in a lane and a block: every length of
    /// input around one block and two, split at every point, and output read
    /// one block, a lane, a byte and a few odd lengths at a time.
    #[test]
    fn pieces_match_one_shot() {
        for (rate, one_shot) in [
            (RATE_SHAKE128, shake128 as fn(&[u8], &mut [u8])),
            (RATE_SHAKE256, shake256 as fn(&[u8], &mut [u8])),
        ] {
            for len in (0..=9)
                .chain(rate - 9..=rate + 9)
                .chain(2 * rate - 3..=2 * rate + 3)
            {
                let input = message(len);
                for cut in 0..=len {
                    if rate == RATE_SHAKE128 {
                        check::<RATE_SHAKE128>(one_shot, &input, &[cut], &[1, 7, 168, 3, 200]);
                    } else {
                        check::<RATE_SHAKE256>(one_shot, &input, &[cut], &[1, 7, 136, 3, 200]);
                    }
                }
            }
        }
    }

    #[test]
    fn many_pieces_in_and_out() {
        let input = message(1000);
        let cuts: Vec<usize> = (0..1000).step_by(37).collect();
        let reads = [0, 1, 1, 1, 8, 9, 16, 135, 136, 137, 168, 169, 1, 0, 500];
        check::<RATE_SHAKE128>(shake128, &input, &cuts, &reads);
        check::<RATE_SHAKE256>(shake256, &input, &cuts, &reads);

        // Byte by byte, both ways.
        let cuts: Vec<usize> = (0..300).collect();
        check::<RATE_SHAKE256>(shake256, &input[..300], &cuts, &[1; 400]);
        check::<RATE_SHAKE128>(shake128, &input[..300], &cuts, &[1; 400]);
    }

    /// An empty `absorb` and an empty `read` do nothing, even between others.
    #[test]
    fn empty_pieces() {
        let mut xof = Shake256::new();
        xof.absorb(b"");
        xof.absorb(b"abc");
        xof.absorb(b"");
        let mut nothing = [0u8; 0];
        xof.read(&mut nothing);
        let mut got = [0u8; 32];
        xof.read(&mut got);
        let mut expected = [0u8; 32];
        shake256(b"abc", &mut expected);
        assert_eq!(got, expected);
    }

    #[test]
    #[should_panic(expected = "absorb after read")]
    fn absorbing_after_reading_panics() {
        let mut xof = Shake128::new();
        let mut byte = [0u8; 1];
        xof.read(&mut byte);
        xof.absorb(b"late");
    }
}
