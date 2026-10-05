//! SHA-256 compression using Intel/AMD's dedicated SHA instructions (SHA-NI).
//!
//! One `SHA256RNDS2` instruction does two SHA-256 rounds at once, and
//! `SHA256MSG1`/`SHA256MSG2` compute the message schedule four words at a
//! time. So each block takes 32 round instructions here instead of 64 rounds
//! in the scalar version.
//!
//! This code only runs via `super::compress`, which checks the `sha`, `ssse3`
//! and `sse4.1` CPU features are present before calling it.
//!
//! On a CPU without those features the file is still compiled, but nothing
//! executes it. The `matches_scalar_backend` test in the digest module is what
//! checks it against `super::scalar`, and it only does so where the CPU
//! reports SHA-NI.

use core::arch::x86_64::*;

use super::K;

/// Runs four rounds. `$w` holds the four message-schedule words for these
/// rounds and `$i` is the group number (0 to 15), which selects the four round
/// constants to add in.
///
/// `SHA256RNDS2` takes the two rounds' worth of (message word + constant) from
/// the low half of its last argument, and leaves the state's two halves
/// swapped. That is why the first call writes `$state1` and the second
/// `$state0`: after two rounds the roles of the registers have exchanged, and
/// after four they are back where they started.
macro_rules! rounds4 {
    ($state0:ident, $state1:ident, $w:expr, $i:expr) => {
        // SAFETY: `$i` is at most 15, so the four words read from `K` at
        // `4 * $i` end at or before `K[63]`.
        let wk = _mm_add_epi32($w, unsafe {
            _mm_loadu_si128(K.as_ptr().add(4 * $i).cast())
        });
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, wk);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, _mm_shuffle_epi32::<0x0e>(wk));
    };
}

/// First half of producing a group of four schedule words: `SHA256MSG1` folds
/// the small sigma of the words one place ahead into `$prev`. `$cur` is the
/// group that follows `$prev`.
macro_rules! schedule_part1 {
    ($prev:ident, $cur:ident) => {
        $prev = _mm_sha256msg1_epu32($prev, $cur);
    };
}

/// Second half, completing the group `$next` that `schedule_part1` started.
/// `$cur` is the newest finished group and `$prev` the one before it. The
/// schedule adds in the word seven places back, which straddles those two
/// groups and is picked out by a four-byte shift across both; `SHA256MSG2`
/// then adds the remaining small sigma term.
macro_rules! schedule_part2 {
    ($next:ident, $cur:ident, $prev:ident) => {
        $next = _mm_sha256msg2_epu32(
            _mm_add_epi32($next, _mm_alignr_epi8::<4>($cur, $prev)),
            $cur,
        );
    };
}

/// Hashes every full 64-byte block in `blocks` into `state`.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
///
/// # Safety
///
/// The caller must make sure the `sha`, `ssse3` and `sse4.1` CPU features are
/// available. `super::compress` is the only caller, and it checks this
/// already. Nothing else needs checking: we only ever read in 64-byte chunks
/// via `chunks_exact(64)`, so every load below is safely in bounds, and
/// `state` is a fixed-size array.
#[target_feature(enable = "sha,ssse3,sse4.1")]
pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    // This mask reverses the bytes of each 32-bit word of a 128-bit register,
    // because SHA-256 expects the message big-endian. The order of the four
    // words is unchanged.
    let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);

    // SHA-NI wants the state as two registers holding {a, b, e, f} and
    // {c, d, g, h}. Register contents are written here from the top lane down,
    // as in Intel's documentation, so a load from memory of `a, b, c, d` reads
    // `dcba`: the first word lands in the bottom lane.
    // SAFETY: `state` has 8 words, so both 4-word loads are in bounds.
    let (dcba, hgfe) = unsafe {
        (
            _mm_loadu_si128(state.as_ptr().cast()),
            _mm_loadu_si128(state.as_ptr().add(4).cast()),
        )
    };
    let cdab = _mm_shuffle_epi32::<0xb1>(dcba);
    let efgh = _mm_shuffle_epi32::<0x1b>(hgfe);
    let mut state0 = _mm_alignr_epi8::<8>(cdab, efgh); // a, b, e, f
    let mut state1 = _mm_blend_epi16::<0xf0>(efgh, cdab); // c, d, g, h

    for block in blocks.chunks_exact(64) {
        let state0_saved = state0;
        let state1_saved = state1;

        // SAFETY: `chunks_exact(64)` guarantees `block` is exactly 64 bytes,
        // so all four 16-byte loads below are in bounds.
        let (mut m0, mut m1, mut m2, mut m3) = unsafe {
            let p = block.as_ptr();
            (
                _mm_shuffle_epi8(_mm_loadu_si128(p.cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(16).cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(32).cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(48).cast()), mask),
            )
        };

        // The sixteen groups of four rounds, with the message schedule
        // produced alongside: groups 1-12 start the schedule for a group two
        // ahead, and groups 3-14 finish the group one ahead. `m0`..`m3` take
        // turns holding the group of message words being used.
        rounds4!(state0, state1, m0, 0);

        rounds4!(state0, state1, m1, 1);
        schedule_part1!(m0, m1);

        rounds4!(state0, state1, m2, 2);
        schedule_part1!(m1, m2);

        rounds4!(state0, state1, m3, 3);
        schedule_part2!(m0, m3, m2);
        schedule_part1!(m2, m3);

        rounds4!(state0, state1, m0, 4);
        schedule_part2!(m1, m0, m3);
        schedule_part1!(m3, m0);

        rounds4!(state0, state1, m1, 5);
        schedule_part2!(m2, m1, m0);
        schedule_part1!(m0, m1);

        rounds4!(state0, state1, m2, 6);
        schedule_part2!(m3, m2, m1);
        schedule_part1!(m1, m2);

        rounds4!(state0, state1, m3, 7);
        schedule_part2!(m0, m3, m2);
        schedule_part1!(m2, m3);

        rounds4!(state0, state1, m0, 8);
        schedule_part2!(m1, m0, m3);
        schedule_part1!(m3, m0);

        rounds4!(state0, state1, m1, 9);
        schedule_part2!(m2, m1, m0);
        schedule_part1!(m0, m1);

        rounds4!(state0, state1, m2, 10);
        schedule_part2!(m3, m2, m1);
        schedule_part1!(m1, m2);

        rounds4!(state0, state1, m3, 11);
        schedule_part2!(m0, m3, m2);
        schedule_part1!(m2, m3);

        rounds4!(state0, state1, m0, 12);
        schedule_part2!(m1, m0, m3);
        schedule_part1!(m3, m0);

        rounds4!(state0, state1, m1, 13);
        schedule_part2!(m2, m1, m0);

        rounds4!(state0, state1, m2, 14);
        schedule_part2!(m3, m2, m1);

        rounds4!(state0, state1, m3, 15);

        // Add this block's starting state back into the result.
        state0 = _mm_add_epi32(state0, state0_saved);
        state1 = _mm_add_epi32(state1, state1_saved);
    }

    // Undo the shuffle from the start, back into memory order.
    let feba = _mm_shuffle_epi32::<0x1b>(state0);
    let dchg = _mm_shuffle_epi32::<0xb1>(state1);
    let dcba = _mm_blend_epi16::<0xf0>(feba, dchg);
    let hgfe = _mm_alignr_epi8::<8>(dchg, feba);

    // SAFETY: `state` has 8 words, so both 4-word stores are in bounds.
    unsafe {
        _mm_storeu_si128(state.as_mut_ptr().cast(), dcba);
        _mm_storeu_si128(state.as_mut_ptr().add(4).cast(), hgfe);
    }
}
