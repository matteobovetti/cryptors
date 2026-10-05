//! SHA-512 compression using ARMv8.2's SHA-512 instructions (FEAT_SHA512).
//!
//! `SHA512H` and `SHA512H2` each update half of the state for two rounds at
//! once, and `SHA512SU0`/`SHA512SU1` compute two message-schedule words at
//! once. So each block takes 40 pairs of state instructions here instead of 80
//! rounds in the scalar version.
//!
//! Rust reports FEAT_SHA512 together with FEAT_SHA3 (the instructions SHA-3
//! uses) as a single CPU feature, `sha3`, and every CPU that has the one has
//! the other. This code only runs via `super::compress`, which checks that
//! feature is present before calling it.

use core::arch::aarch64::*;

use super::K;

/// Runs two rounds. `$w` holds the two message-schedule words for these rounds
/// and `$i` is the group number (0 to 39), which selects the two round
/// constants to add in.
///
/// The state is four vectors of two words each, `$ab`, `$cd`, `$ef` and `$gh`,
/// with the earlier letter in the lower lane. `SHA512H` wants its inputs
/// lined up differently from how they are stored, so `vextq_u64::<1>` builds
/// the pairs it needs out of neighbouring vectors:
///
/// - `$gh + K + W`, with the two sums swapped so that `h + K[t] + W[t]`, the
///   term the first round starts from, sits in the upper lane. This is
///   `SHA512H`'s accumulator, and its result holds `T1` of both rounds.
/// - `(f, g)` and `(d, e)`, the other state words that the two rounds' `Ch`
///   and `Sigma1` read.
///
/// `T1` plus `d` is the new `e` of each round, and `SHA512H2` adds `T2` to
/// `T1` for the new `a`. After two rounds the new `(c, d)` is the old `(a, b)`
/// and the new `(g, h)` is the old `(e, f)`, so nothing moves; the variables
/// just change names.
macro_rules! rounds2 {
    ($ab:ident, $cd:ident, $ef:ident, $gh:ident, $w:expr, $i:expr) => {
        // SAFETY: `$i` is at most 39, so the two words read from `K` at
        // `2 * $i` end at or before `K[79]`.
        let wk = vaddq_u64($w, unsafe { vld1q_u64(K.as_ptr().add(2 * $i)) });
        let gh_wk = vaddq_u64($gh, vextq_u64::<1>(wk, wk));
        let t1 = vsha512hq_u64(gh_wk, vextq_u64::<1>($ef, $gh), vextq_u64::<1>($cd, $ef));
        let ef_next = vaddq_u64($cd, t1);
        let ab_next = vsha512h2q_u64(t1, $cd, $ab);
        $gh = $ef;
        $cd = $ab;
        $ef = ef_next;
        $ab = ab_next;
    };
}

/// Replaces `$m0`, the oldest two schedule words, with the two that come
/// sixteen words after it. The other arguments are the vectors holding the
/// words `t - 14`, `t - 8`, `t - 6` and `t - 2` (each pair's first word),
/// where `t` is the first new word: `$m1` the next pair after `$m0`, `$m4` and
/// `$m5` the two that straddle `w[t-7]`, and `$m7` the newest pair.
///
/// `SHA512SU0` adds the small sigma of the words one place ahead into
/// `w[t-16]`; `SHA512SU1` then adds `w[t-7]`, picked out by a one-word shift
/// across `$m4` and `$m5`, and the other small sigma of the newest words.
macro_rules! next_words {
    ($m0:ident, $m1:ident, $m4:ident, $m5:ident, $m7:ident) => {
        $m0 = vsha512su1q_u64(vsha512su0q_u64($m0, $m1), $m7, vextq_u64::<1>($m4, $m5));
    };
}

/// Runs eight groups of two rounds (sixteen rounds), the first being group
/// `$g`, each followed by the schedule step that replaces the words it just
/// used with the ones needed eight groups later. `$m0`..`$m7` take turns
/// holding the group being used, so the arguments of `next_words!` advance by
/// one place per group, wrapping around.
macro_rules! sixteen_rounds {
    ($ab:ident, $cd:ident, $ef:ident, $gh:ident,
     $m0:ident, $m1:ident, $m2:ident, $m3:ident, $m4:ident, $m5:ident, $m6:ident, $m7:ident,
     $g:expr) => {
        rounds2!($ab, $cd, $ef, $gh, $m0, $g);
        next_words!($m0, $m1, $m4, $m5, $m7);
        rounds2!($ab, $cd, $ef, $gh, $m1, $g + 1);
        next_words!($m1, $m2, $m5, $m6, $m0);
        rounds2!($ab, $cd, $ef, $gh, $m2, $g + 2);
        next_words!($m2, $m3, $m6, $m7, $m1);
        rounds2!($ab, $cd, $ef, $gh, $m3, $g + 3);
        next_words!($m3, $m4, $m7, $m0, $m2);
        rounds2!($ab, $cd, $ef, $gh, $m4, $g + 4);
        next_words!($m4, $m5, $m0, $m1, $m3);
        rounds2!($ab, $cd, $ef, $gh, $m5, $g + 5);
        next_words!($m5, $m6, $m1, $m2, $m4);
        rounds2!($ab, $cd, $ef, $gh, $m6, $g + 6);
        next_words!($m6, $m7, $m2, $m3, $m5);
        rounds2!($ab, $cd, $ef, $gh, $m7, $g + 7);
        next_words!($m7, $m0, $m3, $m4, $m6);
    };
}

/// Hashes every full 128-byte block in `blocks` into `state`.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
///
/// # Safety
///
/// The caller must make sure the `sha3` CPU feature (which includes
/// FEAT_SHA512) is available. `super::compress` is the only caller, and it
/// checks this already. Nothing else needs checking: the input is split into
/// whole 128-byte blocks with `as_chunks`, so every load below is safely in
/// bounds, and `state` is a fixed-size array.
#[target_feature(enable = "sha3")]
pub(super) unsafe fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    // a, b live together in one vector register, then c, d, and so on, with
    // the earlier letter in the lower lane, which is also memory order.
    // SAFETY: `state` has 8 words, so all four 2-word loads are in bounds.
    let (mut ab, mut cd, mut ef, mut gh) = unsafe {
        let p = state.as_ptr();
        (
            vld1q_u64(p),
            vld1q_u64(p.add(2)),
            vld1q_u64(p.add(4)),
            vld1q_u64(p.add(6)),
        )
    };

    let (blocks, _) = blocks.as_chunks::<128>();
    for block in blocks {
        let (ab_saved, cd_saved, ef_saved, gh_saved) = (ab, cd, ef, gh);

        // SHA-512 expects the message big-endian; `rev64` byte-swaps two
        // 64-bit words at once to get there.
        // SAFETY: `block` is exactly 128 bytes, so all eight 16-byte loads
        // below are in bounds.
        let (mut m0, mut m1, mut m2, mut m3, mut m4, mut m5, mut m6, mut m7) = unsafe {
            let p = block.as_ptr();
            (
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(16)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(32)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(48)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(64)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(80)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(96)))),
                vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(112)))),
            )
        };

        // Groups 0-31: each group of two rounds uses one vector of message
        // words, then replaces it with the words needed eight groups later.
        // Doing the two together keeps the schedule just ahead of the rounds,
        // so the round instructions never wait for their inputs.
        sixteen_rounds!(ab, cd, ef, gh, m0, m1, m2, m3, m4, m5, m6, m7, 0);
        sixteen_rounds!(ab, cd, ef, gh, m0, m1, m2, m3, m4, m5, m6, m7, 8);
        sixteen_rounds!(ab, cd, ef, gh, m0, m1, m2, m3, m4, m5, m6, m7, 16);
        sixteen_rounds!(ab, cd, ef, gh, m0, m1, m2, m3, m4, m5, m6, m7, 24);

        // Groups 32-39: the whole schedule has been produced by now.
        rounds2!(ab, cd, ef, gh, m0, 32);
        rounds2!(ab, cd, ef, gh, m1, 33);
        rounds2!(ab, cd, ef, gh, m2, 34);
        rounds2!(ab, cd, ef, gh, m3, 35);
        rounds2!(ab, cd, ef, gh, m4, 36);
        rounds2!(ab, cd, ef, gh, m5, 37);
        rounds2!(ab, cd, ef, gh, m6, 38);
        rounds2!(ab, cd, ef, gh, m7, 39);

        // Add this block's starting state back into the result.
        ab = vaddq_u64(ab, ab_saved);
        cd = vaddq_u64(cd, cd_saved);
        ef = vaddq_u64(ef, ef_saved);
        gh = vaddq_u64(gh, gh_saved);
    }

    // SAFETY: `state` has 8 words, so all four 2-word stores are in bounds.
    unsafe {
        let p = state.as_mut_ptr();
        vst1q_u64(p, ab);
        vst1q_u64(p.add(2), cd);
        vst1q_u64(p.add(4), ef);
        vst1q_u64(p.add(6), gh);
    }
}
