//! SHA-256 compression using ARMv8's crypto extensions (FEAT_SHA256).
//!
//! `SHA256H` and `SHA256H2` each update half of the state (`a`-`d` and
//! `e`-`h`) for four rounds at once, and `SHA256SU0`/`SHA256SU1` compute four
//! message-schedule words at once. So each block takes 16 pairs of state
//! instructions here instead of 64 rounds in the scalar version.
//!
//! This code only runs via `super::compress`, which checks the `sha2` CPU
//! feature is present before calling it.

use core::arch::aarch64::*;
use core::arch::asm;

use super::K;

/// Returns `v` unchanged, through an empty block of inline assembly that the
/// compiler cannot see into, so the result counts as a separate value.
///
/// `rounds4!` uses this to decide where the one copy each group needs goes.
/// `SHA256H` overwrites its `a`-`d` input with the result, but `SHA256H2`
/// still needs the old `a`-`d`, so one of the two has to work on a copy.
/// Left to itself, the compiler hands `SHA256H` the copy and keeps the
/// original for `SHA256H2`. That puts the copy between one group's `SHA256H`
/// and the next, the chain every group waits on, so the copy's latency is
/// paid sixteen times per block. Taking the copy through here instead makes
/// it the operand `SHA256H2` reads, so `SHA256H` can update `a`-`d` in place
/// and the copy runs alongside it.
#[inline(always)]
fn opaque(mut v: uint32x4_t) -> uint32x4_t {
    // SAFETY: the template is empty, so nothing is executed. The block only
    // claims to read and write `v`'s register; it touches no memory, stack or
    // flags, as its options state.
    unsafe {
        asm!("/* {0:v} */", inout(vreg) v, options(pure, nomem, nostack, preserves_flags));
    }
    v
}

/// Runs four rounds. `$w` holds the four message-schedule words for these
/// rounds and `$i` is the group number (0 to 15), which selects the four round
/// constants to add in.
///
/// `SHA256H2` needs the `a`-`d` half as it was *before* this group, to update
/// `e`-`h` with, so a copy is taken first, via `opaque` (see there for why).
macro_rules! rounds4 {
    ($abcd:ident, $efgh:ident, $w:expr, $i:expr) => {
        // SAFETY: `$i` is at most 15, so the four words read from `K` at
        // `4 * $i` end at or before `K[63]`.
        let wk = vaddq_u32($w, unsafe { vld1q_u32(K.as_ptr().add(4 * $i)) });
        let abcd_before = opaque($abcd);
        $abcd = vsha256hq_u32($abcd, $efgh, wk);
        $efgh = vsha256h2q_u32($efgh, abcd_before, wk);
    };
}

/// Replaces `$w0`, the oldest four schedule words, with the four that come
/// sixteen words after it. `$w1`, `$w2` and `$w3` are the following groups of
/// four, in order.
macro_rules! next_words {
    ($w0:ident, $w1:ident, $w2:ident, $w3:ident) => {
        $w0 = vsha256su1q_u32(vsha256su0q_u32($w0, $w1), $w2, $w3);
    };
}

/// Hashes every full 64-byte block in `blocks` into `state`.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
///
/// # Safety
///
/// The caller must make sure the `sha2` CPU feature is available.
/// `super::compress` is the only caller, and it checks this already. Nothing
/// else needs checking: we only ever read in 64-byte chunks via
/// `chunks_exact(64)`, so every load below is safely in bounds, and `state`
/// is a fixed-size array.
#[target_feature(enable = "sha2")]
pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    // a, b, c, d live together in one vector register and e, f, g, h in
    // another, in the order the instructions expect.
    // SAFETY: `state` has 8 words, so both 4-word loads are in bounds.
    let (mut abcd, mut efgh) =
        unsafe { (vld1q_u32(state.as_ptr()), vld1q_u32(state.as_ptr().add(4))) };

    for block in blocks.chunks_exact(64) {
        let abcd_saved = abcd;
        let efgh_saved = efgh;

        // SHA-256 expects the message big-endian; `rev32` byte-swaps four
        // 32-bit words at once to get there.
        // SAFETY: `chunks_exact(64)` guarantees `block` is exactly 64 bytes,
        // so all four 16-byte loads below are in bounds.
        let (mut m0, mut m1, mut m2, mut m3) = unsafe {
            let p = block.as_ptr();
            (
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48)))),
            )
        };

        // Rounds 0-47: each group of four rounds uses one vector of message
        // words, then replaces it with the words needed four groups later.
        // Doing the two together keeps the schedule just ahead of the rounds,
        // so the round instructions never wait for their inputs.
        rounds4!(abcd, efgh, m0, 0);
        next_words!(m0, m1, m2, m3);
        rounds4!(abcd, efgh, m1, 1);
        next_words!(m1, m2, m3, m0);
        rounds4!(abcd, efgh, m2, 2);
        next_words!(m2, m3, m0, m1);
        rounds4!(abcd, efgh, m3, 3);
        next_words!(m3, m0, m1, m2);

        rounds4!(abcd, efgh, m0, 4);
        next_words!(m0, m1, m2, m3);
        rounds4!(abcd, efgh, m1, 5);
        next_words!(m1, m2, m3, m0);
        rounds4!(abcd, efgh, m2, 6);
        next_words!(m2, m3, m0, m1);
        rounds4!(abcd, efgh, m3, 7);
        next_words!(m3, m0, m1, m2);

        rounds4!(abcd, efgh, m0, 8);
        next_words!(m0, m1, m2, m3);
        rounds4!(abcd, efgh, m1, 9);
        next_words!(m1, m2, m3, m0);
        rounds4!(abcd, efgh, m2, 10);
        next_words!(m2, m3, m0, m1);
        rounds4!(abcd, efgh, m3, 11);
        next_words!(m3, m0, m1, m2);

        // Rounds 48-63: the whole schedule has been produced by now.
        rounds4!(abcd, efgh, m0, 12);
        rounds4!(abcd, efgh, m1, 13);
        rounds4!(abcd, efgh, m2, 14);
        rounds4!(abcd, efgh, m3, 15);

        // Add this block's starting state back into the result.
        abcd = vaddq_u32(abcd, abcd_saved);
        efgh = vaddq_u32(efgh, efgh_saved);
    }

    // SAFETY: `state` has 8 words, so both 4-word stores are in bounds.
    unsafe {
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }
}
