//! Portable scalar SHA-1 compression function.
//!
//! This is the reference implementation: it runs everywhere, and the hardware
//! backends in this module are differential-tested against it (see the
//! `matches_scalar_backend` test in the parent module).
//!
//! The 80 steps are fully unrolled, so the round function, message-word index
//! and round constant are all known at compile time -- no per-step branch or
//! table lookup. The message schedule lives in a 16-word ring buffer rather
//! than materializing all 80 words, so each schedule word is computed once, in
//! place, right before it is consumed.

use super::K;

macro_rules! f1 {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) | (!$x & $z)
    };
}
macro_rules! f2 {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}
macro_rules! f3 {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) | ($x & $z) | ($y & $z)
    };
}

/// One SHA-1 step. `$a`..`$e` name the physical variables holding the current
/// (A, B, C, D, E) state in round order. Only two writes happen per step: the
/// new `A` (TEMP) goes into the slot passed as `$e` (whose old value is dead,
/// since `E_next = D`), and the new `C` goes into the slot passed as `$b`
/// (dead too, since `B_next = A`). The next step reads the same five variables
/// rotated one position right, so the other three need no copying.
macro_rules! step {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $k:expr, $x:expr) => {
        $e = $e
            .wrapping_add($a.rotate_left(5))
            .wrapping_add($f!($b, $c, $d))
            .wrapping_add($k)
            .wrapping_add($x);
        $b = $b.rotate_left(30);
    };
}

/// Compresses every complete 64-byte block in `blocks` into `state`.
///
/// Any trailing bytes that do not form a full block are ignored; callers are
/// responsible for padding (see `super::digest`).
pub(super) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        process_block(state, block);
    }
}

#[inline]
fn process_block(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 16];
    for (word, src) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;

    // `w` is a 16-word ring buffer: slot `t & 15` holds message word `t`. For
    // t >= 16 the schedule is `rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1)`;
    // `w[t-16]` lives in the very slot being overwritten, so each update below
    // reads it as `w[t & 15]` before storing the new value there. The other
    // three indices are `(t - {3,8,14}) & 15`, folded to literals.
    step!(f1, a, b, c, d, e, K[0], w[0]);
    step!(f1, e, a, b, c, d, K[0], w[1]);
    step!(f1, d, e, a, b, c, K[0], w[2]);
    step!(f1, c, d, e, a, b, K[0], w[3]);
    step!(f1, b, c, d, e, a, K[0], w[4]);
    step!(f1, a, b, c, d, e, K[0], w[5]);
    step!(f1, e, a, b, c, d, K[0], w[6]);
    step!(f1, d, e, a, b, c, K[0], w[7]);
    step!(f1, c, d, e, a, b, K[0], w[8]);
    step!(f1, b, c, d, e, a, K[0], w[9]);
    step!(f1, a, b, c, d, e, K[0], w[10]);
    step!(f1, e, a, b, c, d, K[0], w[11]);
    step!(f1, d, e, a, b, c, K[0], w[12]);
    step!(f1, c, d, e, a, b, K[0], w[13]);
    step!(f1, b, c, d, e, a, K[0], w[14]);
    step!(f1, a, b, c, d, e, K[0], w[15]);
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    step!(f1, e, a, b, c, d, K[0], w[0]);
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    step!(f1, d, e, a, b, c, K[0], w[1]);
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    step!(f1, c, d, e, a, b, K[0], w[2]);
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    step!(f1, b, c, d, e, a, K[0], w[3]);
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[1], w[4]);
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[1], w[5]);
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[1], w[6]);
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[1], w[7]);
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[1], w[8]);
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[1], w[9]);
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[1], w[10]);
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[1], w[11]);
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[1], w[12]);
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[1], w[13]);
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[1], w[14]);
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[1], w[15]);
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[1], w[0]);
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[1], w[1]);
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[1], w[2]);
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[1], w[3]);
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[1], w[4]);
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[1], w[5]);
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[1], w[6]);
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[1], w[7]);
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    step!(f3, a, b, c, d, e, K[2], w[8]);
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    step!(f3, e, a, b, c, d, K[2], w[9]);
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    step!(f3, d, e, a, b, c, K[2], w[10]);
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    step!(f3, c, d, e, a, b, K[2], w[11]);
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    step!(f3, b, c, d, e, a, K[2], w[12]);
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    step!(f3, a, b, c, d, e, K[2], w[13]);
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    step!(f3, e, a, b, c, d, K[2], w[14]);
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    step!(f3, d, e, a, b, c, K[2], w[15]);
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    step!(f3, c, d, e, a, b, K[2], w[0]);
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    step!(f3, b, c, d, e, a, K[2], w[1]);
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    step!(f3, a, b, c, d, e, K[2], w[2]);
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    step!(f3, e, a, b, c, d, K[2], w[3]);
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    step!(f3, d, e, a, b, c, K[2], w[4]);
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    step!(f3, c, d, e, a, b, K[2], w[5]);
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    step!(f3, b, c, d, e, a, K[2], w[6]);
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    step!(f3, a, b, c, d, e, K[2], w[7]);
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    step!(f3, e, a, b, c, d, K[2], w[8]);
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    step!(f3, d, e, a, b, c, K[2], w[9]);
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    step!(f3, c, d, e, a, b, K[2], w[10]);
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    step!(f3, b, c, d, e, a, K[2], w[11]);
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[3], w[12]);
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[3], w[13]);
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[3], w[14]);
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[3], w[15]);
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[3], w[0]);
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[3], w[1]);
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[3], w[2]);
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[3], w[3]);
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[3], w[4]);
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[3], w[5]);
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[3], w[6]);
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[3], w[7]);
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[3], w[8]);
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[3], w[9]);
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[3], w[10]);
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    step!(f2, a, b, c, d, e, K[3], w[11]);
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    step!(f2, e, a, b, c, d, K[3], w[12]);
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    step!(f2, d, e, a, b, c, K[3], w[13]);
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    step!(f2, c, d, e, a, b, K[3], w[14]);
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    step!(f2, b, c, d, e, a, K[3], w[15]);
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}
