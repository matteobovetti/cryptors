//! Portable scalar MD5 compression function.
//!
//! This is the reference implementation: it runs on every target, and the
//! SIMD backends elsewhere in this module are checked against it (see the
//! `matches_scalar_backend` test in `super::digest`).
//!
//! `md5_schedule!` fully unrolls the 64 steps, so the nonlinear function,
//! message word, shift amount, and constant for each step are all known at
//! compile time -- no branches, modulo, or table lookups at runtime.

use super::T;

/// The four nonlinear functions, RFC 1321 section 3.4.
macro_rules! nonlinear {
    (F, $x:expr, $y:expr, $z:expr) => {
        ($x & $y) | (!$x & $z)
    };
    (G, $x:expr, $y:expr, $z:expr) => {
        ($x & $z) | ($y & !$z)
    };
    (H, $x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
    (I, $x:expr, $y:expr, $z:expr) => {
        $y ^ ($x | !$z)
    };
}

/// One MD5 step. `$a`..`$d` are the variables holding the current state in
/// round order; only `$a` is written, and the next step reads the same four
/// variables shifted over by one, so nothing needs to be copied.
macro_rules! step {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:literal, $i:literal) => {
        $a = $a
            .wrapping_add(nonlinear!($f, $b, $c, $d))
            .wrapping_add($x)
            .wrapping_add(T[$i])
            .rotate_left($s)
            .wrapping_add($b);
    };
}

/// Processes one 64-byte block, updating `state` in place.
#[inline]
pub(super) fn process_block(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut m = [0u32; 16];
    for (word, src) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
    }

    let [mut a, mut b, mut c, mut d] = *state;

    md5_schedule!(step, a, b, c, d, m);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// Compresses every full 64-byte block in `blocks` into `state`.
///
/// Leftover bytes that don't form a full block are ignored; the caller is
/// responsible for padding (see `super::digest::digest`).
pub(super) fn compress(state: &mut [u32; 4], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        // `chunks_exact(64)` guarantees this conversion succeeds.
        process_block(state, block.try_into().unwrap());
    }
}
