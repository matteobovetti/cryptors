//! Keccak-f\[1600\] using ARMv8.2's SHA-3 extension (FEAT_SHA3).
//!
//! Four instructions match Keccak's step mappings almost exactly:
//!
//! | Instruction | Computes | Replaces |
//! |-------------|----------|----------|
//! | `EOR3` | `a ^ b ^ c` | two XORs in theta's column parity |
//! | `RAX1` | `a ^ rotl(b, 1)` | theta's `d[x]`, a rotate plus an XOR |
//! | `XAR` | `rotr(a ^ b, n)` | theta's final XOR fused with rho's rotate |
//! | `BCAX` | `a ^ (b & !c)` | all three operations of chi |
//!
//! The last two don't match the macro's contract exactly -- `XAR` rotates the
//! wrong way and `BCAX` negates the wrong operand -- so the wrappers below
//! adjust for both. Each adjustment is free: one is arithmetic on a constant,
//! the other a swap of two arguments.
//!
//! Compiled, a round here is 74 instructions, against 150 for the scalar
//! backend. The speedup over scalar is well short of that ratio, and why has
//! not been established. What is certain is that [`permute`] below leaves
//! half of every register idle: filled with a second message by
//! [`permute_many`], the same routine is much cheaper per message.
//!
//! # Architecture compatibility
//!
//! This backend is AArch64-only and requires the `sha3` CPU feature
//! (FEAT_SHA3, ARMv8.2-SHA3). Every entry point is `unsafe` and gated with
//! `#[target_feature(enable = "neon,sha3")]`, so callers must check for the
//! feature at run time and fall back to the scalar backend on CPUs without it.
//!
//! # One routine, two widths
//!
//! These are all 128-bit instructions operating on two 64-bit lanes, and
//! Keccak's rho rotation depends only on *which* state lane is being
//! rotated, never on the message. So both halves of every register always
//! want the same rotation, and [`permute_pair`] can serve two completely
//! different purposes depending on what gets loaded into those halves:
//!
//! - [`permute`] hashes one message, broadcasting each state lane into both
//!   halves and reading back the low one. The second half recomputes the same
//!   thing and is discarded; the win is purely the fused instructions.
//! - [`permute_many`] hashes two messages, one per half, and gets the fused
//!   instructions *and* twice the width out of the identical code.

use core::arch::aarch64::*;

/// The five operations of [`keccak_round`], each a single instruction.
macro_rules! xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        veor3q_u64(veor3q_u64($a, $b, $c), $d, $e)
    };
}
macro_rules! rax1 {
    ($a:expr, $b:expr) => {
        vrax1q_u64($a, $b)
    };
}
/// `XAR` rotates *right*, but [`keccak_round`]'s contract is a left rotate,
/// so the amount is complemented here. Every rotation the macro asks for is
/// between 1 and 62 -- state lane 0 rotates by zero and uses `$xor!` instead
/// -- so `64 - $r` is always a valid 6-bit immediate and never degenerates
/// into a rotate by 64.
macro_rules! xar {
    ($a:expr, $b:expr, $r:expr) => {
        vxarq_u64::<{ 64 - $r }>($a, $b)
    };
}
macro_rules! xor {
    ($a:expr, $b:expr) => {
        veorq_u64($a, $b)
    };
}
/// `BCAX` computes `a ^ (b & !c)`, but [`keccak_round`]'s contract is
/// `a ^ (!b & c)`, so the last two operands are swapped here.
macro_rules! bcax {
    ($a:expr, $b:expr, $c:expr) => {
        vbcaxq_u64($a, $c, $b)
    };
}
macro_rules! rc {
    ($v:expr) => {
        vdupq_n_u64($v)
    };
}

/// Applies Keccak-f\[1600\] to the two independent states held in the low and
/// high halves of each register.
///
/// # Safety
///
/// The caller must make sure the `sha3` CPU feature is available.
#[target_feature(enable = "neon,sha3")]
unsafe fn permute_pair(state: &mut [uint64x2_t; 25]) {
    keccak_rounds!(xor5, rax1, xar, xor, bcax, state, rc);
}

/// Applies Keccak-f\[1600\] to one state, using the fused instructions.
///
/// # Safety
///
/// The caller must make sure the `sha3` CPU feature is available.
/// `super::digest::permute` is the only caller, and it checks this already.
#[target_feature(enable = "neon,sha3")]
pub(super) unsafe fn permute(state: &mut [u64; 25]) {
    // Both halves get the same lane, so both compute the same permutation;
    // only the low half is read back out.
    let mut wide = [vdupq_n_u64(0); 25];
    for (slot, &lane) in wide.iter_mut().zip(state.iter()) {
        *slot = vdupq_n_u64(lane);
    }

    // SAFETY: this function's own contract guarantees `sha3`.
    unsafe { permute_pair(&mut wide) };

    for (lane, &slot) in state.iter_mut().zip(wide.iter()) {
        *lane = vgetq_lane_u64::<0>(slot);
    }
}

/// Applies Keccak-f\[1600\] to two independent states at once, one message
/// per 64-bit half.
///
/// `state` is transposed -- `state[lane][slot]` holds state lane `lane` of
/// message `slot` -- so each `state[lane]` is exactly one 128-bit register.
///
/// # Safety
///
/// The caller must make sure the `sha3` CPU feature is available.
/// `super::digest::sponge_many` is the only caller, and it checks this
/// already. The loads and stores below are all of a fixed-size array, so
/// they are in bounds by construction.
#[target_feature(enable = "neon,sha3")]
pub(super) unsafe fn permute_many(state: &mut [[u64; 2]; 25]) {
    let mut wide = [vdupq_n_u64(0); 25];
    for (slot, lane) in wide.iter_mut().zip(state.iter()) {
        // SAFETY: `lane` is a `[u64; 2]`, exactly the 16 bytes loaded.
        *slot = unsafe { vld1q_u64(lane.as_ptr()) };
    }

    // SAFETY: this function's own contract guarantees `sha3`.
    unsafe { permute_pair(&mut wide) };

    for (lane, &slot) in state.iter_mut().zip(wide.iter()) {
        // SAFETY: `lane` is a `[u64; 2]`, exactly the 16 bytes stored.
        unsafe { vst1q_u64(lane.as_mut_ptr(), slot) };
    }
}
