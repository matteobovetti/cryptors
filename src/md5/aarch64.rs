//! Lane-parallel MD5 compression using aarch64 NEON, at widths 4, 8 and 16.
//!
//! There is no MD5 instruction on aarch64 (see the module docs in `super`), so
//! this is not a one-instruction-per-round backend like `crate::sha::aarch64`.
//! Instead each 128-bit register holds the same state word of four *different*
//! messages, and the ordinary MD5 step runs on all four at once -- four digests
//! for the price of one dependency chain.
//!
//! NEON maps the step well: the `F` and `G` functions are a single `BSL`
//! (bit-select), `I` uses `ORN`, and the left-rotation is `SHL` followed by
//! `SRI` (shift-right-and-insert), which keeps the rotate at two instructions
//! and no temporary.
//!
//! # Why the widest version is 16 lanes, not 4
//!
//! Four lanes alone leave the vector units mostly idle. Every instruction on
//! MD5's serial chain has multi-cycle latency on NEON, and with one chain in
//! flight there is nothing to issue while it completes -- measured at only
//! ~1.7x the scalar backend on an M1 Pro. So [`compress_lanes`] holds each
//! state word as `H` independent 128-bit halves and interleaves them
//! instruction by instruction, each filling the others' latency. On an M1 Pro
//! that is worth 1.7x at `H = 1`, 3.2x at `H = 2` and 4.8x at `H = 4`, for no
//! extra arithmetic; `H = 4` is where issue width and latency balance out, so
//! that is the widest version. The message words of four halves exceed the 32
//! vector registers and partly spill, but they are off the serial chain and
//! stay in L1.
//!
//! All three widths exist so that `super::digest::digest_many` can step down
//! through them and keep a batch whose size is not a multiple of 16 off the
//! scalar path.
//!
//! Only reachable through `super::digest::digest_many`, which verifies the
//! `neon` target feature first (it is part of the aarch64 baseline).

use core::arch::aarch64::*;

use super::T;

/// The four nonlinear functions, RFC 1321 section 3.4.
///
/// `vbslq_u32(mask, p, q)` yields `(mask & p) | (!mask & q)`, which is exactly
/// `F` with `mask = x`, and exactly `G` with `mask = z` and the operands
/// swapped. `vornq_u32(p, q)` yields `p | !q`, the inner term of `I`.
macro_rules! nonlinear {
    (F, $x:expr, $y:expr, $z:expr) => {
        vbslq_u32($x, $y, $z)
    };
    (G, $x:expr, $y:expr, $z:expr) => {
        vbslq_u32($z, $x, $y)
    };
    (H, $x:expr, $y:expr, $z:expr) => {
        veorq_u32(veorq_u32($x, $y), $z)
    };
    (I, $x:expr, $y:expr, $z:expr) => {
        veorq_u32($y, vornq_u32($x, $z))
    };
}

/// One MD5 step, across the `H` independent 128-bit halves of every state
/// variable. Each `from_fn` below unrolls to `H` back-to-back instructions, so
/// the halves' dependency chains interleave rather than queue up.
macro_rules! step {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:literal, $i:literal) => {
        // SAFETY: `$x` is one element of the caller's `[[u32; W]; 16]`, i.e. a
        // `[u32; W]` with `W == 4 * H`, so half `h` is in bounds for `h < H`.
        let x: [uint32x4_t; H] =
            core::array::from_fn(|h| unsafe { vld1q_u32($x.as_ptr().add(h * 4)) });
        let k = vdupq_n_u32(T[$i]);
        // `$a + m + T` does not depend on the register the previous step wrote,
        // so this add stays off the serial dependency chain; only the nonlinear
        // function, one add, the rotate and the final add remain on it.
        let acc: [uint32x4_t; H] = core::array::from_fn(|h| vaddq_u32(vaddq_u32($a[h], x[h]), k));
        let acc: [uint32x4_t; H] =
            core::array::from_fn(|h| vaddq_u32(acc[h], nonlinear!($f, $b[h], $c[h], $d[h])));
        $a = core::array::from_fn(|h| {
            let rotated = vsriq_n_u32::<{ 32 - $s }>(vshlq_n_u32::<$s>(acc[h]), acc[h]);
            vaddq_u32(rotated, $b[h])
        });
    };
}

/// Compresses one 64-byte block in each of `W` lanes into `state`, holding the
/// lanes as `H` 128-bit halves.
///
/// Both arrays are lane-transposed: `state[k][lane]` is state word `k` of
/// message `lane`, and `m[word][lane]` is message word `word` of message
/// `lane`. `super::digest::group_digest` produces that layout. Lanes
/// `4h..4h + 4` are half `h`.
///
/// # Safety
///
/// The caller must ensure the `neon` target feature is available on this CPU.
/// The `compress*` wrappers below are the only callers; `super::digest` checks
/// the feature before reaching them. No other invariants are required: `W` is
/// pinned to `4 * H` by the const assertion, both arguments are fixed-size
/// arrays, and `h < H` throughout, so every vector load and store below is in
/// bounds by construction.
#[target_feature(enable = "neon")]
#[inline]
unsafe fn compress_lanes<const W: usize, const H: usize>(
    state: &mut [[u32; W]; 4],
    m: &[[u32; W]; 16],
) {
    const { assert!(W == 4 * H, "each 128-bit half holds exactly 4 u32 lanes") };

    // SAFETY: `state[k]` is a `[u32; 4 * H]`, so half `h` is in bounds.
    let [a0, b0, c0, d0] = unsafe {
        [0usize, 1, 2, 3].map(|k| {
            core::array::from_fn::<uint32x4_t, H, _>(|h| vld1q_u32(state[k].as_ptr().add(h * 4)))
        })
    };
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    md5_schedule!(step, a, b, c, d, m);

    // Feed-forward: add each lane's starting state back in. SAFETY: as above.
    unsafe {
        for (k, (start, end)) in [(a0, a), (b0, b), (c0, c), (d0, d)].into_iter().enumerate() {
            for h in 0..H {
                vst1q_u32(
                    state[k].as_mut_ptr().add(h * 4),
                    vaddq_u32(start[h], end[h]),
                );
            }
        }
    }
}

/// Compresses one 64-byte block in each of 4 lanes. See [`compress_lanes`].
///
/// # Safety
///
/// The caller must ensure the `neon` target feature is available on this CPU.
/// `super::digest::digest_many` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress4(state: &mut [[u32; 4]; 4], m: &[[u32; 4]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<4, 1>(state, m) }
}

/// Compresses one 64-byte block in each of 8 lanes. See [`compress_lanes`].
///
/// # Safety
///
/// The caller must ensure the `neon` target feature is available on this CPU.
/// `super::digest::digest_many` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress8(state: &mut [[u32; 8]; 4], m: &[[u32; 8]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<8, 2>(state, m) }
}

/// Compresses one 64-byte block in each of 16 lanes -- the widest and fastest
/// version. See [`compress_lanes`].
///
/// # Safety
///
/// The caller must ensure the `neon` target feature is available on this CPU.
/// `super::digest::digest_many` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress16(state: &mut [[u32; 16]; 4], m: &[[u32; 16]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<16, 4>(state, m) }
}
