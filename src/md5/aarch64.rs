//! Lane-parallel MD5 compression using aarch64 NEON, at widths 4, 8 and 16.
//!
//! aarch64 has no MD5 instruction (see the module docs in `super`), so this
//! isn't a one-instruction-per-round backend like `crate::sha::aarch64`.
//! Instead, each 128-bit register holds one state word from four *different*
//! messages, and the normal MD5 step runs on all four at once -- four
//! digests for the price of one dependency chain.
//!
//! NEON maps the step well: `F` and `G` are a single `BSL` (bit-select), `I`
//! uses `ORN`, and the left rotation is `SHL` followed by `SRI`
//! (shift-right-and-insert) -- two instructions, no temporary needed.
//!
//! # Why the widest version uses 16 lanes, not 4
//!
//! Four lanes alone leave the vector units mostly idle: every instruction in
//! MD5's chain has multi-cycle latency, and with only one chain in flight
//! there's nothing to issue while it completes -- measured at only ~1.7x the
//! scalar backend on an M1 Pro. So [`compress_lanes`] splits each state word
//! into `H` independent 128-bit halves and interleaves their instructions,
//! so each half fills in the others' latency gaps. On an M1 Pro that's worth
//! 1.7x at `H = 1`, 3.2x at `H = 2`, and 4.8x at `H = 4` -- for no extra
//! arithmetic -- so `H = 4` is where it stops paying off, making it the
//! widest version. The message words of four halves don't all fit in the 32
//! vector registers and partly spill, but they're off the critical chain and
//! stay in L1 cache.
//!
//! All three widths exist so `super::digest::digest_batch` can step down
//! through them, keeping a batch that isn't a multiple of 16 mostly off the
//! scalar path.
//!
//! Only reachable through `super::digest::digest_batch`, which checks for the
//! `neon` feature first (though it's always available on aarch64 anyway).

use core::arch::aarch64::*;

use super::T;

/// The four nonlinear functions, RFC 1321 section 3.4.
///
/// `vbslq_u32(mask, p, q)` computes `(mask & p) | (!mask & q)`, which is
/// exactly `F` with `mask = x`, and exactly `G` with `mask = z` and the
/// operands swapped. `vornq_u32(p, q)` computes `p | !q`, the inner term of
/// `I`.
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

/// One MD5 step, across the `H` independent 128-bit halves of each state
/// variable. Each `from_fn` below unrolls into `H` back-to-back
/// instructions, so the halves' dependency chains interleave instead of
/// queuing up one after another.
macro_rules! step {
    ($f:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:literal, $i:literal) => {
        // SAFETY: `$x` is a `[u32; W]` with `W == 4 * H` from the caller's
        // array, so half `h` is in bounds for `h < H`.
        let x: [uint32x4_t; H] =
            core::array::from_fn(|h| unsafe { vld1q_u32($x.as_ptr().add(h * 4)) });
        let k = vdupq_n_u32(T[$i]);
        // `$a + m + T` doesn't depend on what the previous step wrote, so
        // this add stays off the critical chain -- only the nonlinear
        // function, one add, the rotate, and the final add remain on it.
        let acc: [uint32x4_t; H] = core::array::from_fn(|h| vaddq_u32(vaddq_u32($a[h], x[h]), k));
        let acc: [uint32x4_t; H] =
            core::array::from_fn(|h| vaddq_u32(acc[h], nonlinear!($f, $b[h], $c[h], $d[h])));
        $a = core::array::from_fn(|h| {
            let rotated = vsriq_n_u32::<{ 32 - $s }>(vshlq_n_u32::<$s>(acc[h]), acc[h]);
            vaddq_u32(rotated, $b[h])
        });
    };
}

/// Compresses one 64-byte block in each of `W` lanes into `state`, holding
/// the lanes as `H` 128-bit halves.
///
/// Both arrays are lane-transposed: `state[k][lane]` is state word `k` of
/// message `lane`, and `m[word][lane]` is message word `word` of message
/// `lane`. `super::digest::group_digest` builds that layout. Lanes
/// `4h..4h + 4` make up half `h`.
///
/// # Safety
///
/// The caller must make sure `neon` is available on this CPU. The
/// `compress*` wrappers below are the only callers; `super::digest` checks
/// the feature before reaching them (though `neon` is always available on
/// aarch64 anyway). No other invariants matter: `W` is fixed to `4 * H` by
/// the const assertion, both arguments are fixed-size arrays, and `h < H`
/// always, so every vector load and store below is in bounds by
/// construction.
#[target_feature(enable = "neon")]
#[inline]
unsafe fn compress_lanes<const W: usize, const H: usize>(
    state: &mut [[u32; W]; 4],
    m: &[[u32; W]; 16],
) {
    const { assert!(W == 4 * H, "each 128-bit half holds exactly 4 u32 lanes") };

    // SAFETY: `state[k]` is a `[u32; 4 * H]`, so half `h` is always in bounds.
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
/// The caller must make sure `neon` is available on this CPU.
/// `super::digest::digest_batch` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress4(state: &mut [[u32; 4]; 4], m: &[[u32; 4]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<4, 1>(state, m) }
}

/// Compresses one 64-byte block in each of 8 lanes. See [`compress_lanes`].
///
/// # Safety
///
/// The caller must make sure `neon` is available on this CPU.
/// `super::digest::digest_batch` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress8(state: &mut [[u32; 8]; 4], m: &[[u32; 8]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<8, 2>(state, m) }
}

/// Compresses one 64-byte block in each of 16 lanes -- the widest and
/// fastest version. See [`compress_lanes`].
///
/// # Safety
///
/// The caller must make sure `neon` is available on this CPU.
/// `super::digest::digest_batch` is the only caller and checks this.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress16(state: &mut [[u32; 16]; 4], m: &[[u32; 16]; 16]) {
    // SAFETY: the caller's obligation is exactly this function's own.
    unsafe { compress_lanes::<16, 4>(state, m) }
}
