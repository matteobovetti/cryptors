//! Plain, portable Keccak-f\[1600\] -- no CPU-specific instructions.
//!
//! This is the trusted reference implementation: it runs on any CPU, and
//! every other backend is checked against it by the `matches_scalar_backend`
//! test in [`super::digest`].
//!
//! # Why this backend has its own round
//!
//! The vector backends share [`keccak_round`], which builds all 25 rho/pi
//! outputs before running chi on any of them. Vector register files hold that
//! comfortably. A general-purpose register file does not: about 30 values are
//! live at once, against 16 registers on x86-64, so a third of every round
//! went to stack spills.
//!
//! [`permute`] instead finishes one row of five lanes at a time and writes it
//! straight back into the five slots its inputs were read from -- the "in-place"
//! technique of the Keccak team's reference code (`Keccak-inplace.c`). That keeps
//! the live set down to about a dozen values. The price is that lanes don't
//! stay put: see [`LAYOUT`] for where they go, and why the layout is back to
//! normal every four rounds.
//!
//! # Architecture compatibility
//!
//! The code is plain Rust with no intrinsics or inline assembly, so it builds
//! and runs unchanged on every target, including x86-64 and AArch64. On
//! x86-64 it cuts stack traffic from 85 to 68 accesses per round, and to 57
//! when built with BMI1/BMI2.
//!
//! The round is still written in terms of the same five operations. The
//! test-only `permute_many` below still drives the shared macro, so
//! `scalar_many_matches_scalar` checks the two formulations against each
//! other.

use super::digest::RC;

/// Scalar forms of the five operations the round macros are written in terms
/// of. None of these map to a fused instruction here; that is the whole point
/// of the hardware backends.
macro_rules! xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        $a ^ $b ^ $c ^ $d ^ $e
    };
}
macro_rules! rax1 {
    ($a:expr, $b:expr) => {
        $a ^ $b.rotate_left(1)
    };
}
macro_rules! xar {
    ($a:expr, $b:expr, $r:expr) => {
        ($a ^ $b).rotate_left($r)
    };
}
macro_rules! xor {
    ($a:expr, $b:expr) => {
        $a ^ $b
    };
}
macro_rules! bcax {
    ($a:expr, $b:expr, $c:expr) => {
        $a ^ (!$b & $c)
    };
}

/// Where each lane is stored before each of the four rounds of a group, and
/// (`LAYOUT[4]`) after the last: lane `n` of the logical state, `n = x + 5y`,
/// lives in slot `LAYOUT[k][n]` of the array.
///
/// Every layout has the form "lane `(x, y)` is in slot `(x, a*x + b*y mod 5)`".
/// Lanes never leave their column, so theta's column sums read the same slots
/// whatever the layout. Only `(a, b)` changes from round to round.
///
/// It changes like this because of chi. chi's output row `y` is built from the
/// five rho/pi outputs `B[x', y]`, and FIPS 202's pi takes those from lanes
/// `(x' + 3y, x')`. To write the row back over exactly the slots it read, and
/// still keep each output lane in its own column, output `(x, y)` must take the
/// slot of the input with `x' + 3y = x`, i.e. `x' = x + 2y`. That slot is
/// `(x, a*x + b*(x + 2y)) = (x, (a + b)*x + 2b*y)`, so each round turns `(a, b)`
/// into `(a + b, 2b)`.
///
/// Starting from the normal layout `(0, 1)`, that runs `(1, 2)`, `(3, 4)`,
/// `(2, 3)` and back to `(0, 1)`: the state is in normal order again every
/// four rounds, which is why [`permute`] runs the rounds four at a time. The
/// assertions below check all of this at compile time.
const LAYOUT: [[usize; 25]; 5] = {
    let mut layout = [[0; 25]; 5];
    let (mut a, mut b) = (0, 1);
    let mut k = 0;
    while k < 5 {
        let mut lane = 0;
        while lane < 25 {
            let (x, y) = (lane % 5, lane / 5);
            layout[k][lane] = x + 5 * ((a * x + b * y) % 5);
            lane += 1;
        }
        (a, b) = ((a + b) % 5, (2 * b) % 5);
        k += 1;
    }
    layout
};

/// The lane FIPS 202's pi moves into lane `n`: `pi` sends `(x, y)` to
/// `(y, 2x + 3y)`, so lane `(x, y)` is filled from `(x + 3y, x)`.
const fn pi_source(n: usize) -> usize {
    let (x, y) = (n % 5, n / 5);
    (x + 3 * y) % 5 + 5 * x
}

// Compile-time proof that the schedule in `LAYOUT` is sound. A wrong table
// fails the build here instead of producing wrong digests.
const _: () = {
    let mut k = 0;
    while k < 5 {
        let mut used = [false; 25];
        let mut n = 0;
        while n < 25 {
            let slot = LAYOUT[k][n];
            assert!(!used[slot], "every layout stores each lane exactly once");
            assert!(
                slot % 5 == n % 5,
                "every layout keeps lanes in their column"
            );
            used[slot] = true;
            n += 1;
        }
        k += 1;
    }

    let mut n = 0;
    while n < 25 {
        assert!(LAYOUT[0][n] == n, "a group starts from the normal layout");
        assert!(LAYOUT[4][n] == n, "and is back to it after four rounds");
        n += 1;
    }

    // The in-place property: each round writes output row `y` only over slots
    // that held that same row's inputs, so no row can clobber a lane another
    // row has yet to read. Both sides are five distinct slots (layouts and pi
    // are permutations), so "each write is one of the reads" means the two
    // sets are equal.
    let mut k = 0;
    while k < 4 {
        let mut n = 0;
        while n < 25 {
            let written = LAYOUT[k + 1][n];
            let row = n - n % 5;
            let mut found = false;
            let mut x = 0;
            while x < 5 {
                found |= LAYOUT[k][pi_source(row + x)] == written;
                x += 1;
            }
            assert!(found, "every output slot is one its own row just read");
            n += 1;
        }
        k += 1;
    }
};

/// One round of Keccak-f\[1600\], in place: round `$k` (0 to 3) of a group of
/// four.
///
/// This is [`keccak_round`] with two changes. Every state access goes through
/// the layout: lane `n` is read from `$a[IN[n]]` and written to `$a[OUT[n]]`.
/// And chi runs one row at a time, as soon as that row's five rho/pi outputs
/// exist. The sources, theta column and rho rotation of each `b` are the same
/// as in [`keccak_round`], line for line.
///
/// `$k` must be a literal: the layouts are indexed with compile-time constants
/// so every state access is to a fixed slot. With loop-computed indices the
/// same round was measured 10x slower.
macro_rules! keccak_round_in_place {
    (
        $xor5:ident, $rax1:ident, $xar:ident, $xor:ident, $bcax:ident,
        $a:ident, $k:literal, $rc:expr
    ) => {{
        const IN: [usize; 25] = LAYOUT[$k];
        const OUT: [usize; 25] = LAYOUT[$k + 1];

        // Theta, part 1: the parity of each of the five columns.
        let c0 = $xor5!($a[IN[0]], $a[IN[5]], $a[IN[10]], $a[IN[15]], $a[IN[20]]);
        let c1 = $xor5!($a[IN[1]], $a[IN[6]], $a[IN[11]], $a[IN[16]], $a[IN[21]]);
        let c2 = $xor5!($a[IN[2]], $a[IN[7]], $a[IN[12]], $a[IN[17]], $a[IN[22]]);
        let c3 = $xor5!($a[IN[3]], $a[IN[8]], $a[IN[13]], $a[IN[18]], $a[IN[23]]);
        let c4 = $xor5!($a[IN[4]], $a[IN[9]], $a[IN[14]], $a[IN[19]], $a[IN[24]]);

        // Theta, part 2: d[x] = c[x - 1] ^ rotl(c[x + 1], 1).
        let d0 = $rax1!(c4, c1);
        let d1 = $rax1!(c0, c2);
        let d2 = $rax1!(c1, c3);
        let d3 = $rax1!(c2, c4);
        let d4 = $rax1!(c3, c0);

        // Theta part 3 + rho + pi for one output row, then chi on that row,
        // written back over the slots the row was just read from. Iota rides
        // along with lane 0.
        let b0 = $xor!($a[IN[0]], d0);
        let b1 = $xar!($a[IN[6]], d1, 44);
        let b2 = $xar!($a[IN[12]], d2, 43);
        let b3 = $xar!($a[IN[18]], d3, 21);
        let b4 = $xar!($a[IN[24]], d4, 14);
        $a[OUT[0]] = $xor!($bcax!(b0, b1, b2), $rc);
        $a[OUT[1]] = $bcax!(b1, b2, b3);
        $a[OUT[2]] = $bcax!(b2, b3, b4);
        $a[OUT[3]] = $bcax!(b3, b4, b0);
        $a[OUT[4]] = $bcax!(b4, b0, b1);

        let b5 = $xar!($a[IN[3]], d3, 28);
        let b6 = $xar!($a[IN[9]], d4, 20);
        let b7 = $xar!($a[IN[10]], d0, 3);
        let b8 = $xar!($a[IN[16]], d1, 45);
        let b9 = $xar!($a[IN[22]], d2, 61);
        $a[OUT[5]] = $bcax!(b5, b6, b7);
        $a[OUT[6]] = $bcax!(b6, b7, b8);
        $a[OUT[7]] = $bcax!(b7, b8, b9);
        $a[OUT[8]] = $bcax!(b8, b9, b5);
        $a[OUT[9]] = $bcax!(b9, b5, b6);

        let b10 = $xar!($a[IN[1]], d1, 1);
        let b11 = $xar!($a[IN[7]], d2, 6);
        let b12 = $xar!($a[IN[13]], d3, 25);
        let b13 = $xar!($a[IN[19]], d4, 8);
        let b14 = $xar!($a[IN[20]], d0, 18);
        $a[OUT[10]] = $bcax!(b10, b11, b12);
        $a[OUT[11]] = $bcax!(b11, b12, b13);
        $a[OUT[12]] = $bcax!(b12, b13, b14);
        $a[OUT[13]] = $bcax!(b13, b14, b10);
        $a[OUT[14]] = $bcax!(b14, b10, b11);

        let b15 = $xar!($a[IN[4]], d4, 27);
        let b16 = $xar!($a[IN[5]], d0, 36);
        let b17 = $xar!($a[IN[11]], d1, 10);
        let b18 = $xar!($a[IN[17]], d2, 15);
        let b19 = $xar!($a[IN[23]], d3, 56);
        $a[OUT[15]] = $bcax!(b15, b16, b17);
        $a[OUT[16]] = $bcax!(b16, b17, b18);
        $a[OUT[17]] = $bcax!(b17, b18, b19);
        $a[OUT[18]] = $bcax!(b18, b19, b15);
        $a[OUT[19]] = $bcax!(b19, b15, b16);

        let b20 = $xar!($a[IN[2]], d2, 62);
        let b21 = $xar!($a[IN[8]], d3, 55);
        let b22 = $xar!($a[IN[14]], d4, 39);
        let b23 = $xar!($a[IN[15]], d0, 41);
        let b24 = $xar!($a[IN[21]], d1, 2);
        $a[OUT[20]] = $bcax!(b20, b21, b22);
        $a[OUT[21]] = $bcax!(b21, b22, b23);
        $a[OUT[22]] = $bcax!(b22, b23, b24);
        $a[OUT[23]] = $bcax!(b23, b24, b20);
        $a[OUT[24]] = $bcax!(b24, b20, b21);
    }};
}

/// All 24 rounds, four per loop iteration so the state is in normal order at
/// every iteration boundary. Shared by [`permute`] and, on x86-64,
/// `permute_bmi`, which differ only in the instructions they are compiled to.
#[inline(always)]
fn rounds(state: &mut [u64; 25]) {
    for &[rc0, rc1, rc2, rc3] in RC.as_chunks::<4>().0 {
        keccak_round_in_place!(xor5, rax1, xar, xor, bcax, state, 0, rc0);
        keccak_round_in_place!(xor5, rax1, xar, xor, bcax, state, 1, rc1);
        keccak_round_in_place!(xor5, rax1, xar, xor, bcax, state, 2, rc2);
        keccak_round_in_place!(xor5, rax1, xar, xor, bcax, state, 3, rc3);
    }
}

/// Applies Keccak-f\[1600\] to one state, held flat as `state[x + 5y]`
/// (FIPS 202 Section 3.3).
// Never inlined on x86-64. Inlined into `digest::permute`, the x86-64 baseline
// build allocated registers worse, with 10% more instructions and 12% more stack
// traffic in every round, and a call costs about a nanosecond against a
// permutation's two hundred. On aarch64, inlining is worth about 1%, so it
// stays allowed there.
#[cfg_attr(target_arch = "x86_64", inline(never))]
pub(super) fn permute(state: &mut [u64; 25]) {
    rounds(state);
}

/// [`permute`], compiled with BMI1 and BMI2 enabled.
///
/// The source is identical; only the instructions differ. BMI1's `andn`
/// computes chi's `!b & c` in one instruction, where the x86-64 baseline needs
/// a copy, a `not` and an `and`. BMI2's `rorx` rotates into a different
/// register, saving the copy a destructive `rol` needs. Together they cut a
/// round from 241 instructions to 181. Most x86-64 CPUs of the last decade have
/// both, but neither is part of the x86-64 baseline, so the portable
/// [`permute`] cannot assume them.
///
/// # Safety
///
/// The caller must make sure the `bmi1` and `bmi2` CPU features are available.
/// `super::digest::permute` is the only caller, and it checks this already.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2")]
pub(super) unsafe fn permute_bmi(state: &mut [u64; 25]) {
    rounds(state);
}

/// Lane-wise forms of the same five operations, for `W` independent states
/// held transposed as `state[lane][slot]`.
///
/// `W` is read from the enclosing function's const parameter.
///
/// These, and `permute_many` below, exist only to validate the SIMD
/// multi-buffer backends, so they are compiled under `cfg(test)`: a portable
/// batch of `W` is no faster than `W` separate calls to [`permute`], and
/// shipping it as a fallback would only be dead weight.
#[cfg(test)]
macro_rules! m_xor5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {{
        let (a, b, c, d, e) = ($a, $b, $c, $d, $e);
        let mut out = [0u64; W];
        for i in 0..W {
            out[i] = a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i];
        }
        out
    }};
}
#[cfg(test)]
macro_rules! m_rax1 {
    ($a:expr, $b:expr) => {{
        let (a, b) = ($a, $b);
        let mut out = [0u64; W];
        for i in 0..W {
            out[i] = a[i] ^ b[i].rotate_left(1);
        }
        out
    }};
}
#[cfg(test)]
macro_rules! m_xar {
    ($a:expr, $b:expr, $r:expr) => {{
        let (a, b) = ($a, $b);
        let mut out = [0u64; W];
        for i in 0..W {
            out[i] = (a[i] ^ b[i]).rotate_left($r);
        }
        out
    }};
}
#[cfg(test)]
macro_rules! m_xor {
    ($a:expr, $b:expr) => {{
        let (a, b) = ($a, $b);
        let mut out = [0u64; W];
        for i in 0..W {
            out[i] = a[i] ^ b[i];
        }
        out
    }};
}
#[cfg(test)]
macro_rules! m_bcax {
    ($a:expr, $b:expr, $c:expr) => {{
        let (a, b, c) = ($a, $b, $c);
        let mut out = [0u64; W];
        for i in 0..W {
            out[i] = a[i] ^ (!b[i] & c[i]);
        }
        out
    }};
}
#[cfg(test)]
macro_rules! m_rc {
    ($v:expr) => {
        [$v; W]
    };
}

/// Applies Keccak-f\[1600\] to `W` independent states at once, the portable
/// reference the SIMD multi-buffer backends are checked against.
///
/// `state` is transposed -- `state[lane][slot]` holds state lane `lane` of
/// message `slot` -- because that is the layout a vector register wants: one
/// load grabs the same state lane from all `W` messages at once.
#[cfg(test)]
pub(super) fn permute_many<const W: usize>(state: &mut [[u64; W]; 25]) {
    keccak_rounds!(m_xor5, m_rax1, m_xar, m_xor, m_bcax, state, m_rc);
}
