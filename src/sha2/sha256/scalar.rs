//! Plain, portable SHA-256 compression function -- no CPU-specific instructions.
//!
//! This is the trusted reference implementation: it runs on any CPU, and the
//! hardware backends are checked against it by the `matches_scalar_backend`
//! test in the digest module.
//!
//! All 64 rounds are written out by hand below instead of looped, so the
//! compiler knows the message-word index and round constant for every round
//! ahead of time. The 64 message words are kept in a 16-word ring buffer
//! instead of all being computed upfront, so each one is computed once,
//! right before the round that uses it, and old slots get reused. Computing
//! them in the middle of the rounds, rather than in a batch of 16 between
//! groups of rounds, lets the CPU work on the schedule while it waits for the
//! previous round to finish.
//!
//! That waiting is what sets the speed. Each round needs the `a` and `e` the
//! previous one produced, so the rounds run strictly one after another, and
//! what matters is how many instructions sit on that path, not how many there
//! are in total. On aarch64 the compiler's usual choices put avoidable
//! instructions on it, so there the round is written to keep them off (see
//! `round!`). That takes an empty block of inline assembly, the only `unsafe`
//! in this file; every other target compiles the round exactly as FIPS 180-4
//! writes it.
//!
//! On x86-64 the same code is also compiled a second time, for CPUs with BMI1
//! and BMI2 (see `compress_bmi`).

use super::K;

/// FIPS 180-4 section 4.1.2: `Ch(x, y, z)` picks each bit from `y` where the
/// bit of `x` is set and from `z` where it isn't.
#[inline]
pub(super) fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// FIPS 180-4 section 4.1.2: `Maj(x, y, z)` is the bitwise majority vote.
///
/// Computed as `((x ^ y) & (y ^ z)) ^ y`: where `x` and `y` agree the vote is
/// theirs, and where they differ `z` decides. `yz` must hold `y ^ z`. The
/// round after this one votes on `(new a, x, y)`, so this round's `x ^ y` is
/// exactly the next round's `y ^ z`; it is left in `yz` for that round,
/// saving one operation per round.
#[inline]
pub(super) fn maj(x: u32, y: u32, yz: &mut u32) -> u32 {
    let xy = x ^ y;
    let vote = (xy & *yz) ^ y;
    *yz = xy;
    vote
}

/// Returns `x` unchanged, through an empty block of inline assembly that the
/// compiler cannot see into: no instruction is emitted, but the result counts
/// as a value the compiler knows nothing about. That stops it from merging
/// the operations on either side, which is how `ror` and `round!` keep the
/// instruction order they were written in.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn opaque(mut x: u32) -> u32 {
    // SAFETY: the template is empty, so nothing is executed. The block only
    // claims to read and write `x`'s register; it touches no memory, stack or
    // flags, as its options state.
    unsafe {
        core::arch::asm!("/* {0:w} */", inout(reg) x, options(pure, nomem, nostack, preserves_flags));
    }
    x
}

/// `x.rotate_right(n)`, for the two uppercase sigmas, which are on the path
/// each round waits on.
///
/// aarch64 can fold a rotate into the instruction that uses its result
/// (`eor w0, w1, w2, ror #n`), and the compiler does so because it saves an
/// instruction. But on cores where an operation on a shifted operand takes
/// two cycles instead of one, three rotates folded into two XORs cost five
/// cycles one after another, where three separate rotates and two plain XORs
/// cost three. So on aarch64 each rotate is kept an instruction of its own.
/// x86 has no such folding, so there this is a plain rotate.
#[inline(always)]
fn ror(x: u32, n: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    return opaque(x.rotate_right(n));
    #[cfg(not(target_arch = "aarch64"))]
    return x.rotate_right(n);
}

/// FIPS 180-4 section 4.1.2: the uppercase sigma applied to `a`.
#[inline]
pub(super) fn big_sigma0(x: u32) -> u32 {
    ror(x, 2) ^ ror(x, 13) ^ ror(x, 22)
}

/// FIPS 180-4 section 4.1.2: the uppercase sigma applied to `e`.
#[inline]
pub(super) fn big_sigma1(x: u32) -> u32 {
    ror(x, 6) ^ ror(x, 11) ^ ror(x, 25)
}

/// FIPS 180-4 section 4.1.2: the lowercase sigma used by the message schedule.
#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// FIPS 180-4 section 4.1.2: the other lowercase sigma of the message schedule.
#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Runs round `$t` (0 to 63) of the compression function. `$a`..`$h` are the
/// eight state variables (a..h), passed in round order, `$w` is the ring
/// buffer of message words, `$k` the round constants, and `$bc` holds
/// `b ^ c` for `maj`.
///
/// For the first 16 rounds the message word is already in `$w[$t]`. From
/// round 16 on it is
/// `small_sigma1(w[t-2]) + w[t-7] + small_sigma0(w[t-15]) + w[t-16]`, and slot
/// `t % 16` of the ring holds `w[t-16]`, so the new word overwrites exactly
/// the one it no longer needs. The other three slots are written as `t + 14`,
/// `t + 9` and `t + 1`, which are the same positions modulo 16 but can never
/// go negative.
///
/// The round itself is FIPS 180-4's
/// `T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]`,
/// `T2 = Sigma0(a) + Maj(a, b, c)`, new `e = d + T1`, new `a = T1 + T2`.
/// Each call only writes two state variables: the new `e` value is written
/// into whichever variable is passed as `$d`, and the new `a` value into
/// whichever is passed as `$h` (the old values are no longer needed). The
/// caller rotates which variable goes in which slot from one round to the
/// next, instead of physically shifting all eight values down by one.
///
/// On aarch64 the sums are grouped by hand. `h + K[t] + W[t]` and `d` are
/// known rounds ahead (`h` and `d` are the `e` and `a` from three rounds
/// back), so they are added up first, off the path that waits for the new
/// `e`; then `Ch`, then `Sigma1`, the last term to be ready. That leaves two
/// additions between `Ch` and the new `e`, where the order the compiler
/// would otherwise choose leaves five, as it adds the values it loads last.
/// It costs two more additions per round, computing the new `e` and `T1`
/// side by side, and `opaque` keeps the compiler from regrouping it all. On
/// x86-64, with half as many registers, the extra values cost more in spills
/// than they save, so everywhere else the sum is written as is.
macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $w:ident, $k:ident, $bc:ident, $t:expr) => {
        if $t >= 16 {
            $w[$t % 16] = small_sigma1($w[($t + 14) % 16])
                .wrapping_add($w[($t + 9) % 16])
                .wrapping_add(small_sigma0($w[($t + 1) % 16]))
                .wrapping_add($w[$t % 16]);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let hkw = opaque($h.wrapping_add($k[$t]).wrapping_add($w[$t % 16]));
            let hkwd = opaque(hkw.wrapping_add($d));
            let ch = ch($e, $f, $g);
            let s1 = big_sigma1($e);
            let t1 = opaque(hkw.wrapping_add(ch)).wrapping_add(s1);
            $d = opaque(hkwd.wrapping_add(ch)).wrapping_add(s1);
            $h = t1.wrapping_add(opaque(big_sigma0($a).wrapping_add(maj($a, $b, &mut $bc))));
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let t1 = $h
                .wrapping_add(big_sigma1($e))
                .wrapping_add(ch($e, $f, $g))
                .wrapping_add($k[$t])
                .wrapping_add($w[$t % 16]);
            $d = $d.wrapping_add(t1);
            $h = t1
                .wrapping_add(big_sigma0($a))
                .wrapping_add(maj($a, $b, &mut $bc));
        }
    };
}

/// Runs eight rounds in a row, starting at round `$t`. After eight rounds
/// every variable has rotated back to the slot it started in, so consecutive
/// groups are written identically.
macro_rules! eight_rounds {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $w:ident, $k:ident, $bc:ident, $t:expr) => {
        round!($a, $b, $c, $d, $e, $f, $g, $h, $w, $k, $bc, $t);
        round!($h, $a, $b, $c, $d, $e, $f, $g, $w, $k, $bc, $t + 1);
        round!($g, $h, $a, $b, $c, $d, $e, $f, $w, $k, $bc, $t + 2);
        round!($f, $g, $h, $a, $b, $c, $d, $e, $w, $k, $bc, $t + 3);
        round!($e, $f, $g, $h, $a, $b, $c, $d, $w, $k, $bc, $t + 4);
        round!($d, $e, $f, $g, $h, $a, $b, $c, $w, $k, $bc, $t + 5);
        round!($c, $d, $e, $f, $g, $h, $a, $b, $w, $k, $bc, $t + 6);
        round!($b, $c, $d, $e, $f, $g, $h, $a, $w, $k, $bc, $t + 7);
    };
}

/// The round constants, as the rounds should read them.
///
/// On aarch64 a 32-bit constant takes two instructions to build in a
/// register, while one load from a table fetches two of them, on a load unit
/// the round arithmetic doesn't use. Hiding where the reference points stops
/// the compiler from turning every `K[t]` back into a built constant. On
/// x86-64 a constant is a free operand of the `add` that uses it, so there the
/// table is read directly.
#[inline(always)]
fn round_constants() -> &'static [u32; 64] {
    #[cfg(target_arch = "aarch64")]
    return core::hint::black_box(&K);
    #[cfg(not(target_arch = "aarch64"))]
    return &K;
}

/// Hashes every full 64-byte block in `blocks` into `state`. Shared by
/// [`compress`] and, on x86-64, `compress_bmi`, which differ only in the
/// instructions they are compiled to.
#[inline(always)]
fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        process_block(state, block);
    }
}

/// Hashes every full 64-byte block in `blocks` into `state`.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
// Never inlined on x86-64, where the build for BMI1/BMI2 sits next to it in
// the dispatcher: like the Keccak permutation in `sha3`, register allocation
// there is easily disturbed by the code around it.
#[cfg_attr(target_arch = "x86_64", inline(never))]
pub(super) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    compress_blocks(state, blocks);
}

/// [`compress`], compiled with BMI1 and BMI2 enabled.
///
/// The source is identical; only the instructions differ. x86-64's baseline
/// rotate overwrites its input, so each of a round's six rotates of `a` and
/// `e`, which are still needed afterwards, has to work on a copy; BMI2's
/// `rorx` writes its result to a different register, removing more than half
/// of the copies. BMI1's `andn` computes `Ch`'s `!e & g` in one instruction.
/// Together they cut a block from about 3250 instructions to 2700. Most x86-64
/// CPUs of the last decade have both, but neither is part of the x86-64
/// baseline, so the portable [`compress`] cannot assume them.
///
/// # Safety
///
/// The caller must make sure the `bmi1` and `bmi2` CPU features are available.
/// `super::digest::compress` is the only caller, and it checks this already.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2")]
pub(super) unsafe fn compress_bmi(state: &mut [u32; 8], blocks: &[u8]) {
    compress_blocks(state, blocks);
}

/// Hashes one 64-byte block into `state`.
// Always inlined, so that `compress_bmi` gets a copy of its own compiled with
// BMI1/BMI2; called out of line, both builds would share the baseline one.
#[inline(always)]
fn process_block(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 16];
    for (word, src) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    }

    let k = round_constants();
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    // `b ^ c` for the first round's `maj`; each round leaves the next one's.
    let mut bc = b ^ c;

    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 0);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 8);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 16);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 24);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 32);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 40);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 48);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 56);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
