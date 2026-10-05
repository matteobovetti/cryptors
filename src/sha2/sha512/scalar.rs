//! Plain, portable SHA-512 compression function -- no CPU-specific instructions.
//!
//! All four 64-bit SHA-2 functions share it: they differ only in their initial
//! state and in how much of the final state they output. This is the trusted
//! reference implementation: it runs on any CPU, and the hardware backends are
//! checked against it by the `matches_scalar_backend` test in the digest
//! module.
//!
//! It is the 64-bit twin of `super::super::sha256::scalar`, with 80 rounds per
//! 128-byte block instead of 64 per 64-byte one. All rounds are written out by
//! hand below instead of looped, so the compiler knows the message-word index
//! and round constant for every round ahead of time. The 80 message words are
//! kept in a 16-word ring buffer instead of all being computed upfront, so
//! each one is computed once, right before the round that uses it, and old
//! slots get reused.
//!
//! Each round needs the `a` and `e` the previous one produced, so the rounds
//! run strictly one after another, and what sets the speed is how many
//! instructions sit on that path, not how many there are in total. Computing
//! the schedule in the middle of the rounds, rather than in a batch between
//! them, lets the CPU work on it while it waits for the previous round.
//!
//! On x86-64 the same code is also compiled a second time, for CPUs with BMI1
//! and BMI2 (see `compress_bmi`).

use super::K;

/// FIPS 180-4 section 4.1.3: `Ch(x, y, z)` picks each bit from `y` where the
/// bit of `x` is set and from `z` where it isn't.
#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

/// FIPS 180-4 section 4.1.3: `Maj(x, y, z)` is the bitwise majority vote.
///
/// Computed as `((x ^ y) & (y ^ z)) ^ y`: where `x` and `y` agree the vote is
/// theirs, and where they differ `z` decides. `yz` must hold `y ^ z`. The
/// round after this one votes on `(new a, x, y)`, so this round's `x ^ y` is
/// exactly the next round's `y ^ z`; it is left in `yz` for that round,
/// saving one operation per round.
#[inline]
fn maj(x: u64, y: u64, yz: &mut u64) -> u64 {
    let xy = x ^ y;
    let vote = (xy & *yz) ^ y;
    *yz = xy;
    vote
}

/// FIPS 180-4 section 4.1.3: the uppercase sigma applied to `a`.
#[inline]
fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// FIPS 180-4 section 4.1.3: the uppercase sigma applied to `e`.
#[inline]
fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// FIPS 180-4 section 4.1.3: the lowercase sigma used by the message schedule.
#[inline]
fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// FIPS 180-4 section 4.1.3: the other lowercase sigma of the message schedule.
#[inline]
fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// Runs round `$t` (0 to 79) of the compression function. `$a`..`$h` are the
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
macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $w:ident, $k:ident, $bc:ident, $t:expr) => {
        if $t >= 16 {
            $w[$t % 16] = small_sigma1($w[($t + 14) % 16])
                .wrapping_add($w[($t + 9) % 16])
                .wrapping_add(small_sigma0($w[($t + 1) % 16]))
                .wrapping_add($w[$t % 16]);
        }

        let t1 = $h
            .wrapping_add(big_sigma1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add($k[$t])
            .wrapping_add($w[$t % 16]);
        $d = $d.wrapping_add(t1);
        $h = t1
            .wrapping_add(big_sigma0($a))
            .wrapping_add(maj($a, $b, &mut $bc));
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

/// Hashes every full 128-byte block in `blocks` into `state`. Shared by
/// [`compress`] and, on x86-64, `compress_bmi`, which differ only in the
/// instructions they are compiled to.
#[inline(always)]
fn compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    let (blocks, _) = blocks.as_chunks::<128>();
    for block in blocks {
        process_block(state, block);
    }
}

/// Hashes every full 128-byte block in `blocks` into `state`.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
// Never inlined on x86-64, where the build for BMI1/BMI2 sits next to it in
// the dispatcher: like the Keccak permutation in `sha3`, register allocation
// there is easily disturbed by the code around it.
#[cfg_attr(target_arch = "x86_64", inline(never))]
pub(super) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    compress_blocks(state, blocks);
}

/// [`compress`], compiled with BMI1 and BMI2 enabled.
///
/// The source is identical; only the instructions differ. x86-64's baseline
/// rotate overwrites its input, so each of a round's six rotates of `a` and
/// `e`, which are still needed afterwards, has to work on a copy; BMI2's
/// `rorx` writes its result to a different register, removing most of the
/// copies. BMI1's `andn` computes `Ch`'s `!e & g` in one instruction. Most
/// x86-64 CPUs of the last decade have both, but neither is part of the
/// x86-64 baseline, so the portable [`compress`] cannot assume them.
///
/// # Safety
///
/// The caller must make sure the `bmi1` and `bmi2` CPU features are available.
/// `super::digest::compress` is the only caller, and it checks this already.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1,bmi2")]
pub(super) unsafe fn compress_bmi(state: &mut [u64; 8], blocks: &[u8]) {
    compress_blocks(state, blocks);
}

/// Hashes one 128-byte block into `state`.
// Always inlined, so that `compress_bmi` gets a copy of its own compiled with
// BMI1/BMI2; called out of line, both builds would share the baseline one.
#[inline(always)]
fn process_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 16];
    let (words, _) = block.as_chunks::<8>();
    for (word, src) in w.iter_mut().zip(words) {
        *word = u64::from_be_bytes(*src);
    }

    let k = &K;
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
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 64);
    eight_rounds!(a, b, c, d, e, f, g, h, w, k, bc, 72);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
