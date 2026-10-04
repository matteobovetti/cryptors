/// Keccak-f\[1600\] round constants (FIPS 202 Algorithm 5 / Table 5), one per
/// round. Shared with every backend through the [`keccak_rounds`] macro.
pub(super) const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Domain-separation suffix for SHA3-224/256/384/512, folded into the first
/// padding byte (FIPS 202 Section 6.1): the two suffix bits `01` followed by
/// the sponge padding's leading `1` bit, in bit-within-byte order (LSB first).
const SUFFIX_SHA3: u8 = 0b0000_0110;

/// Domain-separation suffix for SHAKE128/256 (FIPS 202 Section 6.2): the four
/// suffix bits `1111` followed by the sponge padding's leading `1` bit.
const SUFFIX_SHAKE: u8 = 0b0001_1111;

/// Bytes absorbed per permutation, for each function FIPS 202 defines. Rate
/// plus capacity is always the full 1600-bit state, so a smaller rate keeps
/// more of the state secret between permutations and buys security margin at
/// the cost of more permutations per byte.
const RATE_224: usize = 144;
const RATE_256: usize = 136;
const RATE_384: usize = 104;
const RATE_512: usize = 72;
const RATE_SHAKE128: usize = 168;
const RATE_SHAKE256: usize = 136;

/// The largest rate above, and so the size of one staged padding block.
const MAX_RATE: usize = RATE_SHAKE128;

#[cfg(target_arch = "aarch64")]
#[inline]
pub(super) fn has_hw_sha3() -> bool {
    // On a target that already has `sha3` in its baseline (aarch64-apple-darwin,
    // for instance) this folds away at compile time.
    cfg!(target_feature = "sha3") || std::arch::is_aarch64_feature_detected!("sha3")
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn has_bmi() -> bool {
    // On a target that already has both in its baseline (`-C target-cpu=x86-64-v3`,
    // for instance) this folds away at compile time.
    (cfg!(target_feature = "bmi1") && cfg!(target_feature = "bmi2"))
        || (std::arch::is_x86_feature_detected!("bmi1")
            && std::arch::is_x86_feature_detected!("bmi2"))
}

/// Applies Keccak-f\[1600\] to one state, picking the fastest backend the CPU
/// supports.
///
/// No x86 CPU implements Keccak, and vectorizing a single sponge loses to
/// scalar code, so the best x86 can do for one message is the scalar backend
/// compiled for BMI1/BMI2. x86's real acceleration comes from the
/// multi-buffer backends instead, via the `*_many` functions.
#[inline]
fn permute(state: &mut [u64; 25]) {
    #[cfg(target_arch = "aarch64")]
    if has_hw_sha3() {
        // SAFETY: has_hw_sha3() just confirmed the `sha3` feature is available.
        unsafe { super::aarch64::permute(state) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_bmi() {
        // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
        unsafe { super::scalar::permute_bmi(state) };
        return;
    }

    super::scalar::permute(state);
}

/// XORs one `rate`-sized block into the state, as little-endian 64-bit words
/// (FIPS 202 Section B.1).
///
/// Every rate FIPS 202 defines is a multiple of 8, so `block` covers exactly
/// `rate / 8` whole lanes and the remaining lanes -- the capacity -- are
/// deliberately left untouched.
#[inline]
fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (lane, word) in state.iter_mut().zip(block.chunks_exact(8)) {
        *lane ^= u64::from_le_bytes(word.try_into().unwrap());
    }
}

/// Builds the final block of a message: whatever is left over after the whole
/// blocks, plus `pad10*1` padding (FIPS 202 Section 5.1).
///
/// The suffix and the padding's leading `1` bit share a byte, and the closing
/// `1` bit goes in the top bit of the block's last byte -- which is the same
/// byte when the leftover is exactly `rate - 1` long. Because the leftover is
/// always shorter than `rate`, this is always exactly one block, never two.
#[inline]
fn pad_block(rate: usize, suffix: u8, remainder: &[u8]) -> [u8; MAX_RATE] {
    debug_assert!(remainder.len() < rate);

    let mut block = [0u8; MAX_RATE];
    block[..remainder.len()].copy_from_slice(remainder);
    block[remainder.len()] |= suffix;
    block[rate - 1] |= 0x80;
    block
}

/// Reads `out.len()` bytes off the state, permuting between successive
/// `rate`-sized blocks (FIPS 202 Section 5.1, squeezing phase).
fn squeeze<F: FnMut(&mut [u64; 25])>(
    permute_fn: &mut F,
    state: &mut [u64; 25],
    rate: usize,
    out: &mut [u8],
) {
    let mut filled = 0;
    while filled < out.len() {
        let take = (out.len() - filled).min(rate);

        // One lane at a time, so only the bytes actually wanted are written.
        for (i, chunk) in out[filled..filled + take].chunks_mut(8).enumerate() {
            let bytes = state[i].to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        filled += take;

        if filled < out.len() {
            permute_fn(state);
        }
    }
}

/// Runs the whole sponge for one message: absorb `input` at `rate` with
/// `suffix` as the domain separator, then squeeze enough to fill `out`.
///
/// Whole blocks are absorbed straight out of `input` without copying; only
/// the final padded block is staged on the stack. The permutation is taken as
/// a parameter so tests can force a specific backend; the public functions
/// always pass the auto-selected [`permute`], so it costs nothing normally.
fn sponge<F: FnMut(&mut [u64; 25])>(
    mut permute_fn: F,
    rate: usize,
    suffix: u8,
    input: &[u8],
    out: &mut [u8],
) {
    let mut state = [0u64; 25];

    let mut blocks = input.chunks_exact(rate);
    for block in &mut blocks {
        absorb_block(&mut state, block);
        permute_fn(&mut state);
    }

    let tail = pad_block(rate, suffix, blocks.remainder());
    absorb_block(&mut state, &tail[..rate]);
    permute_fn(&mut state);

    squeeze(&mut permute_fn, &mut state, rate, out);
}

/// Returns block `b` of a padded message: the first `full` blocks come
/// straight from `input`, and the last one from the staged `tail`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
fn block_at<'a>(
    input: &'a [u8],
    tail: &'a [u8; MAX_RATE],
    full: usize,
    rate: usize,
    b: usize,
) -> &'a [u8] {
    if b < full {
        &input[b * rate..(b + 1) * rate]
    } else {
        &tail[..rate]
    }
}

/// Runs `W` sponges at once, one message per vector lane, writing each
/// message's `out_len` bytes of output back to back into `out`.
///
/// `state` is "lane-transposed" (`state[lane][slot]`) because that is the
/// layout a vector register wants: one load grabs state lane `lane` from all
/// `W` messages at once.
///
/// Messages don't have to be the same length. All `W` advance together for as
/// long as every one of them still has a block left; past that point the
/// longer ones finish on the single-message path, exactly as `md5`'s
/// multi-buffer backends do. A sponge must not be permuted again after its
/// last block, so each lane is lifted out of the batch at precisely its own
/// final block, then squeezed.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn group_sponge<const W: usize, F>(
    permute_many: &mut F,
    rate: usize,
    suffix: u8,
    group: &[&[u8]],
    out_len: usize,
    out: &mut [u8],
) where
    F: FnMut(&mut [[u64; W]; 25]),
{
    debug_assert_eq!(group.len(), W);

    // Pad each lane's tail once up front, so the loop below can treat every
    // lane as a flat sequence of `blocks[slot]` complete blocks.
    let mut tails = [[0u8; MAX_RATE]; W];
    let mut full = [0usize; W];
    let mut blocks = [0usize; W];

    for (slot, input) in group.iter().enumerate() {
        full[slot] = input.len() / rate;
        // Padding always adds exactly one block, never two.
        blocks[slot] = full[slot] + 1;
        tails[slot] = pad_block(rate, suffix, &input[full[slot] * rate..]);
    }

    let mut state = [[0u64; W]; 25];

    // Lane-parallel phase: while every lane still has a block, advance all
    // `W` of them together on the vector backend.
    let common = blocks.iter().copied().min().unwrap_or(0);
    for b in 0..common {
        for (slot, input) in group.iter().enumerate() {
            let block = block_at(input, &tails[slot], full[slot], rate, b);
            for (i, word) in block.chunks_exact(8).enumerate() {
                state[i][slot] ^= u64::from_le_bytes(word.try_into().unwrap());
            }
        }
        permute_many(&mut state);
    }

    // Tail phase: each lane leaves the batch, absorbs any blocks the shorter
    // lanes didn't have, and is squeezed.
    for (slot, input) in group.iter().enumerate() {
        let mut single = [0u64; 25];
        for (lane, wide) in single.iter_mut().zip(state.iter()) {
            *lane = wide[slot];
        }

        for b in common..blocks[slot] {
            let block = block_at(input, &tails[slot], full[slot], rate, b);
            absorb_block(&mut single, block);
            permute(&mut single);
        }

        squeeze(
            &mut permute,
            &mut single,
            rate,
            &mut out[slot * out_len..(slot + 1) * out_len],
        );
    }
}

/// Runs every whole group of `W` messages at the front of `inputs` through
/// `permute_many`, appending their output to `out`. Returns whatever is left
/// -- fewer than `W` messages -- for a narrower backend to pick up.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn many_into<'a, const W: usize, F>(
    mut permute_many: F,
    rate: usize,
    suffix: u8,
    out_len: usize,
    inputs: &'a [&'a [u8]],
    out: &mut Vec<u8>,
) -> &'a [&'a [u8]]
where
    F: FnMut(&mut [[u64; W]; 25]),
{
    let mut groups = inputs.chunks_exact(W);
    for group in &mut groups {
        let base = out.len();
        out.resize(base + W * out_len, 0);
        group_sponge(
            &mut permute_many,
            rate,
            suffix,
            group,
            out_len,
            &mut out[base..],
        );
    }
    groups.remainder()
}

/// Hashes many messages, returning their outputs concatenated -- `out_len`
/// bytes each, in input order.
///
/// The widest backend runs first and narrower ones mop up, so a batch size
/// that isn't a multiple of the widest lane count still gets most of the
/// benefit. Only a final remainder smaller than the narrowest backend -- or
/// every message, on a CPU with no multi-buffer backend -- falls back to the
/// single-message path.
fn sponge_many(rate: usize, suffix: u8, out_len: usize, inputs: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * out_len);
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(unused_mut)
    )]
    let mut rest = inputs;

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: `is_x86_feature_detected` just confirmed `avx2`.
            rest = many_into::<4, _>(
                |s| unsafe { super::x86::permute4(s) },
                rate,
                suffix,
                out_len,
                rest,
                &mut out,
            );
        }
        // SAFETY: `sse2` is guaranteed by the x86-64 target baseline.
        rest = many_into::<2, _>(
            |s| unsafe { super::x86::permute2(s) },
            rate,
            suffix,
            out_len,
            rest,
            &mut out,
        );
    }

    #[cfg(target_arch = "aarch64")]
    if has_hw_sha3() {
        // SAFETY: has_hw_sha3() just confirmed the `sha3` feature is available.
        rest = many_into::<2, _>(
            |s| unsafe { super::aarch64::permute_many(s) },
            rate,
            suffix,
            out_len,
            rest,
            &mut out,
        );
    }

    for input in rest {
        let base = out.len();
        out.resize(base + out_len, 0);
        sponge(permute, rate, suffix, input, &mut out[base..]);
    }

    out
}

/// Computes one fixed-size SHA-3 digest.
fn sha3_digest<const N: usize>(rate: usize, input: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    sponge(permute, rate, SUFFIX_SHA3, input, &mut out);
    out
}

/// Computes one fixed-size SHA-3 digest for each message in `inputs`.
fn sha3_digest_many<const N: usize>(rate: usize, inputs: &[&[u8]]) -> Vec<[u8; N]> {
    sponge_many(rate, SUFFIX_SHA3, N, inputs)
        .chunks_exact(N)
        .map(|digest| digest.try_into().unwrap())
        .collect()
}

/// Computes `output_len` bytes of SHAKE output for each message in `inputs`.
fn shake_many(rate: usize, inputs: &[&[u8]], output_len: usize) -> Vec<Vec<u8>> {
    if output_len == 0 {
        return vec![Vec::new(); inputs.len()];
    }
    sponge_many(rate, SUFFIX_SHAKE, output_len, inputs)
        .chunks_exact(output_len)
        .map(<[u8]>::to_vec)
        .collect()
}

/// Computes the 224-bit SHA3-224 digest of `input` (rate 1152 bits / 144 bytes).
pub fn sha3_224(input: &[u8]) -> [u8; 28] {
    sha3_digest(RATE_224, input)
}

/// Computes the 256-bit SHA3-256 digest of `input` (rate 1088 bits / 136 bytes).
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    sha3_digest(RATE_256, input)
}

/// Computes the 384-bit SHA3-384 digest of `input` (rate 832 bits / 104 bytes).
pub fn sha3_384(input: &[u8]) -> [u8; 48] {
    sha3_digest(RATE_384, input)
}

/// Computes the 512-bit SHA3-512 digest of `input` (rate 576 bits / 72 bytes).
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    sha3_digest(RATE_512, input)
}

/// Fills `output` with SHAKE128 extendable output for `input` (rate 1344
/// bits / 168 bytes). Unlike the fixed-size digests above, SHAKE produces as
/// much or as little output as the caller asks for.
pub fn shake128(input: &[u8], output: &mut [u8]) {
    sponge(permute, RATE_SHAKE128, SUFFIX_SHAKE, input, output);
}

/// Fills `output` with SHAKE256 extendable output for `input` (rate 1088
/// bits / 136 bytes).
pub fn shake256(input: &[u8], output: &mut [u8]) {
    sponge(permute, RATE_SHAKE256, SUFFIX_SHAKE, input, output);
}

/// Computes the SHA3-224 digest of every message in `inputs`.
///
/// Messages are hashed in groups of up to 4 (AVX2) or 2 (SSE2, or aarch64
/// with FEAT_SHA3), one per vector lane, so a whole group costs little more
/// than a single digest. They don't need to be the same length. See the
/// [module docs](crate::sha3) for which backend runs where.
pub fn sha3_224_many(inputs: &[&[u8]]) -> Vec<[u8; 28]> {
    sha3_digest_many(RATE_224, inputs)
}

/// Computes the SHA3-256 digest of every message in `inputs`. See
/// [`sha3_224_many`].
pub fn sha3_256_many(inputs: &[&[u8]]) -> Vec<[u8; 32]> {
    sha3_digest_many(RATE_256, inputs)
}

/// Computes the SHA3-384 digest of every message in `inputs`. See
/// [`sha3_224_many`].
pub fn sha3_384_many(inputs: &[&[u8]]) -> Vec<[u8; 48]> {
    sha3_digest_many(RATE_384, inputs)
}

/// Computes the SHA3-512 digest of every message in `inputs`. See
/// [`sha3_224_many`].
pub fn sha3_512_many(inputs: &[&[u8]]) -> Vec<[u8; 64]> {
    sha3_digest_many(RATE_512, inputs)
}

/// Computes `output_len` bytes of SHAKE128 output for every message in
/// `inputs`. Every message gets the same output length, so all lanes squeeze
/// in step. See [`sha3_224_many`].
pub fn shake128_many(inputs: &[&[u8]], output_len: usize) -> Vec<Vec<u8>> {
    shake_many(RATE_SHAKE128, inputs, output_len)
}

/// Computes `output_len` bytes of SHAKE256 output for every message in
/// `inputs`. See [`shake128_many`].
pub fn shake256_many(inputs: &[&[u8]], output_len: usize) -> Vec<Vec<u8>> {
    shake_many(RATE_SHAKE256, inputs, output_len)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Renders `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0xf) as usize]);
    }
    // SAFETY: `out` only ever contains bytes from the `HEX` table, which is ASCII.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Computes the SHA3-224 digest of `input` and renders it as lowercase hex.
pub fn sha3_224_hex(input: &[u8]) -> String {
    hex(&sha3_224(input))
}

/// Computes the SHA3-256 digest of `input` and renders it as lowercase hex.
pub fn sha3_256_hex(input: &[u8]) -> String {
    hex(&sha3_256(input))
}

/// Computes the SHA3-384 digest of `input` and renders it as lowercase hex.
pub fn sha3_384_hex(input: &[u8]) -> String {
    hex(&sha3_384(input))
}

/// Computes the SHA3-512 digest of `input` and renders it as lowercase hex.
pub fn sha3_512_hex(input: &[u8]) -> String {
    hex(&sha3_512(input))
}

/// Computes `output_len` bytes of SHAKE128 output for `input` and renders
/// them as lowercase hex.
pub fn shake128_hex(input: &[u8], output_len: usize) -> String {
    let mut out = vec![0u8; output_len];
    shake128(input, &mut out);
    hex(&out)
}

/// Computes `output_len` bytes of SHAKE256 output for `input` and renders
/// them as lowercase hex.
pub fn shake256_hex(input: &[u8], output_len: usize) -> String {
    let mut out = vec![0u8; output_len];
    shake256(input, &mut out);
    hex(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::scalar;

    /// Which single-message backend [`permute`] picks on this machine.
    fn active_backend() -> &'static str {
        #[cfg(target_arch = "aarch64")]
        if has_hw_sha3() {
            return "aarch64 (FEAT_SHA3)";
        }
        #[cfg(target_arch = "x86_64")]
        if has_bmi() {
            return "scalar (BMI1/BMI2)";
        }
        "scalar"
    }

    /// Which multi-buffer backend `*_many` picks on this machine, and how
    /// many messages it takes at a time.
    fn active_many_backend() -> (&'static str, usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                ("x86_64 AVX2", 4)
            } else {
                ("x86_64 SSE2", 2)
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if has_hw_sha3() {
                ("aarch64 FEAT_SHA3", 2)
            } else {
                ("scalar", 1)
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            ("scalar", 1)
        }
    }

    /// One of the `*_hex` functions, so the tables below can pair a function
    /// with its expected outputs.
    type HexFn = fn(&[u8]) -> String;

    /// A list of (input length, expected hex output) pairs.
    type Vectors<'a> = &'a [(usize, &'a str)];

    /// A deterministic pseudorandom byte pattern, so every test runs on the
    /// same inputs on every machine.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Input lengths covering every point where the block layout or padding
    /// changes, for all five distinct rates, plus sizes big enough to run the
    /// permutation many times over.
    const LENGTHS: [usize; 30] = [
        0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 207, 208,
        271, 272, 287, 288, 335, 336, 337, 1000, 4096, 10_000, 100_000,
    ];

    // ---- Known-answer vectors (FIPS 202 / NIST examples) ----

    #[test]
    fn empty_string() {
        assert_eq!(
            sha3_224_hex(b""),
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        );
        assert_eq!(
            sha3_256_hex(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            sha3_384_hex(b""),
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        );
        assert_eq!(
            sha3_512_hex(b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            sha3_224_hex(b"abc"),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            sha3_256_hex(b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            sha3_384_hex(b"abc"),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        );
        assert_eq!(
            sha3_512_hex(b"abc"),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn two_block_message() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha3_224_hex(input),
            "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
        );
        assert_eq!(
            sha3_256_hex(input),
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
        );
        assert_eq!(
            sha3_384_hex(input),
            "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"
        );
        assert_eq!(
            sha3_512_hex(input),
            "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
        );
    }

    #[test]
    fn quick_brown_fox() {
        let input = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(
            sha3_224_hex(input),
            "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795"
        );
        assert_eq!(
            sha3_256_hex(input),
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"
        );
        assert_eq!(
            sha3_384_hex(input),
            "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41"
        );
        assert_eq!(
            sha3_512_hex(input),
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"
        );
    }

    /// 1,000,000 repetitions of 'a' -- the only input here big enough to run
    /// the permutation thousands of times at every rate.
    #[test]
    fn million_a() {
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            sha3_224_hex(&input),
            "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
        );
        assert_eq!(
            sha3_256_hex(&input),
            "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
        );
        assert_eq!(
            sha3_384_hex(&input),
            "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"
        );
        assert_eq!(
            sha3_512_hex(&input),
            "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
        );
    }

    #[test]
    fn shake_known_answers() {
        assert_eq!(
            shake128_hex(b"", 32),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        assert_eq!(
            shake256_hex(b"", 64),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        assert_eq!(
            shake128_hex(b"abc", 32),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );
        assert_eq!(
            shake256_hex(b"abc", 64),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    /// Output longer than one rate-sized block, so squeezing has to permute
    /// and keep reading rather than stopping after the first block.
    #[test]
    fn shake_multi_block_output() {
        assert_eq!(
            shake128_hex(b"", 400),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b"
        );
        assert_eq!(
            shake256_hex(b"abc", 300),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412fc346b1bb39b878330e026b12ddf384af3334560ea1d363966caa7d8ddcbec7da52b42215c11d5f8ee57f341"
        );
    }

    /// Input lengths right around each variant's rate boundary -- one byte
    /// short, exact, and one byte over -- since that is where the padding
    /// block and the extra permutation could go wrong.
    #[test]
    fn rate_boundaries() {
        let cases: [(usize, HexFn, Vectors<'_>); 4] = [
            (
                RATE_224,
                sha3_224_hex,
                &[
                    (
                        143,
                        "64d0e8a1be3cf30ef6727b30a6e428f7f068d44634c943d277ad8e7f",
                    ),
                    (
                        144,
                        "5be75e6a08f19913a1d8036c056cc4556b98dc90aeca3f2a0664dedc",
                    ),
                    (
                        145,
                        "90b861ac1b1598459ad8337afa9933ce2f1a6f972c57daf8fc2737e4",
                    ),
                    (
                        287,
                        "15a2f08845143cf999c3235ed78c568278a3469f9f27d6e8eed61589",
                    ),
                    (
                        288,
                        "c31edb82e0debcac85099028f8dda66900e716217b7f30e003d611bc",
                    ),
                    (
                        289,
                        "94030cc380f90034f5bf5d2e10c7e9d939152a9e5eecf5534af22948",
                    ),
                ],
            ),
            (
                RATE_256,
                sha3_256_hex,
                &[
                    (
                        135,
                        "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2",
                    ),
                    (
                        136,
                        "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5",
                    ),
                    (
                        137,
                        "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca",
                    ),
                    (
                        271,
                        "0153fcdb6825d836b10835ccb3999dc1d8b68492f77e7e38afa31f8e244bd7af",
                    ),
                    (
                        272,
                        "b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794",
                    ),
                    (
                        273,
                        "4827800416bd25b01f53360454943ef688112eaee40422929a59af596a2c0be7",
                    ),
                ],
            ),
            (
                RATE_384,
                sha3_384_hex,
                &[
                    (
                        103,
                        "1f91ee551ad18f268876d1fc262f137fe196580216c5193819a95ec5222537d2a658dd129c3d8080e65ec7460f1f4704",
                    ),
                    (
                        104,
                        "5b8d0d5cf8b41be507be8fcbfcbdbac3a28eb368d430fed6780aaa78a93a8da4a6c50485949ca344f228be91a96005a3",
                    ),
                    (
                        105,
                        "4a2f0a8f2f1f4cc4605cc2537e0be28cf8b465c30f0a54b494a7128ec54ee4e85706b5e47a5697344d15cbf85680cd40",
                    ),
                    (
                        207,
                        "05c54ebcce483360359d63bf0aafd97e2b15b00ea40c6152b3bbac80285711cd0b00fc234cdc214251e0aa13e38a0008",
                    ),
                    (
                        208,
                        "13a929eb9e4ac18a07de84b17e79bb420a86924b9dc4cd80038dd61f17770fc42460f2a0a717dd26fb6b6b4de357ae02",
                    ),
                    (
                        209,
                        "4a40dd56c8a2efb2e3de6f05fc8fe00df8af8869a66aff4fe734f9a6cb0db930d547fc0f3f213f6b8a172db13b15ec5c",
                    ),
                ],
            ),
            (
                RATE_512,
                sha3_512_hex,
                &[
                    (
                        71,
                        "3ccc850d53a1287af7b4560b2ef0d43eb5d9a80d62a0e9cf1dbc040135921104d4395168e90bfc871773ebb34bca1bd67056e1cc7dc7a48ff7c3167d389f117c",
                    ),
                    (
                        72,
                        "5d63f2bbe971a983ac6847480106e4e1264ee3a0befd79954914e1d86e795b2e18238f12fc5e46cb9cc78efdec610a93647cc04e1c23d8caaa6a58c21dd26c07",
                    ),
                    (
                        73,
                        "921d9b7b2b0f3066a1646dbb058c979cb3925dec0f8c269faaa7f9648e73465ae55ec527257d5d5e1cfdbf5d6799bea1004b6186f5108c74e3b92fe924166558",
                    ),
                    (
                        143,
                        "eb9748309c6b70ffe82820052ad26ea99f43968d2af359adc804b2a76741a62ea8d710f018ea113c2259d0bd6687e3838602ae6c1dff727ae985f059141c7217",
                    ),
                    (
                        144,
                        "e1951b8bcb58ca75a34af80a7a2b765cad4257fe383a79b55bf21f180b75f6e5b08f09598851eeea7d13486387618d6c6bf88cf23c0088a3f783f59a06d60493",
                    ),
                    (
                        145,
                        "1abec62dce93a6775cd2ec0098d7264676a21e644c7c1b80580c305cfde31b7d5848c63af4d0e7cfeda2e5076a32dbd632665fbb1e7f06651b2ed4d7341ac844",
                    ),
                ],
            ),
        ];

        for (rate, digest_hex, vectors) in cases {
            for &(len, expected) in vectors {
                assert_eq!(
                    digest_hex(&pattern(len)),
                    expected,
                    "rate = {rate}, len = {len}"
                );
            }
        }
    }

    #[test]
    fn shake_rate_boundaries() {
        let shake128_cases = [
            (
                167,
                "1e552791cc4e93a0d4a8dc47ae49228c2faa869e40e628f6ace477aec3f1ca7a",
            ),
            (
                168,
                "f15277eb61c4908d44a2853f3cde071ae2ed7a23461fbe162a1a98cf6875059c",
            ),
            (
                169,
                "015be3338c986d9846affa0f94b4afc2a76bc289c709e1a596ec9eccf090a773",
            ),
            (
                336,
                "278918d9abddd4a3c154affd8fe4f85e8e890eb2bbf659f393ca09ec8f9254bb",
            ),
            (
                337,
                "0c2700a9aae2f7a3886a7130bc9d90790e32b5094b86c273cc4551f3427e680e",
            ),
        ];
        for (len, expected) in shake128_cases {
            assert_eq!(shake128_hex(&pattern(len), 32), expected, "len = {len}");
        }

        let shake256_cases = [
            (
                135,
                "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade07f4056bf081a1098101cea8132188c422136feb4687d1e2209f3fd28bedfb8f4",
            ),
            (
                136,
                "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a757e8dbf043dac48d2154e46d59c0b9e8bc36ba035153691fbe83b9eff5dae4a",
            ),
            (
                137,
                "01d90952c642a5eb2a8fc9d713f843a45d7ac05132dddcb2efc9bebc27e37bcbe42130c36f3540250ab11796980e773683f28d07f0f838606fb9c45e452bd38f",
            ),
            (
                272,
                "e3299fa992163e7ffc875aff708dac93d2157e9b4ccaa2a13ba1ca4ef0b40f29a8922462cee9739430c22a70d36a91fdf654d7457d79b942d7e1ad573b139bd7",
            ),
            (
                273,
                "3bf949e3523de3b5a8cb9e105ae817050987d0f31655722fa601e460d60c5dda489a05902b8fc332436edd5458881e56244c1fd8604e5f1e92ccd781b972b9f1",
            ),
        ];
        for (len, expected) in shake256_cases {
            assert_eq!(shake256_hex(&pattern(len), 64), expected, "len = {len}");
        }
    }

    /// A zero-length output is a degenerate but valid XOF request: it must
    /// not panic, for the batch API as well as the single one.
    #[test]
    fn shake_empty_output() {
        let mut empty = [];
        shake128(b"anything", &mut empty);
        shake256(b"anything", &mut empty);

        assert_eq!(shake128_many(&[b"a", b"b"], 0), vec![Vec::<u8>::new(); 2]);
        assert_eq!(shake256_many(&[b"a"], 0), vec![Vec::<u8>::new(); 1]);
    }

    /// Squeeze lengths that are not a multiple of 8, so the final lane is
    /// only partly written, and lengths that straddle a squeeze block.
    #[test]
    fn shake_output_lengths_agree_with_truncation() {
        let long = shake128_hex(b"cryptors", 512);
        for len in [1usize, 7, 8, 9, 31, 167, 168, 169, 335, 336, 337, 512] {
            assert_eq!(
                shake128_hex(b"cryptors", len),
                long[..len * 2],
                "len = {len}"
            );
        }
    }

    // ---- Backend differential tests ----

    /// Checks each hardware single-message backend against the scalar one.
    ///
    /// This calls the backend directly instead of going through [`permute`],
    /// so the test can't accidentally compare the scalar backend with itself.
    #[test]
    fn matches_scalar_backend() {
        /// Runs whole sponges through `backend` and through the scalar
        /// reference, at every interesting length and rate, and checks they
        /// produce the same bytes.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        fn check(name: &str, mut backend: impl FnMut(&mut [u64; 25])) {
            for len in LENGTHS {
                let input = pattern(len);
                for (rate, suffix) in [
                    (RATE_224, SUFFIX_SHA3),
                    (RATE_256, SUFFIX_SHA3),
                    (RATE_384, SUFFIX_SHA3),
                    (RATE_512, SUFFIX_SHA3),
                    (RATE_SHAKE128, SUFFIX_SHAKE),
                ] {
                    let mut theirs = [0u8; 200];
                    let mut ours = [0u8; 200];
                    sponge(&mut backend, rate, suffix, &input, &mut theirs);
                    sponge(scalar::permute, rate, suffix, &input, &mut ours);
                    assert_eq!(
                        theirs, ours,
                        "{name} disagrees with scalar at rate = {rate}, len = {len}"
                    );
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        if has_hw_sha3() {
            // SAFETY: has_hw_sha3() just confirmed the `sha3` feature.
            check("aarch64 FEAT_SHA3", |s| unsafe {
                crate::sha3::aarch64::permute(s)
            });
            return;
        }

        // The BMI build is the same source as the reference, but it is still
        // different machine code, selected at runtime, and so still checked.
        #[cfg(target_arch = "x86_64")]
        if has_bmi() {
            // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
            check("scalar BMI1/BMI2 build", |s| unsafe {
                scalar::permute_bmi(s)
            });
            return;
        }

        println!("no faster single-message SHA-3 backend on this CPU; scalar only");
    }

    /// Checks each multi-buffer backend's permutation against the scalar
    /// reference, on states that have had data absorbed into them so no lane
    /// is still zero.
    #[test]
    fn matches_scalar_backend_many() {
        /// Builds `W` distinct, fully-mixed states.
        fn seed<const W: usize>() -> [[u64; W]; 25] {
            let mut state = [[0u64; W]; 25];
            for (lane, wide) in state.iter_mut().enumerate() {
                for (slot, v) in wide.iter_mut().enumerate() {
                    // A cheap mix, just to avoid structured inputs.
                    let x = (lane as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        ^ (slot as u64 + 1).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    *v = x ^ x.rotate_left(31);
                }
            }
            state
        }

        /// Runs `permute_many` and the scalar reference on the same state for
        /// several successive rounds, and checks they stay identical.
        fn check<const W: usize, F>(mut permute_many: F, name: &str)
        where
            F: FnMut(&mut [[u64; W]; 25]),
        {
            let mut theirs = seed::<W>();
            let mut ours = theirs;
            for step in 0..4 {
                permute_many(&mut theirs);
                scalar::permute_many(&mut ours);
                assert_eq!(theirs, ours, "{name} disagrees with scalar at step {step}");
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: `is_x86_feature_detected` just confirmed `avx2`.
                check::<4, _>(|s| unsafe { crate::sha3::x86::permute4(s) }, "x86 AVX2");
            } else {
                println!("no avx2 on this CPU; AVX2 backend not checked");
            }
            // SAFETY: `sse2` is guaranteed by the x86-64 target baseline.
            check::<2, _>(|s| unsafe { crate::sha3::x86::permute2(s) }, "x86 SSE2");
        }

        #[cfg(target_arch = "aarch64")]
        if has_hw_sha3() {
            // SAFETY: has_hw_sha3() just confirmed the `sha3` feature.
            check::<2, _>(
                |s| unsafe { crate::sha3::aarch64::permute_many(s) },
                "aarch64 FEAT_SHA3",
            );
        } else {
            println!("no FEAT_SHA3 on this CPU; aarch64 backend not checked");
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        println!("no multi-buffer SHA-3 backend on this target; scalar only");
    }

    /// Checks the transposed scalar reference against the plain single-state
    /// one, so a bug in the reference itself can't hide behind a matching bug
    /// in the backends it validates.
    #[test]
    fn scalar_many_matches_scalar() {
        let mut wide = [[0u64; 3]; 25];
        let mut singles = [[0u64; 25]; 3];

        for lane in 0..25 {
            for slot in 0..3 {
                let v = ((lane * 3 + slot) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                wide[lane][slot] = v;
                singles[slot][lane] = v;
            }
        }

        for _ in 0..4 {
            scalar::permute_many(&mut wide);
            for single in &mut singles {
                scalar::permute(single);
            }
            for (slot, single) in singles.iter().enumerate() {
                for lane in 0..25 {
                    assert_eq!(wide[lane][slot], single[lane], "slot {slot}, lane {lane}");
                }
            }
        }
    }

    /// Checks the shared round macro against a second, independently written
    /// permutation, so a transcription error in the macro's 25 fused
    /// assignments can't pass just because every backend shares it.
    #[test]
    fn scalar_matches_independent_reference() {
        let mut ours = [0u64; 25];
        let mut theirs = [0u64; 25];
        for lane in 0..25 {
            let v = (lane as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ 0x1234_5678_9abc_def0;
            ours[lane] = v;
            theirs[lane] = v;
        }

        for step in 0..8 {
            scalar::permute(&mut ours);
            reference_permute(&mut theirs);
            assert_eq!(ours, theirs, "step {step}");
        }
    }

    /// Reference permutation for `scalar_matches_independent_reference`.
    ///
    /// Written the other way round from the shared macro: theta, rho, pi and
    /// chi are four separate passes driven by lookup tables, with rho and pi
    /// walking the lane orbit through a temporary, rather than one fused pass
    /// of 25 hand-written assignments.
    fn reference_permute(state: &mut [u64; 25]) {
        /// Rotation applied to lane `PI[i]`, from FIPS 202 Algorithm 2.
        const RHO: [u32; 24] = [
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20,
            44,
        ];
        /// The lane orbit of `(x, y) -> (y, 2x + 3y)`, starting from lane 1.
        const PI: [usize; 24] = [
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
        ];

        for &round_constant in &RC {
            let mut parity = [0u64; 5];
            for (x, p) in parity.iter_mut().enumerate() {
                *p = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for x in 0..5 {
                let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    state[x + 5 * y] ^= d;
                }
            }

            // Rho + pi, walking the orbit: lane 0 is the only fixed point.
            let mut carried = state[1];
            for i in 0..24 {
                let dest = PI[i];
                let next = state[dest];
                state[dest] = carried.rotate_left(RHO[i]);
                carried = next;
            }

            for row in (0..25).step_by(5) {
                let a: [u64; 5] = state[row..row + 5].try_into().unwrap();
                for x in 0..5 {
                    state[row + x] = a[x] ^ (!a[(x + 1) % 5] & a[(x + 2) % 5]);
                }
            }

            state[0] ^= round_constant;
        }
    }

    // ---- Batch API ----

    /// The batch API must agree with the single-message one message for
    /// message, at every batch size around and beyond the widest backend, and
    /// for every function.
    #[test]
    fn many_matches_single() {
        assert!(sha3_256_many(&[]).is_empty());

        let bodies: Vec<Vec<u8>> = LENGTHS.iter().map(|&len| pattern(len)).collect();

        // Batch sizes that straddle every lane count: a partial group, exact
        // groups, and groups plus a remainder.
        for count in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 17] {
            let group: Vec<&[u8]> = (0..count)
                .map(|i| bodies[i % bodies.len()].as_slice())
                .collect();

            assert_eq!(
                sha3_224_many(&group),
                group.iter().map(|m| sha3_224(m)).collect::<Vec<_>>(),
                "sha3-224, count = {count}"
            );
            assert_eq!(
                sha3_256_many(&group),
                group.iter().map(|m| sha3_256(m)).collect::<Vec<_>>(),
                "sha3-256, count = {count}"
            );
            assert_eq!(
                sha3_384_many(&group),
                group.iter().map(|m| sha3_384(m)).collect::<Vec<_>>(),
                "sha3-384, count = {count}"
            );
            assert_eq!(
                sha3_512_many(&group),
                group.iter().map(|m| sha3_512(m)).collect::<Vec<_>>(),
                "sha3-512, count = {count}"
            );

            for out_len in [1usize, 32, 168, 200] {
                assert_eq!(
                    shake128_many(&group, out_len),
                    group
                        .iter()
                        .map(|m| {
                            let mut o = vec![0u8; out_len];
                            shake128(m, &mut o);
                            o
                        })
                        .collect::<Vec<_>>(),
                    "shake128, count = {count}, out_len = {out_len}"
                );
                assert_eq!(
                    shake256_many(&group, out_len),
                    group
                        .iter()
                        .map(|m| {
                            let mut o = vec![0u8; out_len];
                            shake256(m, &mut o);
                            o
                        })
                        .collect::<Vec<_>>(),
                    "shake256, count = {count}, out_len = {out_len}"
                );
            }
        }
    }

    /// Lanes that run out of blocks at different times are the tricky case: a
    /// sponge must not be permuted again after its final block, so each lane
    /// has to leave the batch at exactly the right moment.
    #[test]
    fn many_handles_mixed_lengths() {
        // Deliberately adversarial: within one group of 4, mix an empty
        // message, a sub-block one, an exact multiple of several rates, and
        // one much longer than the rest.
        let lengths = [
            0usize, 1, 136, 137, 272, 1, 0, 10_000, 71, 72, 73, 144, 168, 5, 4096, 0, 9, 200, 1000,
            136,
        ];
        let bodies: Vec<Vec<u8>> = lengths.iter().map(|&len| pattern(len)).collect();
        let group: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();

        assert_eq!(
            sha3_256_many(&group),
            group.iter().map(|m| sha3_256(m)).collect::<Vec<_>>()
        );
        assert_eq!(
            sha3_512_many(&group),
            group.iter().map(|m| sha3_512(m)).collect::<Vec<_>>()
        );
        assert_eq!(
            shake128_many(&group, 300),
            group
                .iter()
                .map(|m| {
                    let mut o = vec![0u8; 300];
                    shake128(m, &mut o);
                    o
                })
                .collect::<Vec<_>>()
        );

        // Identical messages must give identical digests regardless of how
        // the batch is split into groups.
        let same = vec![b"cryptors".as_slice(); 33];
        assert_eq!(sha3_256_many(&same), vec![sha3_256(b"cryptors"); 33]);
    }

    /// Checks the public `permute` dispatch, whichever backend it picks,
    /// still matches the scalar reference end to end.
    #[test]
    fn public_api_matches_scalar() {
        for len in LENGTHS {
            let input = pattern(len);

            let mut sw = [0u8; 32];
            sponge(scalar::permute, RATE_256, SUFFIX_SHA3, &input, &mut sw);
            assert_eq!(sha3_256(&input), sw, "len = {len}");

            let mut sw = [0u8; 64];
            sponge(scalar::permute, RATE_512, SUFFIX_SHA3, &input, &mut sw);
            assert_eq!(sha3_512(&input), sw, "len = {len}");

            let mut sw = [0u8; 137];
            sponge(
                scalar::permute,
                RATE_SHAKE128,
                SUFFIX_SHAKE,
                &input,
                &mut sw,
            );
            let mut got = [0u8; 137];
            shake128(&input, &mut got);
            assert_eq!(got, sw, "shake128, len = {len}");
        }
    }

    // ---- Throughput ----

    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture"]
    fn throughput() {
        use std::time::Instant;

        let data = vec![0x61u8; 64 * 1024 * 1024];

        // The first pass over a fresh buffer is slowed by page faults and CPU
        // clock ramp-up, not just Keccak, so warm up before timing.
        std::hint::black_box(sha3_256(&data));

        /// Runs `sponge` over `data` five times and prints the best rate.
        fn time(name: &str, backend: &str, data: &[u8], sponge: impl Fn(&[u8], &mut [u8])) {
            let mib = data.len() as f64 / (1024.0 * 1024.0);
            let mut out = [0u8; 64];
            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                sponge(data, &mut out);
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "{name} [{backend}]: {mib:.0} MiB, best {best:.1} MiB/s (digest {}...)",
                hex(&out[..8])
            );
        }

        // (name, rate, suffix, output bytes): the fixed digests at their own
        // size, the XOFs producing 32 bytes.
        let cases = [
            ("sha3-224", RATE_224, SUFFIX_SHA3, 28),
            ("sha3-256", RATE_256, SUFFIX_SHA3, 32),
            ("sha3-384", RATE_384, SUFFIX_SHA3, 48),
            ("sha3-512", RATE_512, SUFFIX_SHA3, 64),
            ("shake128", RATE_SHAKE128, SUFFIX_SHAKE, 32),
            ("shake256", RATE_SHAKE256, SUFFIX_SHAKE, 32),
        ];

        for (name, rate, suffix, len) in cases {
            // Exactly the public API's path: the dispatcher picks the backend.
            time(name, active_backend(), &data, |d, out| {
                sponge(permute, rate, suffix, d, &mut out[..len])
            });

            // Where the dispatcher picked something faster, time the portable
            // scalar backend too, so it can be compared across machines.
            if active_backend() != "scalar" {
                time(name, "scalar", &data, |d, out| {
                    sponge(scalar::permute, rate, suffix, d, &mut out[..len])
                });
            }
        }
    }

    /// Times the bare permutation of every backend compiled into this binary
    /// that the CPU can run, each called directly. Unlike [`throughput`], this
    /// measures the scalar backend even where the dispatcher would never pick
    /// it, and leaves out the sponge's absorbing and squeezing (about 3% of
    /// the work for a long message).
    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture"]
    fn permutation_throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        /// Times `permute`, which permutes `states` states per call, and
        /// prints the cost of one permutation.
        fn time<S>(name: &str, states: usize, mut state: S, mut permute: impl FnMut(&mut S)) {
            const PERMUTATIONS: usize = 1 << 20;
            let calls = PERMUTATIONS / states;

            for _ in 0..calls / 8 {
                permute(black_box(&mut state));
            }
            let mut best = f64::MAX;
            for _ in 0..5 {
                let start = Instant::now();
                for _ in 0..calls {
                    permute(black_box(&mut state));
                }
                best = best.min(start.elapsed().as_secs_f64());
            }
            black_box(state);

            let ns = best * 1e9 / (calls * states) as f64;
            // The throughput the permutation alone would allow at SHA3-256's
            // rate: the ceiling for any sponge built on it.
            let ceiling = RATE_256 as f64 / (ns * 1e-9) / (1024.0 * 1024.0);
            println!(
                "keccak-f[1600] [{name}]: {ns:.1} ns per permutation, SHA3-256 ceiling {ceiling:.0} MiB/s"
            );
        }

        time("scalar", 1, [0u64; 25], scalar::permute);

        #[cfg(target_arch = "x86_64")]
        {
            if has_bmi() {
                // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
                time("scalar, BMI1/BMI2", 1, [0u64; 25], |s| unsafe {
                    scalar::permute_bmi(s)
                });
            }
            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: `is_x86_feature_detected` just confirmed `avx2`.
                time("x86_64 AVX2, 4 lanes", 4, [[0u64; 4]; 25], |s| unsafe {
                    crate::sha3::x86::permute4(s)
                });
            }
            // SAFETY: `sse2` is guaranteed by the x86-64 target baseline.
            time("x86_64 SSE2, 2 lanes", 2, [[0u64; 2]; 25], |s| unsafe {
                crate::sha3::x86::permute2(s)
            });
        }

        #[cfg(target_arch = "aarch64")]
        if has_hw_sha3() {
            // SAFETY: has_hw_sha3() just confirmed the `sha3` feature.
            time("aarch64 FEAT_SHA3", 1, [0u64; 25], |s| unsafe {
                crate::sha3::aarch64::permute(s)
            });
            // SAFETY: as above.
            time(
                "aarch64 FEAT_SHA3, 2 lanes",
                2,
                [[0u64; 2]; 25],
                |s| unsafe { crate::sha3::aarch64::permute_many(s) },
            );
        }
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture"]
    fn throughput_many() {
        use std::time::Instant;

        const TOTAL: usize = 64 * 1024 * 1024;
        const MSG: usize = 64 * 1024;

        let body = vec![0x61u8; MSG];
        let messages = vec![body.as_slice(); TOTAL / MSG];
        let mib = TOTAL as f64 / (1024.0 * 1024.0);
        let (backend, width) = active_many_backend();

        std::hint::black_box(sha3_256_many(&messages));

        let mut best = 0.0f64;
        for _ in 0..5 {
            let start = Instant::now();
            let out = sha3_256_many(&messages);
            best = best.max(mib / start.elapsed().as_secs_f64());
            std::hint::black_box(out);
        }
        println!(
            "sha3-256 x{} [{backend}, {width} lanes]: {mib:.0} MiB, best {best:.1} MiB/s",
            messages.len()
        );

        // The same total bytes, one message at a time, as the baseline the
        // multi-buffer number should be compared against.
        let mut best_single = 0.0f64;
        for _ in 0..5 {
            let start = Instant::now();
            for m in &messages {
                std::hint::black_box(sha3_256(m));
            }
            best_single = best_single.max(mib / start.elapsed().as_secs_f64());
        }
        println!(
            "sha3-256 x{} [{}, 1 at a time]: {mib:.0} MiB, best {best_single:.1} MiB/s ({:.2}x from lanes)",
            messages.len(),
            active_backend(),
            best / best_single
        );

        // And on the portable scalar backend, as in `throughput`.
        if active_backend() != "scalar" {
            let mut best_scalar = 0.0f64;
            let mut out = [0u8; 32];
            for _ in 0..5 {
                let start = Instant::now();
                for m in &messages {
                    sponge(scalar::permute, RATE_256, SUFFIX_SHA3, m, &mut out);
                    std::hint::black_box(&out);
                }
                best_scalar = best_scalar.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "sha3-256 x{} [scalar, 1 at a time]: {mib:.0} MiB, best {best_scalar:.1} MiB/s ({:.2}x from lanes)",
                messages.len(),
                best / best_scalar
            );
        }
    }
}
