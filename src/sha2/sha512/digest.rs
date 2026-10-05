use crate::Digest;
#[cfg(target_arch = "x86_64")]
use crate::sha2::has_bmi;

/// Initial hash state for SHA-384: the first 64 bits of the fractional parts
/// of the square roots of the 9th through 16th primes (FIPS 180-4 section 5.3.4).
const INIT_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Initial hash state for SHA-512: the first 64 bits of the fractional parts
/// of the square roots of the first eight primes (FIPS 180-4 section 5.3.5).
const INIT_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Initial hash state for SHA-512/224 (FIPS 180-4 section 5.3.6.1), as the
/// standard's generation function produces it: SHA-512, started from its
/// initial state XOR `0xa5a5a5a5a5a5a5a5`, applied to the string "SHA-512/224".
/// The `sha512_t_initial_states` test runs that function and compares.
const INIT_512_224: [u64; 8] = [
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1,
];

/// Initial hash state for SHA-512/256 (FIPS 180-4 section 5.3.6.2), from the
/// same generation function applied to the string "SHA-512/256".
const INIT_512_256: [u64; 8] = [
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2,
];

/// Round constants: the first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes (FIPS 180-4 section 4.2.3).
pub(super) const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_hw_sha512() -> bool {
    // Rust reports FEAT_SHA512 as part of `sha3`. On targets where that is in
    // the baseline the first half is true at compile time, so the runtime
    // check is skipped entirely.
    cfg!(target_feature = "sha3") || std::arch::is_aarch64_feature_detected!("sha3")
}

/// Hashes every full 128-byte block in `blocks` into `state`, picking the
/// fastest backend the CPU supports.
///
/// We check which backend to use once per call, not once per block, so the
/// hardware backends only need to set up once per message instead of once
/// per block.
#[inline]
fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if has_hw_sha512() {
        // SAFETY: has_hw_sha512() just confirmed the `sha3` feature is available.
        unsafe { super::aarch64::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_bmi() {
        // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
        unsafe { super::scalar::compress_bmi(state, blocks) };
        return;
    }

    super::scalar::compress(state, blocks);
}

/// SHA-384 (FIPS 180-4): a 384-bit digest. The SHA-512 algorithm, started from
/// its own initial state, with the last two words of the result left out.
///
/// A zero-sized namespace for the hashing functions; it holds no state.
///
/// ```
/// use cryptors::{Digest, sha2::Sha384};
///
/// assert_eq!(Sha384::digest(b"abc")[0], 0xcb);
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Sha384;

impl Digest for Sha384 {
    const BLOCK_LEN: usize = 128;
    const OUTPUT_LEN: usize = 48;
    type Output = [u8; 48];

    /// Computes the 384-bit SHA-384 digest of `input`.
    ///
    /// Full blocks are hashed straight out of `input` without copying; only
    /// the last partial block (plus padding) is copied onto the stack.
    fn digest(input: &[u8]) -> [u8; 48] {
        to_bytes(&hash_with(compress, INIT_384, input))
    }
}

/// SHA-512 (FIPS 180-4): a 512-bit digest.
///
/// A zero-sized namespace for the hashing functions; it holds no state.
///
/// ```
/// use cryptors::{Digest, sha2::Sha512};
///
/// assert_eq!(Sha512::digest(b"abc")[0], 0xdd);
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Sha512;

impl Digest for Sha512 {
    const BLOCK_LEN: usize = 128;
    const OUTPUT_LEN: usize = 64;
    type Output = [u8; 64];

    /// Computes the 512-bit SHA-512 digest of `input`.
    ///
    /// Full blocks are hashed straight out of `input` without copying; only
    /// the last partial block (plus padding) is copied onto the stack.
    fn digest(input: &[u8]) -> [u8; 64] {
        to_bytes(&hash_with(compress, INIT_512, input))
    }
}

/// SHA-512/224 (FIPS 180-4): a 224-bit digest. The SHA-512 algorithm, started
/// from an initial state of its own, with the result cut to 224 bits.
///
/// A zero-sized namespace for the hashing functions; it holds no state.
///
/// ```
/// use cryptors::{Digest, sha2::Sha512_224};
///
/// assert_eq!(Sha512_224::digest(b"abc")[0], 0x46);
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Sha512_224;

impl Digest for Sha512_224 {
    const BLOCK_LEN: usize = 128;
    const OUTPUT_LEN: usize = 28;
    type Output = [u8; 28];

    /// Computes the 224-bit SHA-512/224 digest of `input`.
    ///
    /// Full blocks are hashed straight out of `input` without copying; only
    /// the last partial block (plus padding) is copied onto the stack.
    fn digest(input: &[u8]) -> [u8; 28] {
        to_bytes(&hash_with(compress, INIT_512_224, input))
    }
}

/// SHA-512/256 (FIPS 180-4): a 256-bit digest. The SHA-512 algorithm, started
/// from an initial state of its own, with the result cut to 256 bits.
///
/// A zero-sized namespace for the hashing functions; it holds no state.
///
/// ```
/// use cryptors::{Digest, sha2::Sha512_256};
///
/// assert_eq!(Sha512_256::digest(b"abc")[0], 0x53);
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Sha512_256;

impl Digest for Sha512_256 {
    const BLOCK_LEN: usize = 128;
    const OUTPUT_LEN: usize = 32;
    type Output = [u8; 32];

    /// Computes the 256-bit SHA-512/256 digest of `input`.
    ///
    /// Full blocks are hashed straight out of `input` without copying; only
    /// the last partial block (plus padding) is copied onto the stack.
    fn digest(input: &[u8]) -> [u8; 32] {
        to_bytes(&hash_with(compress, INIT_512_256, input))
    }
}

/// Pads `input`, runs every block through `compress_fn` starting from the
/// initial state `init`, and returns the final state. The four functions
/// differ only in `init` and in how much of this state they output.
///
/// Takes the backend as a parameter so tests can force a specific one; the
/// public functions always call this with the auto-selected `compress`, so it
/// costs nothing in the normal case.
#[inline]
fn hash_with<F: FnMut(&mut [u64; 8], &[u8])>(
    mut compress_fn: F,
    init: [u64; 8],
    input: &[u8],
) -> [u64; 8] {
    let mut state = init;

    let aligned = input.len() & !127;
    compress_fn(&mut state, &input[..aligned]);
    let remainder = &input[aligned..];

    // The leftover bytes plus the required padding (a 0x80 marker byte and
    // a 16-byte length) never need more than one extra 128-byte block.
    let mut tail = [0u8; 256];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;

    // The length field holds 128 bits, and a slice can't be longer than
    // `isize::MAX` bytes, so the multiplication can't overflow.
    let bit_len = (input.len() as u128) * 8;
    let total_len = if remainder.len() < 112 { 128 } else { 256 };
    tail[total_len - 16..total_len].copy_from_slice(&bit_len.to_be_bytes());

    compress_fn(&mut state, &tail[..total_len]);
    state
}

/// Writes the leading `N` bytes of `state` out big-endian: all 64 for
/// SHA-512, the first 48 for SHA-384, and so on. SHA-512/224 ends in the
/// middle of a word, with the first four bytes of the fourth.
fn to_bytes<const N: usize>(state: &[u64; 8]) -> [u8; N] {
    const { assert!(N <= 64) };

    let mut full = [0u8; 64];
    for (word, chunk) in state.iter().zip(full.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::hex;
    use crate::sha2::sha512::scalar;

    /// A backend's compression function, callable like `scalar::compress`.
    type Backend = fn(&mut [u64; 8], &[u8]);

    /// Every backend this CPU can run, named, in the order `compress` prefers
    /// them: the first entry is the one the public functions use, and the
    /// last is always `scalar`.
    ///
    /// The hardware backends are `unsafe` to call because they need a CPU
    /// feature. Each is wrapped in a safe function pointer here, and only
    /// added to the list after that feature has been confirmed, so every
    /// entry is safe to call on this machine.
    fn backends() -> Vec<(&'static str, Backend)> {
        let mut list: Vec<(&'static str, Backend)> = Vec::new();

        #[cfg(target_arch = "aarch64")]
        if has_hw_sha512() {
            // SAFETY: has_hw_sha512() just confirmed the `sha3` feature is available.
            list.push(("aarch64 (FEAT_SHA512)", |s, b| unsafe {
                crate::sha2::sha512::aarch64::compress(s, b)
            }));
        }

        #[cfg(target_arch = "x86_64")]
        if has_bmi() {
            // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
            list.push(("scalar (BMI1+BMI2)", |s, b| unsafe {
                scalar::compress_bmi(s, b)
            }));
        }

        list.push(("scalar", scalar::compress));
        list
    }

    /// Which backend `compress` picks on this machine.
    fn active_backend() -> &'static str {
        backends()[0].0
    }

    /// The four initial states, with the number of output bytes each function
    /// keeps, for tests that run all of them.
    const FUNCTIONS: [(&str, [u64; 8], usize); 4] = [
        ("sha384", INIT_384, 48),
        ("sha512", INIT_512, 64),
        ("sha512_224", INIT_512_224, 28),
        ("sha512_256", INIT_512_256, 32),
    ];

    /// Message lengths around every point where the padding layout changes
    /// (a partial block of 111 bytes is the last that leaves room for the
    /// marker and length; 112 forces a second block) plus a few larger sizes
    /// that run the main loop of a backend for many blocks.
    const LENGTHS: [usize; 32] = [
        0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 241, 255, 256, 257, 383, 384, 385, 511, 512,
        513, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 4097, 65536, 65537, 100_000, 100_001,
    ];

    /// A deterministic input that does not repeat within a block, so a
    /// backend that confuses two words of the message cannot go unnoticed.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The digest of one message under each of the four functions, as hex.
    struct Digests {
        sha384: &'static str,
        sha512: &'static str,
        sha512_224: &'static str,
        sha512_256: &'static str,
    }

    /// Checks `input` against `expected` through the public functions.
    fn assert_public(input: &[u8], expected: &Digests, what: &str) {
        assert_eq!(
            Sha384::hex_digest(input),
            expected.sha384,
            "SHA-384, {what}"
        );
        assert_eq!(
            Sha512::hex_digest(input),
            expected.sha512,
            "SHA-512, {what}"
        );
        assert_eq!(
            Sha512_224::hex_digest(input),
            expected.sha512_224,
            "SHA-512/224, {what}"
        );
        assert_eq!(
            Sha512_256::hex_digest(input),
            expected.sha512_256,
            "SHA-512/256, {what}"
        );
    }

    /// Checks `input` against `expected` through the scalar backend
    /// specifically.
    ///
    /// The public functions skip `scalar` on a machine with hardware SHA-512.
    /// Without this, the scalar backend would never actually get checked on
    /// such a machine.
    fn assert_scalar(input: &[u8], expected: &Digests, what: &str) {
        let state = |init| hash_with(scalar::compress, init, input);
        assert_eq!(
            hex(&to_bytes::<48>(&state(INIT_384))),
            expected.sha384,
            "SHA-384, {what}"
        );
        assert_eq!(
            hex(&to_bytes::<64>(&state(INIT_512))),
            expected.sha512,
            "SHA-512, {what}"
        );
        assert_eq!(
            hex(&to_bytes::<28>(&state(INIT_512_224))),
            expected.sha512_224,
            "SHA-512/224, {what}"
        );
        assert_eq!(
            hex(&to_bytes::<32>(&state(INIT_512_256))),
            expected.sha512_256,
            "SHA-512/256, {what}"
        );
    }

    /// Known-answer vectors.
    ///
    /// "abc" and the 896-bit message are the example messages NIST publishes
    /// for FIPS 180-4 (the third example, a million repetitions of "a", is
    /// `MILLION_A` below). The empty message, the 448-bit message and the pangram are
    /// common extra checks.
    const VECTORS: [(&[u8], Digests); 5] = [
        (
            b"",
            Digests {
                sha384: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                sha512_224: "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
                sha512_256: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            },
        ),
        (
            b"abc",
            Digests {
                sha384: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                sha512: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                sha512_224: "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
                sha512_256: "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            },
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            Digests {
                sha384: "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
                sha512: "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
                sha512_224: "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
                sha512_256: "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
            },
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            Digests {
                sha384: "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
                sha512: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
                sha512_224: "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
                sha512_256: "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
            },
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            Digests {
                sha384: "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
                sha512: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
                sha512_224: "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
                sha512_256: "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
            },
        ),
    ];

    const MILLION_A: Digests = Digests {
        sha384: "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        sha512: "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        sha512_224: "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
        sha512_256: "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
    };

    /// Digests of `pattern(len)` for lengths at the padding boundaries, as
    /// computed by two independent SHA-2 implementations (OpenSSL and Go's
    /// standard library): (length, digests).
    const PATTERN_DIGESTS: [(usize, Digests); 16] = [
        (
            1,
            Digests {
                sha384: "bec021b4f368e3069134e012c2b4307083d3a9bdd206e24e5f0d86e13d6636655933ec2b413465966817a9c208a11717",
                sha512: "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
                sha512_224: "283bb59af7081ed08197227d8f65b9591ffe1155be43e9550e57f941",
                sha512_256: "10baad1713566ac2333467bddb0597dec9066120dd72ac2dcb8394221dcbe43d",
            },
        ),
        (
            111,
            Digests {
                sha384: "f5f9fe110d809d34029de262a01b208356caec6e054c7f926b2591f6c9780579d4b59f5578c6f531a84f158a33660cef",
                sha512: "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d",
                sha512_224: "f8810ee322210d0f4cbd7a4e92e7d7e72b63d2777dcb531e13ddd690",
                sha512_256: "bd209f60b0d04102a09175297fd255367e54b5a5605b928635c606306914363f",
            },
        ),
        (
            112,
            Digests {
                sha384: "33ba080ec0ccb378e4e95fed3b26c23aa1a280476e007519ee47f60cd9c5c8a65d627259a9aa2fd33ca06d3c14ee5548",
                sha512: "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9",
                sha512_224: "8099918892ebbd31215c9bb5e4e53c0b52927b000ced0720d2c65a22",
                sha512_256: "2cafeb0882cc405167e9a255b8581a66dc683212474902dd453dbca20a94e61a",
            },
        ),
        (
            113,
            Digests {
                sha384: "f14fc73c4192759b70993dc35fbee193a60a98dbd1f8b2421afa253dec63015a0d6b75fb50f9f9a5f7fb8e7241540699",
                sha512: "61b2e77db697dfe5571fff3ed06bd60c41e1e7b7c08a80de01cb16526d9a9a52d690dfbe792278a60f6e2b4c57a97c729773f26e258d2393890c985d645f6715",
                sha512_224: "8aa886cfb7357d802e9043498bb9ca36c80a79dcbfe06c9324f8c027",
                sha512_256: "3222333be019dc995e5dd1496d5859ddaa491e03e7df81a659d5e74957bf3b53",
            },
        ),
        (
            127,
            Digests {
                sha384: "d5fcfe2fcf6b3ef375ede37c8123d9b78065fecc1d55197e2f7721e6e9a93d0ba4d7fd15f9b96dea2744df24141ba2ef",
                sha512: "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0",
                sha512_224: "29d2c4166a36e07b2dcd3a7c988dcb14776dc187040f6a733162efb7",
                sha512_256: "c26bc7e9315e62ab0dc6aeb577724d07c09b0c6fdfc0a9f08d8548047c032248",
            },
        ),
        (
            128,
            Digests {
                sha384: "ca2385773319124534111a36d0581fc3f00815e907034b90cff9c3a861e126a741d5dfcff65a417b6d7296863ac0ec17",
                sha512: "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7",
                sha512_224: "49a64b72a88a3c93432b6e4c59a1b4908403f70e46e13bf7494fbe88",
                sha512_256: "2ff11194b2aec1f943cb5f130ba647c151334068083194d7281a55d607ae255f",
            },
        ),
        (
            129,
            Digests {
                sha384: "ef49ae5b9ad51433d00323528d81ea8d2e4d2b507dbd9f1cb84f952b66249a788b1c89fcdb77a0db9f1feb901d47fc73",
                sha512: "1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f",
                sha512_224: "aa05964c59a40bb5140f3f1b9ca03c3eee0a1044bbd3fe84e5936877",
                sha512_256: "c4a3bbf841ed2a289e5109fb392229c80db61c72fd92079b5a4f0441f095a111",
            },
        ),
        (
            239,
            Digests {
                sha384: "2556cf077a788c49bb6d600f4a3cee635c4443832d169f761537afee2980742b9f34afbc87f598dd0aedc4a826ed6a73",
                sha512: "cb4c7fd522756d5781ad3a4f590a1d862906b960e7720136cb3fb36b563caa1ea5689134291fa79c80ccc2b4092b41df32ebdcb36dbe79db483440228c1622a8",
                sha512_224: "5f3fd8a5a4ef847d833b2faaa74a30fe51d22c68244298a25302b7ed",
                sha512_256: "b81472d255d80182e196481e5866aa207761a152302a0237e242eb88c577a428",
            },
        ),
        (
            240,
            Digests {
                sha384: "d64769ad58f5a338669b935f3431e5bef31667d0a2437bff78f1e5275075f434fff675f9833ea04ac4e5c2e2c2c99b8c",
                sha512: "6c48466c9f6c07e4ab762c696b7eeb35cfe236fca73683e5fab873ac3489b4d2eb3d7afcce7e8165dbbf37aded3b5b0c889c0b7e0f1790a8330d8677429d91a5",
                sha512_224: "181dbae9308b111d4ae06a6229d6038c4afffb93a0eafda9cf1e83aa",
                sha512_256: "6ca13c55886b74a5ca2ac9782c4b9a49fe3aeeefdfc0cefc34984872fb4c54fd",
            },
        ),
        (
            241,
            Digests {
                sha384: "3264cad70d24b53cec95269b980dab85a30d24cf8bdbd68f0ff8a45c6208f05723a4b3270cd095fb8b2d9a4167fb3d3b",
                sha512: "4f663484efca758d670147758a5d4d9e5933fe22c0a1dc01f954738ff8310a6515b3ec42094449075ed678c55ee001a4fb91b1081dfae6ab83860b7b4cc7b4ab",
                sha512_224: "671d5ce9a1dbffb15b4449cde3dd91569f875d4bdf427e0b42de0974",
                sha512_256: "1a488e47268942a41b5733238286fb218ae45d4bd9b59b48e1c20478410943f6",
            },
        ),
        (
            255,
            Digests {
                sha384: "0ba9892ce126be582d86f75cd5e682092525cc6a232c5d8b83ce4b8b0eefd644a14cb58c7989108d90a16a99325e99b5",
                sha512: "e9746a5516961da1fdc8e6c59350cd147b7d80c120cc7ed621399faeb2462c28f34217a13009a8e6a721f538356db9a9b64d9a5412e0fd07d24cac1315d95548",
                sha512_224: "b411a5a0806d83eba9455301f9cc947cfe2b705eeedb89549e887fe0",
                sha512_256: "282a7af172c05b48cb02870d79ec5bc32fc2c6fd32d237d9b84728b6c36d2ed1",
            },
        ),
        (
            256,
            Digests {
                sha384: "2786ae11483c719dcb61b32652daf932d7c304f0d5d1e3904f6be6b44826d94de4fc922065558ad6aa10ae8b9eba005d",
                sha512: "7ff1cd1e9773a4b7ba1f40e642db0d879bd5f6cc151a7d3401a0bc7778b8270c108b530fb195f2383f4cec8cf05778e6af4db56811673371674cec1524488f83",
                sha512_224: "6fa84e430acfc84bdb28c830dea2feb2d23b536216fdf60ac4225edc",
                sha512_256: "0ea4199eb79185d8198973ee464a7e0eb26345b54b361ac6af8b1dc10d41911c",
            },
        ),
        (
            257,
            Digests {
                sha384: "ef86a8c8a9fedc22da3cde73091fba0498a7390fae805fe18ef681b3cfc0aec21b25a58ec1b3132fb365068c22f0e2b6",
                sha512: "9fc68cce815c180c9188fad684397a7e9b423b3dadc3a6d3db74538eaec0c63393df5c79983dd62d137bdde627d9b80afa5fa26a976ed9cdca348c2257d9102b",
                sha512_224: "aa4f20c7a0dfdec9f52d08e85145bedfeaeb38332e440b2e0176a211",
                sha512_256: "df2a5529f911b588c655586748d8c988eff070ba25478b47ff33f2662497d197",
            },
        ),
        (
            383,
            Digests {
                sha384: "f62086a61818fd6ba333c8089e7b32900c282f2baeec2d7e332684950815b9081492be976e528999ec2cddf473d5e159",
                sha512: "2ff65a18302b3d64af513dd60a5fec090514326c37391072803cd76e9c68e43410487a138f35104a4450b9b3112674958dad38115891baeec111abea6d09dbc6",
                sha512_224: "c019219c0b23738c76025cf093c5371cb439f1d00c688f0f5258f92d",
                sha512_256: "d2683114f0d54a01bfee89a497ed27c1b688e29390d9ed57a433bc79426658ed",
            },
        ),
        (
            384,
            Digests {
                sha384: "0ac7d66c3b4f0e682e8d64b8748c5f899b4b76745f54467c1336a4e1aec54385b0b8e2d096982c27be816933619c796c",
                sha512: "a99b75dce7a1ef874125a270ec39ce9ed862f6e60cbcffab716a2c0ff7170e0d59d73000e5a263cf2830acc8c86096e0e9b39982d34b3d7dd32058ed309c05d4",
                sha512_224: "fc353faddbd56c045720d395d22749b5079e86fbcec10b5b57e593eb",
                sha512_256: "7671fef864251344ec1178b26153700965a0b4f58f9d606afcccd391c7c31b4c",
            },
        ),
        (
            385,
            Digests {
                sha384: "e67cd6964458163cdfce8d0bf235ec24676779051e3285115f9398810fd5b35f8073dd1638216fdaacb41ceffa80af66",
                sha512: "086548b9e9699e3a7434c1be2a7e18b6439c0c40edf0b9cb2cef0fdd423858afdd29f1a72460029be8b5fd23aede2e60dc95bad38edbdce4f70da34a4d49a100",
                sha512_224: "145fce0f9af0860dbfe8e6fd2bbab0790b22623e8bea1cd85a4af186",
                sha512_256: "117cf5a91a45067492e2460ac388f79daedf6830087edd5d584fdbd83c10695c",
            },
        ),
    ];

    #[test]
    fn known_answers() {
        for (input, expected) in &VECTORS {
            assert_public(input, expected, &format!("input = {input:?}"));
        }
    }

    #[test]
    fn million_a() {
        // The third NIST example message: 1,000,000 repetitions of 'a'. It is
        // the only known-answer input big enough (7,813 blocks) to make a
        // backend's main loop run for long.
        assert_public(&vec![b'a'; 1_000_000], &MILLION_A, "one million 'a'");
    }

    #[test]
    fn padding_boundaries() {
        for (len, expected) in &PATTERN_DIGESTS {
            assert_public(&pattern(*len), expected, &format!("len = {len}"));
        }
    }

    /// Runs FIPS 180-4's SHA-512/t generation function (section 5.3.6) for
    /// `t` = 224 and 256 and checks that it reproduces the initial states
    /// above, so that those constants are derived from the standard's
    /// definition and not merely copied from a table.
    #[test]
    fn sha512_t_initial_states() {
        let generator = INIT_512.map(|word| word ^ 0xa5a5_a5a5_a5a5_a5a5);
        assert_eq!(
            hash_with(scalar::compress, generator, b"SHA-512/224"),
            INIT_512_224
        );
        assert_eq!(
            hash_with(scalar::compress, generator, b"SHA-512/256"),
            INIT_512_256
        );
    }

    /// Checks that every other backend this CPU can run produces exactly the
    /// same digest as the scalar backend.
    ///
    /// This calls each backend directly instead of going through `compress`,
    /// so the test can't accidentally end up comparing the scalar backend
    /// against itself. Backends the CPU doesn't support are not in
    /// `backends()`, so their part of the test is just skipped.
    #[test]
    fn matches_scalar_backend() {
        let others: Vec<_> = backends()
            .into_iter()
            .filter(|&(name, _)| name != "scalar")
            .collect();

        for (name, backend) in &others {
            for (function, init, _) in FUNCTIONS {
                for len in LENGTHS {
                    let input = pattern(len);
                    assert_eq!(
                        hash_with(backend, init, &input),
                        hash_with(scalar::compress, init, &input),
                        "{name} backend disagrees with scalar for {function} at len = {len}"
                    );
                }
            }
            println!("{name} backend matches scalar");
        }

        if others.is_empty() {
            println!("no hardware SHA-512 backend on this CPU; only the scalar path is in use");
        }
    }

    /// Checks that the digest does not depend on where in memory the message
    /// starts. The hardware backends read it with unaligned vector loads, and
    /// that is only correct if they never assume an alignment. Every backend
    /// is checked, not just the one the public functions pick.
    #[test]
    fn unaligned_input() {
        // Five full blocks and a partial one, starting at every offset in
        // the first 128 bytes of the buffer.
        let len = 128 * 5 + 7;
        let backing = pattern(128 + len);
        for (name, backend) in backends() {
            for (function, init, _) in FUNCTIONS {
                for offset in 0..128 {
                    let input = &backing[offset..offset + len];
                    // The same bytes in a fresh allocation, as the reference.
                    let aligned = input.to_vec();
                    assert_eq!(
                        hash_with(backend, init, input),
                        hash_with(scalar::compress, init, &aligned),
                        "{name} backend, {function}, offset = {offset}"
                    );
                }
            }
        }
    }

    /// Checks the known-answer vectors against the scalar backend.
    #[test]
    fn scalar_known_answers() {
        for (input, expected) in &VECTORS {
            assert_scalar(input, expected, &format!("input = {input:?}"));
        }
        assert_scalar(&vec![b'a'; 1_000_000], &MILLION_A, "one million 'a'");
        for (len, expected) in &PATTERN_DIGESTS {
            assert_scalar(&pattern(*len), expected, &format!("len = {len}"));
        }
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release sha2::sha512 -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        let data = vec![0x61u8; 64 * 1024 * 1024];
        let mib = data.len() as f64 / (1024.0 * 1024.0);

        // The first pass over a fresh buffer is slowed down by page faults and
        // CPU clock ramp-up, not just SHA-512 itself. So we warm up once, then
        // time several runs and keep the best.
        std::hint::black_box(Sha512::digest(&data));

        /// Runs `hash` over `data` five times and prints the best rate.
        fn time(name: &str, backend: &str, data: &[u8], mib: f64, hash: impl Fn(&[u8]) -> Vec<u8>) {
            let mut best = 0.0f64;
            let mut digest = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                digest = hash(data);
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "{name} [{backend}]: {mib:.0} MiB, best {best:.1} MiB/s (digest {}...)",
                hex(&digest[..8])
            );
        }

        // Exactly the public API's path: the dispatcher picks the backend.
        time("sha384", active_backend(), &data, mib, |d| {
            Sha384::digest(d).to_vec()
        });
        time("sha512", active_backend(), &data, mib, |d| {
            Sha512::digest(d).to_vec()
        });
        time("sha512_224", active_backend(), &data, mib, |d| {
            Sha512_224::digest(d).to_vec()
        });
        time("sha512_256", active_backend(), &data, mib, |d| {
            Sha512_256::digest(d).to_vec()
        });

        // Then every backend the dispatcher passed over, down to scalar, so
        // that one run on a machine with the fastest instructions also
        // measures the paths other CPUs would take.
        for (backend_name, backend) in backends().into_iter().skip(1) {
            for (name, init, len) in FUNCTIONS {
                time(name, backend_name, &data, mib, |d| {
                    to_bytes::<64>(&hash_with(backend, init, d))[..len].to_vec()
                });
            }
        }
    }
}
