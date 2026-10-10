//! AES-GCM's counter mode and tag (NIST SP 800-38D sections 6.5 and 7), over
//! the crate's AES through [`BlockCipher`] and a GHASH backend.

use super::ghash::{AGGREGATE, Backend, Ghash, HashKey};
use crate::BlockCipher;
use crate::wipe::wipe;

/// The length of a nonce: 96 bits, the one length for which `J0` is the nonce
/// itself and a counter.
pub(crate) const NONCE_LEN: usize = 12;

/// The length of a tag: the full 128 bits.
const TAG_LEN: usize = 16;

/// The longest plaintext under one nonce, in bytes: 2^39 - 256 bits (SP 800-38D
/// section 5.2.1.1). The 32-bit counter starts at 2 and would wrap after
/// 2^32 - 2 blocks.
const MAX_TEXT_LEN: u64 = (1 << 36) - 32;

/// The longest associated data, in bytes: 2^64 - 1 bits.
const MAX_AAD_LEN: u64 = (1 << 61) - 1;

/// How much is encrypted and hashed at a time: four times as many blocks as
/// the hardware GHASH backends reduce at once, 1 KiB. The copy, the keystream
/// and the hash of a chunk all run while it is in the L1 cache, and the GHASH
/// backends load their powers of `H` once per chunk. A chunk of one group
/// measured 9% slower on an Apple M1 Pro, and one of eight no faster.
const CHUNK: usize = 16 * AGGREGATE * 4;

/// A message longer than GCM allows under one nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TooLong;

/// A ciphertext that did not authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NotAuthentic;

/// Whether associated data and a text of these lengths are within GCM's limits.
fn lengths_fit(aad_len: usize, text_len: usize) -> bool {
    u64::try_from(aad_len).is_ok_and(|len| len <= MAX_AAD_LEN)
        && u64::try_from(text_len).is_ok_and(|len| len <= MAX_TEXT_LEN)
}

/// AES-GCM under one key: the block cipher and the GHASH key derived from it.
///
/// Both are wiped when the value is dropped: the cipher by its own `Drop`, the
/// hash key by its.
pub(crate) struct Gcm<C> {
    cipher: C,
    key: HashKey,
}

impl<C: BlockCipher<Block = [u8; 16]>> Gcm<C> {
    /// Expands `key` for the cipher, and derives the hash key `H = E_K(0^128)`
    /// (SP 800-38D section 7.1, step 1) for the fastest GHASH backend the CPU
    /// supports.
    pub(crate) fn new(key: &C::Key) -> Self {
        Self::with_backend(key, Backend::detect())
    }

    fn with_backend(key: &C::Key, backend: Backend) -> Self {
        let cipher = C::new(key);
        let mut h = cipher.encrypt_block(&[0; 16]);
        let key = HashKey::new(&h, backend);
        wipe(&mut h);
        Self { cipher, key }
    }

    /// GCM-AE (SP 800-38D section 7.1): the ciphertext of `plaintext` with the
    /// tag appended.
    pub(crate) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TooLong> {
        if !lengths_fit(aad.len(), plaintext.len()) {
            return Err(TooLong);
        }
        // Allocated at its final size, so the plaintext copied in never moves.
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);

        let mut ghash = Ghash::new(&self.key);
        ghash.update(aad);
        let mut counter = Counter::new(nonce);
        for chunk in plaintext.chunks(CHUNK) {
            let start = out.len();
            out.extend_from_slice(chunk);
            let chunk = &mut out[start..];
            counter.apply(&self.cipher, chunk);
            ghash.update(chunk);
        }
        let tag = self.tag(nonce, ghash, aad.len(), plaintext.len());
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// GCM-AD (SP 800-38D section 7.2): the plaintext of `ciphertext`, which
    /// ends in its tag, or [`NotAuthentic`] if the tag does not match.
    ///
    /// The ciphertext is hashed and decrypted in one pass, so the plaintext
    /// exists before the tag has been checked; if the tag does not match, it is
    /// overwritten with zeros and never returned.
    pub(crate) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NotAuthentic> {
        let Some((body, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(NotAuthentic);
        };
        // A ciphertext over the limit cannot have come from `seal`.
        if !lengths_fit(aad.len(), body.len()) {
            return Err(NotAuthentic);
        }
        let mut out = Vec::with_capacity(body.len());

        let mut ghash = Ghash::new(&self.key);
        ghash.update(aad);
        let mut counter = Counter::new(nonce);
        for chunk in body.chunks(CHUNK) {
            ghash.update(chunk);
            let start = out.len();
            out.extend_from_slice(chunk);
            counter.apply(&self.cipher, &mut out[start..]);
        }
        if !equal(&self.tag(nonce, ghash, aad.len(), body.len()), tag) {
            wipe(&mut out);
            return Err(NotAuthentic);
        }
        Ok(out)
    }

    /// The tag (SP 800-38D section 7.1, steps 5 and 6): `E_K(J0) ^ GHASH(A ||
    /// 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)`, the hash having taken
    /// in `A` and `C` already.
    fn tag(
        &self,
        nonce: &[u8; NONCE_LEN],
        ghash: Ghash<'_>,
        aad_len: usize,
        text_len: usize,
    ) -> [u8; TAG_LEN] {
        let s = ghash.finish(aad_len, text_len);
        let mut j0 = [0u8; 16];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[15] = 1;
        let mask = self.cipher.encrypt_block(&j0);
        core::array::from_fn(|i| s[i] ^ mask[i])
    }
}

/// GCTR from `inc32(J0)` (SP 800-38D section 6.5): the counter blocks `nonce ||
/// 2`, `nonce || 3`, ..., the counter a 32-bit big-endian integer that
/// `lengths_fit` keeps from wrapping.
struct Counter {
    block: [u8; 16],
    counter: u32,
}

impl Counter {
    fn new(nonce: &[u8; NONCE_LEN]) -> Self {
        let mut block = [0u8; 16];
        block[..NONCE_LEN].copy_from_slice(nonce);
        Self { block, counter: 2 }
    }

    /// The next block of keystream.
    fn next<C: BlockCipher<Block = [u8; 16]>>(&mut self, cipher: &C) -> [u8; 16] {
        self.block[NONCE_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        cipher.encrypt_block(&self.block)
    }

    /// XORs `data` with the next blocks of keystream. The encryptions do not
    /// depend on each other, so the CPU overlaps them.
    fn apply<C: BlockCipher<Block = [u8; 16]>>(&mut self, cipher: &C, data: &mut [u8]) {
        let (blocks, rest) = data.as_chunks_mut::<16>();
        for block in blocks {
            let keystream = self.next(cipher);
            for (byte, key) in block.iter_mut().zip(keystream) {
                *byte ^= key;
            }
        }
        if !rest.is_empty() {
            let keystream = self.next(cipher);
            for (byte, key) in rest.iter_mut().zip(keystream) {
                *byte ^= key;
            }
        }
    }
}

/// Whether two tags are equal, looking at every byte whatever they contain:
/// the OR of their XORs, compared once at the end.
fn equal(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::aes::{Aes128, Aes256};
    use crate::digest::hex;
    use crate::gcm::tests::{stream, unhex};
    use crate::sha2::Sha256;

    /// Seals with a key of 16 or 32 bytes, on `backend`.
    fn seal(
        backend: Backend,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        match key.len() {
            16 => Gcm::<Aes128>::with_backend(key.try_into().unwrap(), backend)
                .seal(nonce, aad, plaintext),
            32 => Gcm::<Aes256>::with_backend(key.try_into().unwrap(), backend)
                .seal(nonce, aad, plaintext),
            n => panic!("no AES-GCM key has {n} bytes"),
        }
        .unwrap()
    }

    fn open(
        backend: Backend,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NotAuthentic> {
        match key.len() {
            16 => Gcm::<Aes128>::with_backend(key.try_into().unwrap(), backend)
                .open(nonce, aad, ciphertext),
            32 => Gcm::<Aes256>::with_backend(key.try_into().unwrap(), backend)
                .open(nonce, aad, ciphertext),
            n => panic!("no AES-GCM key has {n} bytes"),
        }
    }

    /// The test cases of McGrew and Viega's GCM specification (Appendix B)
    /// with 96-bit IVs, for AES-128 (1 to 4) and AES-256 (13 to 16): (case,
    /// key, IV, plaintext, AAD, ciphertext, tag). They cover an empty message,
    /// one block, four, and three and a half with associated data.
    const SPEC_CASES: [(u32, &str, &str, &str, &str, &str, &str); 8] = [
        (
            1,
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ),
        (
            2,
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        (
            3,
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        ),
        (
            4,
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        ),
        (
            13,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        (
            14,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
        (
            15,
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        ),
        (
            16,
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ),
    ];

    #[test]
    fn known_answers() {
        // On every backend this CPU supports, the first being the one `new`
        // picks and the last always scalar, which on a machine with a
        // carry-less multiply the public path does not use.
        for backend in Backend::available() {
            for (case, key, iv, plaintext, aad, ciphertext, tag) in SPEC_CASES {
                let (key, plaintext, aad) = (unhex(key), unhex(plaintext), unhex(aad));
                let iv: [u8; 12] = unhex(iv).try_into().unwrap();
                let mut want = unhex(ciphertext);
                want.extend_from_slice(&unhex(tag));
                let what = format!("test case {case}, {}", backend.name());

                let sealed = seal(backend, &key, &iv, &aad, &plaintext);
                assert_eq!(hex(&sealed), hex(&want), "{what}");
                assert_eq!(
                    open(backend, &key, &iv, &aad, &sealed),
                    Ok(plaintext),
                    "{what}"
                );
            }
        }
    }

    #[test]
    fn many_lengths() {
        // Plaintexts of every length from 0 to 300 bytes, with associated data
        // of (7 i mod 41) bytes, each under its own key and nonce: the SHA-256
        // of all the sealed messages, from Go's crypto/cipher, on every
        // backend. Each also opens back.
        let expected = [
            (
                16,
                "b2e5831f4d8de8f41ce9fe45d7c062be62aa7e23078c9ed0034fd6985583cbfe",
            ),
            (
                32,
                "4645e27dd307e7f309ec1773d74cc7f3f20d42ae36230c9037da9e5cae57d78a",
            ),
        ];
        for backend in Backend::available() {
            for (key_len, want) in expected {
                let mut all = Vec::new();
                for i in 0..=300u32 {
                    let key = stream(b"gcm key", i, key_len);
                    let nonce: [u8; 12] = stream(b"gcm nonce", i, 12).try_into().unwrap();
                    let aad = stream(b"gcm aad", i, (i * 7 % 41) as usize);
                    let plaintext = stream(b"gcm plaintext", i, i as usize);
                    let sealed = seal(backend, &key, &nonce, &aad, &plaintext);
                    assert_eq!(
                        open(backend, &key, &nonce, &aad, &sealed),
                        Ok(plaintext),
                        "i = {i}"
                    );
                    all.extend_from_slice(&sealed);
                }
                let what = format!("{key_len}-byte keys, {}", backend.name());
                assert_eq!(hex(&Sha256::digest(&all)), want, "{what}");
            }
        }
    }

    #[test]
    fn long_messages() {
        // Messages longer than a chunk (1 KiB), at the boundaries of chunks
        // and of the GHASH groups inside them, with associated data of 5 i
        // bytes: the SHA-256 of the sealed messages, from Go's crypto/cipher,
        // on every backend. Each also opens back.
        let lengths = [1023, 1024, 1025, 1040, 2047, 2048, 2049, 4097, 65536 + 15];
        let expected = [
            (
                16,
                "50a895e55028da7576b5c89afb568adb90484137d98afbd3dd2d143a1d3cd12a",
            ),
            (
                32,
                "14dd0c354a9614741dfb5d11293a0b2e00f4880d6207de835598bbb12d6edf2b",
            ),
        ];
        for backend in Backend::available() {
            for (key_len, want) in expected {
                let mut all = Vec::new();
                for (i, len) in (0u32..).zip(lengths) {
                    let key = stream(b"gcm long key", i, key_len);
                    let nonce: [u8; 12] = stream(b"gcm long nonce", i, 12).try_into().unwrap();
                    let aad = stream(b"gcm long aad", i, i as usize * 5);
                    let plaintext = stream(b"gcm long plaintext", i, len);
                    let sealed = seal(backend, &key, &nonce, &aad, &plaintext);
                    assert_eq!(
                        open(backend, &key, &nonce, &aad, &sealed),
                        Ok(plaintext),
                        "{len} bytes"
                    );
                    all.extend_from_slice(&sealed);
                }
                let what = format!("{key_len}-byte keys, {}", backend.name());
                assert_eq!(hex(&Sha256::digest(&all)), want, "{what}");
            }
        }
    }

    #[test]
    fn any_change_fails_to_open() {
        // Test case 4, which has associated data and a partial last block.
        let backend = Backend::detect();
        let (_, key, iv, plaintext, aad, _, _) = SPEC_CASES[3];
        let (key, plaintext, aad) = (unhex(key), unhex(plaintext), unhex(aad));
        let iv: [u8; 12] = unhex(iv).try_into().unwrap();
        let sealed = seal(backend, &key, &iv, &aad, &plaintext);

        for bit in 0..sealed.len() * 8 {
            let mut forged = sealed.clone();
            forged[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                open(backend, &key, &iv, &aad, &forged),
                Err(NotAuthentic),
                "bit {bit}"
            );
        }
        for bit in 0..aad.len() * 8 {
            let mut other = aad.clone();
            other[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                open(backend, &key, &iv, &other, &sealed),
                Err(NotAuthentic),
                "aad bit {bit}"
            );
        }
        let mut other_iv = iv;
        other_iv[11] ^= 1;
        assert_eq!(
            open(backend, &key, &other_iv, &aad, &sealed),
            Err(NotAuthentic)
        );
        let mut other_key = key.clone();
        other_key[0] ^= 1;
        assert_eq!(
            open(backend, &other_key, &iv, &aad, &sealed),
            Err(NotAuthentic)
        );

        // Cut short anywhere, down to less than a tag, it does not open either.
        for len in 0..sealed.len() {
            assert_eq!(
                open(backend, &key, &iv, &aad, &sealed[..len]),
                Err(NotAuthentic),
                "{len} bytes"
            );
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn length_limits() {
        // 2^36 - 32 bytes of text is the most a nonce allows, and the
        // associated data stops at 2^61 - 1 bytes.
        assert!(lengths_fit(0, (1 << 36) - 32));
        assert!(!lengths_fit(0, (1 << 36) - 31));
        assert!(lengths_fit((1 << 61) - 1, 0));
        assert!(!lengths_fit(1 << 61, 0));
    }

    /// Which AES backend the crate's AES runs on this machine, for the label
    /// only; `crate::aes` makes the choice.
    fn aes_backend() -> &'static str {
        #[cfg(target_arch = "aarch64")]
        if cfg!(target_feature = "aes") || std::arch::is_aarch64_feature_detected!("aes") {
            return "FEAT_AES";
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("aes") {
            return "AES-NI";
        }
        "scalar"
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release gcm:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        // 64 MiB in 64 KiB messages, as the throughput test of `hpke` seals
        // and opens them: GHASH alone on each backend, AES-128 in counter mode
        // alone, and AES-128-GCM sealing and opening on each backend. A warm-up
        // pass, then the best of five.
        const LEN: usize = 64 * 1024 * 1024;
        const MESSAGE_LEN: usize = 64 * 1024;
        let mib = LEN as f64 / (1024.0 * 1024.0);
        let mut data: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let nonce = [0x24; 12];

        fn best(mib: f64, mut pass: impl FnMut()) -> f64 {
            pass();
            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass();
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            best
        }

        let aes = aes_backend();
        let ctr = {
            let gcm = Gcm::<Aes128>::new(&[0x42; 16]);
            best(mib, || {
                for message in data.chunks_mut(MESSAGE_LEN) {
                    let mut counter = Counter::new(&nonce);
                    for chunk in message.chunks_mut(CHUNK) {
                        counter.apply(&gcm.cipher, chunk);
                    }
                }
                black_box(&data);
            })
        };
        println!(
            "gcm aes-128-ctr alone [AES: {aes}]: {mib:.0} MiB in 64 KiB messages, best {ctr:.1} MiB/s"
        );

        for backend in Backend::available() {
            let gcm = Gcm::<Aes128>::with_backend(&[0x42; 16], backend);
            let name = backend.name();
            let ghash = best(mib, || {
                for message in data.chunks(MESSAGE_LEN) {
                    let mut ghash = Ghash::new(&gcm.key);
                    ghash.update(message);
                    black_box(ghash.finish(0, message.len()));
                }
            });
            let mut sealed = Vec::new();
            let seal = best(mib, || {
                sealed.clear();
                for message in data.chunks(MESSAGE_LEN) {
                    sealed.push(gcm.seal(&nonce, b"", message).unwrap());
                }
            });
            let open = best(mib, || {
                for ciphertext in &sealed {
                    black_box(gcm.open(&nonce, b"", ciphertext).unwrap());
                }
            });
            println!(
                "gcm ghash alone [{name}]: {mib:.0} MiB in 64 KiB messages, best {ghash:.1} MiB/s"
            );
            println!(
                "gcm aes-128-gcm seal [{name}, AES: {aes}]: {mib:.0} MiB in 64 KiB messages, best {seal:.1} MiB/s"
            );
            println!(
                "gcm aes-128-gcm open [{name}, AES: {aes}]: {mib:.0} MiB in 64 KiB messages, best {open:.1} MiB/s"
            );
        }
    }
}
