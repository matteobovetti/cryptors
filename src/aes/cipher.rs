use core::fmt;

use super::schedule::Schedule;
use crate::BlockCipher;

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_hw_aes() -> bool {
    // On targets where `aes` is part of the baseline the first half is
    // true at compile time, so the runtime check is skipped entirely. Rust
    // reports `aes` only where FEAT_PMULL is present too.
    cfg!(target_feature = "aes") || std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_hw_aes() -> bool {
    std::arch::is_x86_feature_detected!("aes")
}

/// Expands `key` into the round keys of both directions, picking the fastest
/// backend the CPU supports.
///
/// We check which backend to use once per call, as the hashes do. For AES that
/// means once per block as well as once per key, because the cipher is called a
/// block at a time; the check is a load and a branch, and where the instructions
/// are part of the target's baseline it is not even that.
#[inline]
fn expand_key<const K: usize, const N: usize>(key: &[u8; K]) -> Schedule<N> {
    #[cfg(target_arch = "aarch64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::aarch64::expand_key(key) };
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::x86::expand_key(key) };
    }

    super::scalar::expand_key(key)
}

/// Encrypts one block with the round keys of `schedule`, on the fastest backend
/// the CPU supports.
#[inline]
fn encrypt<const N: usize>(schedule: &Schedule<N>, block: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "aarch64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::aarch64::encrypt(&schedule.enc, block) };
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::x86::encrypt(&schedule.enc, block) };
    }

    super::scalar::encrypt(&schedule.enc, block)
}

/// Decrypts one block with the round keys of `schedule`, on the fastest backend
/// the CPU supports.
#[inline]
fn decrypt<const N: usize>(schedule: &Schedule<N>, block: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "aarch64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::aarch64::decrypt(&schedule.dec, block) };
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_aes() {
        // SAFETY: has_hw_aes() just confirmed the `aes` feature is available.
        return unsafe { super::x86::decrypt(&schedule.dec, block) };
    }

    super::scalar::decrypt(&schedule.dec, block)
}

/// Defines one of the three AES types: they differ only in the key size and
/// so in how many round keys the schedule holds.
macro_rules! aes {
    (
        $(#[$meta:meta])*
        $name:ident, key = $key_len:literal, round_keys = $round_keys:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            schedule: Schedule<$round_keys>,
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = 16;
            const KEY_LEN: usize = $key_len;
            type Key = [u8; $key_len];
            type Block = [u8; 16];

            /// Builds the cipher, expanding `key` into the round keys of
            /// both directions.
            fn new(key: &[u8; $key_len]) -> Self {
                Self { schedule: expand_key(key) }
            }

            /// Encrypts one 16-byte block (`Cipher()` in FIPS 197).
            fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                encrypt(&self.schedule, block)
            }

            /// Decrypts one 16-byte block (`InvCipher()` in FIPS 197).
            fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
                decrypt(&self.schedule, block)
            }
        }

        /// Shows the type and nothing else: the round keys are secret.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

aes! {
    /// AES with a 128-bit key (FIPS 197): ten rounds.
    ///
    /// Holds the expanded key, which is overwritten with zeros when the value
    /// is dropped.
    ///
    /// ```
    /// use cryptors::{BlockCipher, aes::Aes128};
    ///
    /// // The FIPS 197 example for a 128-bit key.
    /// let key: [u8; 16] = std::array::from_fn(|i| i as u8);
    /// let plaintext: [u8; 16] = std::array::from_fn(|i| 0x11 * i as u8);
    ///
    /// let cipher = Aes128::new(&key);
    /// let ciphertext = cipher.encrypt_block(&plaintext);
    /// assert_eq!(
    ///     ciphertext,
    ///     [
    ///         0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    ///         0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    ///     ]
    /// );
    /// assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);
    /// ```
    Aes128, key = 16, round_keys = 11
}

aes! {
    /// AES with a 192-bit key (FIPS 197): twelve rounds.
    ///
    /// Holds the expanded key, which is overwritten with zeros when the value
    /// is dropped.
    ///
    /// ```
    /// use cryptors::{BlockCipher, aes::Aes192};
    ///
    /// // The FIPS 197 example for a 192-bit key.
    /// let key: [u8; 24] = std::array::from_fn(|i| i as u8);
    /// let plaintext: [u8; 16] = std::array::from_fn(|i| 0x11 * i as u8);
    ///
    /// let cipher = Aes192::new(&key);
    /// let ciphertext = cipher.encrypt_block(&plaintext);
    /// assert_eq!(
    ///     ciphertext,
    ///     [
    ///         0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
    ///         0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    ///     ]
    /// );
    /// assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);
    /// ```
    Aes192, key = 24, round_keys = 13
}

aes! {
    /// AES with a 256-bit key (FIPS 197): fourteen rounds.
    ///
    /// Holds the expanded key, which is overwritten with zeros when the value
    /// is dropped.
    ///
    /// ```
    /// use cryptors::{BlockCipher, aes::Aes256};
    ///
    /// // The FIPS 197 example for a 256-bit key.
    /// let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    /// let plaintext: [u8; 16] = std::array::from_fn(|i| 0x11 * i as u8);
    ///
    /// let cipher = Aes256::new(&key);
    /// let ciphertext = cipher.encrypt_block(&plaintext);
    /// assert_eq!(
    ///     ciphertext,
    ///     [
    ///         0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    ///         0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ///     ]
    /// );
    /// assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);
    /// ```
    Aes256, key = 32, round_keys = 15
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::aes::scalar;
    use crate::digest::hex;
    use crate::sha2::Sha256;

    /// The round keys of one key, whichever of the three sizes it has.
    enum Keys {
        Aes128(Schedule<11>),
        Aes192(Schedule<13>),
        Aes256(Schedule<15>),
    }

    impl Keys {
        /// The round keys of encryption.
        fn enc(&self) -> &[[u8; 16]] {
            match self {
                Keys::Aes128(s) => &s.enc,
                Keys::Aes192(s) => &s.enc,
                Keys::Aes256(s) => &s.enc,
            }
        }

        /// The round keys of decryption.
        fn dec(&self) -> &[[u8; 16]] {
            match self {
                Keys::Aes128(s) => &s.dec,
                Keys::Aes192(s) => &s.dec,
                Keys::Aes256(s) => &s.dec,
            }
        }
    }

    /// One backend, callable like `scalar`.
    ///
    /// The hardware backends are `unsafe` to call because they need a CPU
    /// feature. A hardware variant is only ever made by `backends()`, after
    /// has_hw_aes() has confirmed that feature, so every method below may call
    /// into it.
    #[derive(Clone, Copy)]
    enum Backend {
        Scalar,
        #[cfg(target_arch = "aarch64")]
        Aarch64,
        #[cfg(target_arch = "x86_64")]
        X86,
    }

    impl Backend {
        fn name(self) -> &'static str {
            match self {
                Backend::Scalar => "scalar",
                #[cfg(target_arch = "aarch64")]
                Backend::Aarch64 => "aarch64 (FEAT_AES)",
                #[cfg(target_arch = "x86_64")]
                Backend::X86 => "x86_64 (AES-NI)",
            }
        }

        fn expand_n<const K: usize, const N: usize>(self, key: &[u8; K]) -> Schedule<N> {
            match self {
                Backend::Scalar => scalar::expand_key(key),
                // SAFETY: see the comment on `Backend`.
                #[cfg(target_arch = "aarch64")]
                Backend::Aarch64 => unsafe { crate::aes::aarch64::expand_key(key) },
                // SAFETY: see the comment on `Backend`.
                #[cfg(target_arch = "x86_64")]
                Backend::X86 => unsafe { crate::aes::x86::expand_key(key) },
            }
        }

        /// Encrypts every block of `blocks` in place. The backend is chosen
        /// once, outside the loop, as the public functions' loop does.
        fn encrypt_n<const N: usize>(self, keys: &[[u8; 16]; N], blocks: &mut [[u8; 16]]) {
            match self {
                Backend::Scalar => {
                    for block in blocks {
                        *block = scalar::encrypt(keys, block);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                Backend::Aarch64 => {
                    for block in blocks {
                        // SAFETY: see the comment on `Backend`.
                        *block = unsafe { crate::aes::aarch64::encrypt(keys, block) };
                    }
                }
                #[cfg(target_arch = "x86_64")]
                Backend::X86 => {
                    for block in blocks {
                        // SAFETY: see the comment on `Backend`.
                        *block = unsafe { crate::aes::x86::encrypt(keys, block) };
                    }
                }
            }
        }

        /// Decrypts every block of `blocks` in place; `keys` are the round
        /// keys of decryption.
        fn decrypt_n<const N: usize>(self, keys: &[[u8; 16]; N], blocks: &mut [[u8; 16]]) {
            match self {
                Backend::Scalar => {
                    for block in blocks {
                        *block = scalar::decrypt(keys, block);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                Backend::Aarch64 => {
                    for block in blocks {
                        // SAFETY: see the comment on `Backend`.
                        *block = unsafe { crate::aes::aarch64::decrypt(keys, block) };
                    }
                }
                #[cfg(target_arch = "x86_64")]
                Backend::X86 => {
                    for block in blocks {
                        // SAFETY: see the comment on `Backend`.
                        *block = unsafe { crate::aes::x86::decrypt(keys, block) };
                    }
                }
            }
        }

        /// Expands a key of 16, 24 or 32 bytes.
        fn expand(self, key: &[u8]) -> Keys {
            match key.len() {
                16 => Keys::Aes128(self.expand_n::<16, 11>(key.try_into().unwrap())),
                24 => Keys::Aes192(self.expand_n::<24, 13>(key.try_into().unwrap())),
                32 => Keys::Aes256(self.expand_n::<32, 15>(key.try_into().unwrap())),
                n => panic!("no AES key has {n} bytes"),
            }
        }

        fn encrypt(self, keys: &Keys, blocks: &mut [[u8; 16]]) {
            match keys {
                Keys::Aes128(s) => self.encrypt_n(&s.enc, blocks),
                Keys::Aes192(s) => self.encrypt_n(&s.enc, blocks),
                Keys::Aes256(s) => self.encrypt_n(&s.enc, blocks),
            }
        }

        fn decrypt(self, keys: &Keys, blocks: &mut [[u8; 16]]) {
            match keys {
                Keys::Aes128(s) => self.decrypt_n(&s.dec, blocks),
                Keys::Aes192(s) => self.decrypt_n(&s.dec, blocks),
                Keys::Aes256(s) => self.decrypt_n(&s.dec, blocks),
            }
        }
    }

    /// Every backend this CPU can run, in the order the public functions
    /// prefer them: the first entry is the one they use, and the last is
    /// always `scalar`.
    fn backends() -> Vec<Backend> {
        let mut list = Vec::new();

        #[cfg(target_arch = "aarch64")]
        if has_hw_aes() {
            list.push(Backend::Aarch64);
        }

        #[cfg(target_arch = "x86_64")]
        if has_hw_aes() {
            list.push(Backend::X86);
        }

        list.push(Backend::Scalar);
        list
    }

    /// Which backend the public functions pick on this machine.
    fn active_backend() -> Backend {
        backends()[0]
    }

    /// What to run a vector through: the public types, as a user calls them,
    /// or one backend called directly.
    #[derive(Clone, Copy)]
    enum Engine {
        Public,
        Direct(Backend),
    }

    /// Encrypts `blocks` in place with the public type `C`, building the
    /// cipher once.
    fn encrypt_with<C: BlockCipher<Block = [u8; 16]>>(key: &C::Key, blocks: &mut [[u8; 16]]) {
        let cipher = C::new(key);
        for block in blocks {
            *block = cipher.encrypt_block(block);
        }
    }

    /// Decrypts `blocks` in place with the public type `C`.
    fn decrypt_with<C: BlockCipher<Block = [u8; 16]>>(key: &C::Key, blocks: &mut [[u8; 16]]) {
        let cipher = C::new(key);
        for block in blocks {
            *block = cipher.decrypt_block(block);
        }
    }

    impl Engine {
        /// Encrypts every block of `blocks` in place under `key` (16, 24 or 32
        /// bytes).
        fn encrypt(self, key: &[u8], blocks: &mut [[u8; 16]]) {
            match self {
                Engine::Public => match key.len() {
                    16 => encrypt_with::<Aes128>(key.try_into().unwrap(), blocks),
                    24 => encrypt_with::<Aes192>(key.try_into().unwrap(), blocks),
                    32 => encrypt_with::<Aes256>(key.try_into().unwrap(), blocks),
                    n => panic!("no AES key has {n} bytes"),
                },
                Engine::Direct(backend) => backend.encrypt(&backend.expand(key), blocks),
            }
        }

        fn decrypt(self, key: &[u8], blocks: &mut [[u8; 16]]) {
            match self {
                Engine::Public => match key.len() {
                    16 => decrypt_with::<Aes128>(key.try_into().unwrap(), blocks),
                    24 => decrypt_with::<Aes192>(key.try_into().unwrap(), blocks),
                    32 => decrypt_with::<Aes256>(key.try_into().unwrap(), blocks),
                    n => panic!("no AES key has {n} bytes"),
                },
                Engine::Direct(backend) => backend.decrypt(&backend.expand(key), blocks),
            }
        }

        fn encrypt_one(self, key: &[u8], block: &[u8; 16]) -> [u8; 16] {
            let mut blocks = [*block];
            self.encrypt(key, &mut blocks);
            blocks[0]
        }

        fn decrypt_one(self, key: &[u8], block: &[u8; 16]) -> [u8; 16] {
            let mut blocks = [*block];
            self.decrypt(key, &mut blocks);
            blocks[0]
        }
    }

    /// `len` bytes derived from `label` and `i`: the start of
    /// SHA-256(`label` || `i` as four big-endian bytes). Simple enough to
    /// reproduce in any language, which is how the expected values below were
    /// made.
    fn derive(label: &[u8], i: u32, len: usize) -> Vec<u8> {
        let mut input = label.to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        Sha256::digest(&input)[..len].to_vec()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn block(s: &str) -> [u8; 16] {
        unhex(s).try_into().unwrap()
    }

    /// FIPS 197 Appendix B, and the three examples that NIST publishes for it,
    /// one per key size (Appendix C of the 2001 edition, since moved to NIST's
    /// website): (key, plaintext, ciphertext).
    const FIPS_197: [(&str, &str, &str); 4] = [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ];

    /// The four plaintext blocks of NIST SP 800-38A section F.1, shared by the
    /// three key sizes.
    const SP_800_38A_PLAINTEXT: [&str; 4] = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ];

    /// SP 800-38A F.1.1, F.1.3 and F.1.5, the ECB examples: (key, the four
    /// ciphertext blocks).
    const SP_800_38A_ECB: [(&str, [&str; 4]); 3] = [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            [
                "3ad77bb40d7a3660a89ecaf32466ef97",
                "f5d3d58503b9699de785895a96fdbaaf",
                "43b1cd7f598ece23881b00e3ed030688",
                "7b0c785e27e8ad3f8223207104725dd4",
            ],
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            [
                "bd334f1d6e45f25ff712a214571fa5cc",
                "974104846d0ad3ad7734ecb3ecee4eef",
                "ef7afd2270e2e60adce0ba2face6444e",
                "9a4b41ba738d6c72fb16691603c18e0e",
            ],
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            [
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
                "591ccb10d410ed26dc5ba74a31362870",
                "b6ed21b99ca6f4f9f153e7b1beafed1d",
                "23304b7a39f9f3ff067d8d8f9e24ecc7",
            ],
        ),
    ];

    /// Encrypting the plaintext of the FIPS 197 examples a thousand times in a
    /// row, each time on the previous ciphertext, under the key `00 01 02 ...`:
    /// (key length, ciphertext), from two independent implementations, which
    /// agree.
    const CHAINED: [(usize, &str); 3] = [
        (16, "b7449c8da15defeb78dbc57ea81db8ee"),
        (24, "d9d92fb5411433bd28973fc2fc543556"),
        (32, "fbe6e70f40a246e81b19eee74949123c"),
    ];

    /// SHA-256 of the 1000 ciphertexts of `block(i)` under `key(i)`, for
    /// `key(i) = derive("key", i)` and `block(i) = derive("block", i)`:
    /// (key length, digest), from the same two implementations.
    const MANY_KEYS: [(usize, &str); 3] = [
        (
            16,
            "bfd4446ec9236c482cedad070c830e065427c98c693a8ac0dd6d7156a4bd84b9",
        ),
        (
            24,
            "a478a7152d94d8b7961dfde99ebd7cd7b9340c9f794dd5db03e2f46354146ab2",
        ),
        (
            32,
            "8e01ec0254c367c824502acb58f487a262b9c37c991c90f4824fca074bd797d6",
        ),
    ];

    /// Checks `engine` against the vectors the standards publish, in both
    /// directions.
    fn assert_published(engine: Engine) {
        for (key, plaintext, ciphertext) in FIPS_197 {
            let (key, plaintext, ciphertext) = (unhex(key), block(plaintext), block(ciphertext));
            let what = format!("FIPS 197, {}-bit key", key.len() * 8);
            assert_eq!(engine.encrypt_one(&key, &plaintext), ciphertext, "{what}");
            assert_eq!(engine.decrypt_one(&key, &ciphertext), plaintext, "{what}");
        }
        for (key, ciphertexts) in SP_800_38A_ECB {
            let key = unhex(key);
            for (plaintext, ciphertext) in SP_800_38A_PLAINTEXT.into_iter().zip(ciphertexts) {
                let (plaintext, ciphertext) = (block(plaintext), block(ciphertext));
                let what = format!(
                    "SP 800-38A, {}-bit key, block {plaintext:02x?}",
                    key.len() * 8
                );
                assert_eq!(engine.encrypt_one(&key, &plaintext), ciphertext, "{what}");
                assert_eq!(engine.decrypt_one(&key, &ciphertext), plaintext, "{what}");
            }
        }
    }

    /// Checks `engine` against `CHAINED`, and checks that decrypting the same
    /// number of times leads back to the start.
    fn assert_chained(engine: Engine) {
        let start = block("00112233445566778899aabbccddeeff");
        for (key_len, expected) in CHAINED {
            let key: Vec<u8> = (0..key_len as u8).collect();

            let mut state = start;
            for _ in 0..1000 {
                state = engine.encrypt_one(&key, &state);
            }
            assert_eq!(hex(&state), expected, "{}-bit key", key_len * 8);

            for _ in 0..1000 {
                state = engine.decrypt_one(&key, &state);
            }
            assert_eq!(state, start, "{}-bit key, decrypting back", key_len * 8);
        }
    }

    /// Checks `engine` against `MANY_KEYS`, and checks that every ciphertext
    /// decrypts back to its block.
    fn assert_many_keys(engine: Engine) {
        for (key_len, expected) in MANY_KEYS {
            let mut ciphertexts = Vec::new();
            for i in 0..1000 {
                let key = derive(b"key", i, key_len);
                let plaintext: [u8; 16] = derive(b"block", i, 16).try_into().unwrap();
                let ciphertext = engine.encrypt_one(&key, &plaintext);
                assert_eq!(
                    engine.decrypt_one(&key, &ciphertext),
                    plaintext,
                    "{}-bit key, i = {i}, decrypting back",
                    key_len * 8
                );
                ciphertexts.extend_from_slice(&ciphertext);
            }
            assert_eq!(
                hex(&Sha256::digest(&ciphertexts)),
                expected,
                "{}-bit keys",
                key_len * 8
            );
        }
    }

    #[test]
    fn known_answers() {
        assert_published(Engine::Public);
    }

    #[test]
    fn chained() {
        // The only known-answer input long enough to carry a mistake in one
        // table entry through many blocks: 1000 encryptions per key size, each
        // on the previous one's output.
        assert_chained(Engine::Public);
    }

    #[test]
    fn many_keys() {
        // A thousand different keys per size, which is what exercises the key
        // schedule: the published vectors only have a handful.
        assert_many_keys(Engine::Public);
    }

    /// Checks all the known answers against the scalar backend.
    ///
    /// The public functions skip `scalar` on a machine with hardware AES.
    /// Without this, the scalar backend would never actually get checked on
    /// such a machine.
    #[test]
    fn scalar_known_answers() {
        let scalar = Engine::Direct(Backend::Scalar);
        assert_published(scalar);
        assert_chained(scalar);
        assert_many_keys(scalar);
    }

    /// Checks that every other backend this CPU can run produces exactly the
    /// same round keys and the same blocks as the scalar backend.
    ///
    /// This calls each backend directly instead of going through the public
    /// types, so the test can't accidentally end up comparing the scalar
    /// backend against itself. Backends the CPU doesn't support are not in
    /// `backends()`, so their part of the test is just skipped.
    #[test]
    fn matches_scalar_backend() {
        let others: Vec<_> = backends()
            .into_iter()
            .filter(|backend| !matches!(backend, Backend::Scalar))
            .collect();

        for backend in &others {
            for key_len in [16, 24, 32] {
                for i in 0..256 {
                    let key = derive(b"differential key", i, key_len);
                    let input: [u8; 16] = derive(b"differential block", i, 16).try_into().unwrap();
                    let what = format!("{}, {}-bit key, i = {i}", backend.name(), key_len * 8);

                    let (ours, reference) = (backend.expand(&key), Backend::Scalar.expand(&key));
                    assert_eq!(ours.enc(), reference.enc(), "encryption round keys, {what}");
                    assert_eq!(ours.dec(), reference.dec(), "decryption round keys, {what}");

                    // Any block will do for either direction: both are
                    // permutations, and the scalar backend defines the answer.
                    let (mut a, mut b) = ([input], [input]);
                    backend.encrypt(&ours, &mut a);
                    Backend::Scalar.encrypt(&reference, &mut b);
                    assert_eq!(a, b, "encrypting, {what}");

                    let (mut a, mut b) = ([input], [input]);
                    backend.decrypt(&ours, &mut a);
                    Backend::Scalar.decrypt(&reference, &mut b);
                    assert_eq!(a, b, "decrypting, {what}");
                }
            }
            println!("{} backend matches scalar", backend.name());
        }

        if others.is_empty() {
            println!("no hardware AES backend on this CPU; only the scalar path is in use");
        }
    }

    /// Checks that the result does not depend on where in memory the block and
    /// the round keys sit. The hardware backends read them with unaligned
    /// vector loads, and that is only correct if they never assume an
    /// alignment. Every backend is checked, not just the one the public
    /// functions pick.
    #[test]
    fn unaligned_input() {
        fn check<const K: usize, const N: usize>(backend: Backend) {
            let key: [u8; K] = derive(b"unaligned key", 0, K).try_into().unwrap();
            let input: [u8; 16] = derive(b"unaligned block", 0, 16).try_into().unwrap();
            let keys: Schedule<N> = Backend::Scalar.expand_n(&key);

            let mut want_enc = [input];
            Backend::Scalar.encrypt_n(&keys.enc, &mut want_enc);
            let mut want_dec = [input];
            Backend::Scalar.decrypt_n(&keys.dec, &mut want_dec);

            // The round keys and the block, copied to start at every offset in
            // the first 16 bytes of a buffer.
            for offset in 0..16 {
                let mut enc = vec![0u8; offset + 16 * N];
                let mut dec = vec![0u8; offset + 16 * N];
                for (i, round_key) in keys.enc.iter().enumerate() {
                    enc[offset + 16 * i..][..16].copy_from_slice(round_key);
                }
                for (i, round_key) in keys.dec.iter().enumerate() {
                    dec[offset + 16 * i..][..16].copy_from_slice(round_key);
                }
                let enc: &[[u8; 16]; N] = enc[offset..].as_chunks::<16>().0.try_into().unwrap();
                let dec: &[[u8; 16]; N] = dec[offset..].as_chunks::<16>().0.try_into().unwrap();

                let mut data = vec![0u8; offset + 16];
                data[offset..].copy_from_slice(&input);
                let blocks = &mut data[offset..].as_chunks_mut::<16>().0;
                backend.encrypt_n(enc, blocks);
                assert_eq!(
                    *blocks,
                    want_enc,
                    "{}, {K}-byte key, offset = {offset}",
                    backend.name()
                );

                data[offset..].copy_from_slice(&input);
                let blocks = &mut data[offset..].as_chunks_mut::<16>().0;
                backend.decrypt_n(dec, blocks);
                assert_eq!(
                    *blocks,
                    want_dec,
                    "{}, {K}-byte key, offset = {offset}",
                    backend.name()
                );
            }
        }

        for backend in backends() {
            check::<16, 11>(backend);
            check::<24, 13>(backend);
            check::<32, 15>(backend);
        }
    }

    /// Dropping a schedule must leave no round key behind.
    #[test]
    fn dropping_wipes_the_round_keys() {
        use core::mem::{MaybeUninit, size_of};

        let mut slot = MaybeUninit::new(scalar::expand_key::<16, 11>(&[0x42; 16]));
        // One raw pointer does the dropping and the reading, so that the drop
        // does not invalidate the pointer the reads go through.
        let schedule = slot.as_mut_ptr();
        let bytes = schedule.cast::<u8>();
        // A schedule is nothing but bytes (both fields have alignment 1), so
        // reading it as `size_of` bytes reads every one of them.
        let read = || -> Vec<u8> {
            (0..size_of::<Schedule<11>>())
                // SAFETY: the slot is alive and every byte of it was written,
                // first by `expand_key` and then, if the drop works, by `wipe`.
                .map(|i| unsafe { bytes.add(i).read() })
                .collect()
        };
        assert!(read().iter().any(|&b| b != 0), "no round keys to wipe");

        // SAFETY: the slot holds an initialised schedule, dropped only here.
        unsafe { schedule.drop_in_place() };
        assert!(
            read().iter().all(|&b| b == 0),
            "round keys survive the drop"
        );
    }

    /// The Debug output must not show the round keys.
    #[test]
    fn debug_hides_the_key() {
        let cipher = Aes128::new(&[0xab; 16]);
        assert_eq!(format!("{cipher:?}"), "Aes128 { .. }");
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release aes -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        const LEN: usize = 64 * 1024 * 1024;
        let mib = LEN as f64 / (1024.0 * 1024.0);

        // A fixed input: block `i` starts the byte pattern at `16 * i`. The
        // data is transformed in place and the passes are not undone, so what
        // is printed at the end identifies the whole run. It is the same for
        // every backend, and for any other correct implementation run the same
        // way.
        let pattern: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();

        /// Runs `pass` over a fresh copy of the pattern: once to warm up, then
        /// five times, keeping the best rate.
        fn time(
            label: &str,
            backend: &str,
            pattern: &[u8],
            mib: f64,
            mut pass: impl FnMut(&mut [[u8; 16]]),
        ) {
            // The first pass over a fresh buffer is slowed down by page faults
            // and CPU clock ramp-up, not just AES itself, so it is not timed.
            let mut data = pattern.to_vec();
            let blocks = data.as_chunks_mut::<16>().0;
            pass(blocks);

            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass(blocks);
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "{label} [{backend}]: {mib:.0} MiB, best {best:.1} MiB/s (first block {}...)",
                hex(&blocks[0][..8])
            );
        }

        // Exactly the public API's path: the dispatcher picks the backend.
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            let bits = key_len * 8;
            let backend = active_backend().name();
            time(
                &format!("aes{bits} encrypt"),
                backend,
                &pattern,
                mib,
                |blocks| Engine::Public.encrypt(&key, blocks),
            );
            time(
                &format!("aes{bits} decrypt"),
                backend,
                &pattern,
                mib,
                |blocks| Engine::Public.decrypt(&key, blocks),
            );
        }

        // Then every backend the dispatcher passed over, down to scalar, so
        // that one run on a machine with the fastest instructions also
        // measures the paths other CPUs would take.
        for backend in backends().into_iter().skip(1) {
            for key_len in [16, 24, 32] {
                let key: Vec<u8> = (0..key_len as u8).collect();
                let bits = key_len * 8;
                let keys = backend.expand(&key);
                time(
                    &format!("aes{bits} encrypt"),
                    backend.name(),
                    &pattern,
                    mib,
                    |blocks| backend.encrypt(&keys, blocks),
                );
                time(
                    &format!("aes{bits} decrypt"),
                    backend.name(),
                    &pattern,
                    mib,
                    |blocks| backend.decrypt(&keys, blocks),
                );
            }
        }
    }
}
