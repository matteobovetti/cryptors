use core::fmt;

use super::hmac::Keyed;
use crate::Digest;

/// Expand numbers its blocks with a one-byte counter (RFC 5869 section 2.3),
/// so there are at most this many of them.
const MAX_BLOCKS: usize = 255;

/// HKDF-Extract (RFC 5869 section 2.2): the PRK `HMAC(salt, ikm)`.
fn extract_prk<D: Digest>(salt: &[u8], ikm: &[u8]) -> D::Output {
    Keyed::<D>::new(salt).mac_parts(&[ikm])
}

/// HKDF (RFC 5869) over the hash `D`: a pseudorandom key (PRK), ready to be
/// expanded into as many keys as are needed.
///
/// Build one with [`extract`](Self::extract), from a secret and a salt, or with
/// [`from_prk`](Self::from_prk), from a key that is already pseudorandom. Then
/// call [`expand`](Self::expand) once for each key, with its own `info`.
/// [`derive`](Self::derive) does both steps in one call.
///
/// Holds the PRK as a key of HMAC, ready for every block of every Expand. It is
/// overwritten with zeros when the value is dropped, and `Debug` does not show
/// it.
///
/// ```
/// use cryptors::{Digest, hkdf::Hkdf, sha1::Sha1, sha2::{Sha256, Sha512}};
///
/// // RFC 5869, Appendix A.6: SHA-1, with neither salt nor info.
/// let hkdf = Hkdf::<Sha1>::extract(&[], &[0x0b; 22]);
/// let mut okm = [0; 42];
/// hkdf.expand(&[], &mut okm)?;
/// assert_eq!(okm[..8], [0x0a, 0xc1, 0xaf, 0x70, 0x02, 0xb3, 0xd7, 0x61]);
///
/// // Code can be generic over the hash, as `Hkdf` itself is.
/// fn session_key<D: Digest>(secret: &[u8]) -> [u8; 32] {
///     let mut key = [0; 32];
///     Hkdf::<D>::derive(b"salt", secret, b"session key", &mut key)
///         .expect("every hash gives at least 32 bytes");
///     key
/// }
/// assert_ne!(session_key::<Sha256>(b"secret"), session_key::<Sha512>(b"secret"));
/// # Ok::<(), cryptors::hkdf::Error>(())
/// ```
pub struct Hkdf<D: Digest> {
    /// HMAC under the PRK: every block of output is one HMAC with this key.
    prk: Keyed<D>,
}

impl<D: Digest> Hkdf<D> {
    /// The longest output one PRK gives: 255 blocks of the hash's output, so
    /// 8160 bytes for SHA-256 and 16320 for SHA-512.
    pub const MAX_OUTPUT_LEN: usize = MAX_BLOCKS * D::OUTPUT_LEN;

    /// HKDF-Extract (RFC 5869 section 2.2): makes the PRK `HMAC(salt, ikm)`, of
    /// one hash output, and keeps it for [`expand`](Self::expand).
    ///
    /// `ikm` is the secret input keying material. `salt` need not be secret,
    /// and may be empty: no salt is HashLen zero bytes (section 2.2), and an
    /// empty one is the same key to HMAC, which pads its key with zeros.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        Self {
            prk: Keyed::new(extract_prk::<D>(salt, ikm).as_ref()),
        }
    }

    /// Starts from a PRK the caller already has, skipping Extract (RFC 5869
    /// section 3.3).
    ///
    /// `prk` must be uniformly random or pseudorandom already, such as the
    /// output of an earlier Expand, and at least one hash output long (section
    /// 2.3). A shorter one is [`Error::InvalidPrkLength`]. A Diffie-Hellman
    /// shared secret is not pseudorandom: give that to [`extract`](Self::extract).
    ///
    /// ```
    /// use cryptors::{hkdf::{Error, Hkdf}, sha2::Sha256};
    ///
    /// // The PRK of RFC 5869, Appendix A.3.
    /// let prk = [
    ///     0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
    ///     0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04,
    /// ];
    /// let mut okm = [0; 42];
    /// Hkdf::<Sha256>::from_prk(&prk)?.expand(&[], &mut okm)?;
    /// assert_eq!(okm[..4], [0x8d, 0xa4, 0xe7, 0x75]);
    ///
    /// // 31 bytes are too short to be a SHA-256 PRK.
    /// assert!(matches!(Hkdf::<Sha256>::from_prk(&prk[..31]), Err(Error::InvalidPrkLength)));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_prk(prk: &[u8]) -> Result<Self, Error> {
        if prk.len() < D::OUTPUT_LEN {
            return Err(Error::InvalidPrkLength);
        }
        Ok(Self {
            prk: Keyed::new(prk),
        })
    }

    /// HKDF-Expand (RFC 5869 section 2.3): fills `okm` with output keying
    /// material for `info`.
    ///
    /// `info` says what the output is for, and may be empty. `okm` may be of
    /// any length up to [`MAX_OUTPUT_LEN`](Self::MAX_OUTPUT_LEN), including
    /// zero. A longer one is [`Error::InvalidLength`], and is left as it was.
    ///
    /// The same PRK and `info` always give the same bytes, and a shorter `okm`
    /// gets the start of what a longer one would. Tell keys apart by their
    /// `info`, not by their length.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
        // `chunks_mut` needs blocks of at least one byte. Every hash in the
        // crate has them, and one that did not would be stopped here at
        // compile time.
        const { assert!(D::OUTPUT_LEN > 0, "HKDF needs a hash with an output") };
        if okm.len() > Self::MAX_OUTPUT_LEN {
            return Err(Error::InvalidLength);
        }

        // T(i) = HMAC(PRK, T(i - 1) | info | i), with T(0) empty. Each block
        // goes straight into `okm`, and the next one reads it back from there,
        // so there is no copy of it to wipe. The last block may be cut short.
        let mut previous: &[u8] = &[];
        for (block, counter) in okm.chunks_mut(D::OUTPUT_LEN).zip(1..=u8::MAX) {
            let t = self.prk.mac_parts(&[previous, info, &[counter]]);
            block.copy_from_slice(&t.as_ref()[..block.len()]);
            previous = block;
        }
        Ok(())
    }

    /// HKDF (RFC 5869 section 2): [`extract`](Self::extract) then
    /// [`expand`](Self::expand), into `okm`.
    ///
    /// Fails as `expand` does: an `okm` longer than
    /// [`MAX_OUTPUT_LEN`](Self::MAX_OUTPUT_LEN) is [`Error::InvalidLength`],
    /// and is left as it was.
    ///
    /// ```
    /// use cryptors::{hkdf::Hkdf, sha1::Sha1};
    ///
    /// // RFC 5869, Appendix A.7: SHA-1, no salt and no info.
    /// let mut okm = [0; 42];
    /// Hkdf::<Sha1>::derive(&[], &[0x0c; 22], &[], &mut okm)?;
    /// assert_eq!(okm[..8], [0x2c, 0x91, 0x11, 0x72, 0x04, 0xd7, 0x45, 0xf3]);
    /// # Ok::<(), cryptors::hkdf::Error>(())
    /// ```
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
        Self::extract(salt, ikm).expand(info, okm)
    }
}

impl<D: Digest> Clone for Hkdf<D> {
    fn clone(&self) -> Self {
        Self {
            prk: self.prk.clone(),
        }
    }
}

/// Shows the type and nothing else: the PRK is secret.
impl<D: Digest> fmt::Debug for Hkdf<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hkdf").finish_non_exhaustive()
    }
}

/// A length that HKDF does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The output asked of [`Hkdf::expand`] or [`Hkdf::derive`] is longer than
    /// [`Hkdf::MAX_OUTPUT_LEN`], 255 outputs of the hash.
    InvalidLength,
    /// The key given to [`Hkdf::from_prk`] is shorter than one output of the
    /// hash, the shortest a PRK can be (RFC 5869 section 2.3).
    InvalidPrkLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "HKDF output longer than 255 times the hash length",
            Error::InvalidPrkLength => "HKDF pseudorandom key shorter than the hash length",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::hex;
    use crate::md5::Md5;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `len` bytes counting up from zero: the salts and PRKs of the vectors
    /// below. The salt of RFC 5869 A.1 is the first 13.
    fn counting(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    /// The IKM and info of RFC 5869 A.1, reused by the vectors from Go and
    /// OpenSSL.
    const A1_IKM: [u8; 22] = [0x0b; 22];
    const A1_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    /// A test case of RFC 5869 Appendix A, in hex.
    struct Rfc {
        name: &'static str,
        ikm: &'static str,
        salt: &'static str,
        info: &'static str,
        prk: &'static str,
        okm: &'static str,
    }

    /// RFC 5869 A.1 to A.3: SHA-256.
    const RFC_SHA256: [Rfc; 3] = [
        Rfc {
            name: "A.1",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            prk: "077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5",
            okm: "3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                  34007208d5b887185865",
        },
        Rfc {
            name: "A.2",
            ikm: "000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
                  202122232425262728292a2b2c2d2e2f 303132333435363738393a3b3c3d3e3f
                  404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f 707172737475767778797a7b7c7d7e7f
                   808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f
                   a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
                   d0d1d2d3d4d5d6d7d8d9dadbdcdddedf e0e1e2e3e4e5e6e7e8e9eaebecedeeef
                   f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            prk: "06a6b88c5853361a06104c9ceb35b45c ef760014904671014a193f40c15fc244",
            okm: "b11e398dc80327a1c8e7f78c596a4934 4f012eda2d4efad8a050cc4c19afa97c
                  59045a99cac7827271cb41c65e590e09 da3275600c2f09b8367793a9aca3db71
                  cc30c58179ec3e87c14c01d5c1f3434f 1d87",
        },
        Rfc {
            name: "A.3",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "",
            info: "",
            prk: "19ef24a32c717b167f33a91d6f648bdf 96596776afdb6377ac434c1c293ccb04",
            okm: "8da4e775a563c18f715f802a063c5a31 b8a11f5c5ee1879ec3454e5f3c738d2d
                  9d201395faa4b61a96c8",
        },
    ];

    /// RFC 5869 A.4 to A.7: SHA-1. A.7's salt is "not provided", which this
    /// API spells as an empty one.
    const RFC_SHA1: [Rfc; 4] = [
        Rfc {
            name: "A.4",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            prk: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
            okm: "085a01ea1b10f36933068b56efa5ad81 a4f14b822f5b091568a9cdd4f155fda2
                  c22e422478d305f3f896",
        },
        Rfc {
            name: "A.5",
            ikm: "000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
                  202122232425262728292a2b2c2d2e2f 303132333435363738393a3b3c3d3e3f
                  404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f 707172737475767778797a7b7c7d7e7f
                   808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f
                   a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
                   d0d1d2d3d4d5d6d7d8d9dadbdcdddedf e0e1e2e3e4e5e6e7e8e9eaebecedeeef
                   f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            prk: "8adae09a2a307059478d309b26c4115a224cfaf6",
            okm: "0bd770a74d1160f7c9f12cd5912a06eb ff6adcae899d92191fe4305673ba2ffe
                  8fa3f1a4e5ad79f3f334b3b202b2173c 486ea37ce3d397ed034c7f9dfeb15c5e
                  927336d0441f4c4300e2cff0d0900b52 d3b4",
        },
        Rfc {
            name: "A.6",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "",
            info: "",
            prk: "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
            okm: "0ac1af7002b3d761d1e55298da9d0506 b9ae52057220a306e07b6b87e8df21d0
                  ea00033de03984d34918",
        },
        Rfc {
            name: "A.7",
            ikm: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            salt: "",
            info: "",
            prk: "2adccada18779e7c2077ad2eb19d3f3e731385dd",
            okm: "2c91117204d745f3500d636a62f64f0a b3bae548aa53d423b0d1f27ebba6f5e5
                  673a081d70cce7acfc48",
        },
    ];

    /// Checks one RFC case through each way in: Extract (its PRK), Expand,
    /// `derive`, and `from_prk` with the RFC's PRK.
    fn check_rfc<D: Digest>(case: &Rfc) {
        let (ikm, salt, info) = (unhex(case.ikm), unhex(case.salt), unhex(case.info));
        let (expected_prk, expected_okm) = (unhex(case.prk), unhex(case.okm));
        let name = case.name;

        let prk = extract_prk::<D>(&salt, &ikm);
        assert_eq!(prk.as_ref(), expected_prk, "{name}: PRK");

        let hkdf = Hkdf::<D>::extract(&salt, &ikm);
        let mut okm = vec![0; expected_okm.len()];
        hkdf.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm, "{name}: extract, then expand");

        let mut okm = vec![0; expected_okm.len()];
        Hkdf::<D>::derive(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm, "{name}: derive");

        let mut okm = vec![0; expected_okm.len()];
        let from_prk = Hkdf::<D>::from_prk(&expected_prk).unwrap();
        from_prk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm, "{name}: from_prk, then expand");
    }

    #[test]
    fn rfc_5869() {
        for case in &RFC_SHA256 {
            check_rfc::<Sha256>(case);
        }
        for case in &RFC_SHA1 {
            check_rfc::<Sha1>(case);
        }
    }

    /// Checks HashLen bytes of HKDF with A.1's IKM and info, and a salt of
    /// `counting(n)` for n = HashLen (the salt RFC 5869 recommends), the hash's
    /// block length and one more: the longest key HMAC pads and the shortest
    /// one it hashes.
    fn check_salt_lengths<D: Digest>(name: &str, expected: [&str; 3]) {
        let lengths = [D::OUTPUT_LEN, D::BLOCK_LEN, D::BLOCK_LEN + 1];
        for (salt_len, expected) in lengths.into_iter().zip(expected) {
            let mut okm = vec![0; D::OUTPUT_LEN];
            Hkdf::<D>::derive(&counting(salt_len), &A1_IKM, &A1_INFO, &mut okm).unwrap();
            assert_eq!(hex(&okm), expected, "{name}, {salt_len}-byte salt");
        }
    }

    /// The RFC has vectors for SHA-256 and SHA-1 only. These cover all eight
    /// hashes, and come from Go's crypto/hkdf and OpenSSL 3.6
    /// (`openssl kdf ... HKDF`), which agree.
    #[test]
    fn salt_lengths() {
        check_salt_lengths::<Md5>(
            "MD5",
            [
                "389d886e679accd33d32ffc7b2378fe5",
                "c5283429a20ff5d2eac2d62a046de4ed",
                "ef4b651d0b88be72eb270879170cc3af",
            ],
        );
        check_salt_lengths::<Sha1>(
            "SHA-1",
            [
                "0e706eab30a2f899c833dad436b7ce26ab666bb5",
                "456e4052f76c7df9a851c3b3d527ef357cdc64a9",
                "e2d88c04f8a5caff9aefdcf4c36d29b755acfb5f",
            ],
        );
        check_salt_lengths::<Sha224>(
            "SHA-224",
            [
                "a862b01263be3169998d69f7f3ba8ceb67dea3b072f7c507a7976f55",
                "6066f84e7923d058228abc0b341f6fd93b2c9a61f89592c4439f04fd",
                "dd85d4470539ecac15562e424d2b7e5a0462e31cfc32e4fef12cd5a8",
            ],
        );
        check_salt_lengths::<Sha256>(
            "SHA-256",
            [
                "01541ab9f2902b89038dab768f1706b15bf8e650095af780520009758f4b690a",
                "68a2a4be13f00db7b68ac676fa238602cf519b1faac2d58db914f52fa79b9f3d",
                "d7e43713f489524e2d4be973f339672525d4692a5c7367045618ea7272d9018d",
            ],
        );
        check_salt_lengths::<Sha384>(
            "SHA-384",
            [
                "565982d7f1347a78ecdb930c6b93a5cbe83de93fe8275a35d0291cadcff78185\
                 10f9c983fb42e5725dbb2b151fc2ef7d",
                "fa6b53c9f1a4c296a737f5bcc54ee8090bd44221da2c6cda603b7205f1ab55ac\
                 df1e1cb7daf495703328ee2bad1630cc",
                "1ec0714da7b16451083ba5bafab02cbc5151945c5da9b232af4f6529385515ed\
                 9115d53e0f871b0279a0e9d8a1535e16",
            ],
        );
        check_salt_lengths::<Sha512>(
            "SHA-512",
            [
                "2d3e539a48284a030315bf8a7edbf39e5612d5d1656cfa0084ad8230161ff549\
                 9bb6edad17aafb4da8e7c009dc8e3a8c3c331bcd4c68a63d2eee19b4555c5ca0",
                "6a0e3a3a732e0a3c82aaa2bcb9db5e583c4967ee57f819a62c3ffa688f393c3a\
                 37fd3e0b67de1ecc8a57c1faa994506cc707a2c555da0941b97be20243f1aa43",
                "02c359667675588069bd840d0b7a1d266a57b7a23b37c5b8cfbe5230dfd3daa3\
                 8fa01009203e526221180b46a37e93217a6991bb0e67b75cf8e27b27e140c099",
            ],
        );
        check_salt_lengths::<Sha512_224>(
            "SHA-512/224",
            [
                "7c19653c3de97b8e490071b09c2231222684ca34851e59c6a20e4468",
                "cead6df5aec1c39ab6bc4e3bcd3e20e1911d175a67fc4f55fe291a32",
                "71053ec43847821a224044d65a3d8385063397ed554d48ca73a50dca",
            ],
        );
        check_salt_lengths::<Sha512_256>(
            "SHA-512/256",
            [
                "91195e0236a390e515786620c922f68822db7f6a9ca623b2015b944ede0d72eb",
                "0a8d72a86aa12302c17b205a140b0180133e7ebb7f39906a0b071fc6cb3af4e5",
                "a0018f566baa35ac96644de0c7d0ced5113fb6f1ef5cf99039961ec7e11dbc28",
            ],
        );
    }

    /// Checks HashLen bytes of Expand with A.1's info, from a PRK of
    /// `counting(n)` for n = the hash's block length and one more: the longest
    /// key HMAC pads and the shortest one it hashes, here as the key of every
    /// block of Expand rather than as the salt of Extract.
    fn check_prk_lengths<D: Digest>(name: &str, expected: [&str; 2]) {
        let lengths = [D::BLOCK_LEN, D::BLOCK_LEN + 1];
        for (prk_len, expected) in lengths.into_iter().zip(expected) {
            let mut okm = vec![0; D::OUTPUT_LEN];
            let hkdf = Hkdf::<D>::from_prk(&counting(prk_len)).unwrap();
            hkdf.expand(&A1_INFO, &mut okm).unwrap();
            assert_eq!(hex(&okm), expected, "{name}, {prk_len}-byte PRK");
        }
    }

    /// From the same two implementations (`hkdf.Expand`, and OpenSSL's
    /// `mode:EXPAND_ONLY`).
    #[test]
    fn prk_lengths() {
        check_prk_lengths::<Md5>(
            "MD5",
            [
                "edf3b03dfffd1cef37cde47067a4c1a4",
                "10e3e8d2c71ad1a872b6d48174be4716",
            ],
        );
        check_prk_lengths::<Sha1>(
            "SHA-1",
            [
                "dd65e5902a9ea7f67a2b923b60254019727b298f",
                "53874bdddc4856456c7043fc0e361336853af556",
            ],
        );
        check_prk_lengths::<Sha224>(
            "SHA-224",
            [
                "cb3f4bb9de251f78a83f89b468a811d86bc5c7700304ff5ac1968725",
                "b8f6815400e0d9fe544da73fdbe39f3c4abb9b492754b88783d75fec",
            ],
        );
        check_prk_lengths::<Sha256>(
            "SHA-256",
            [
                "8423ee1e206da245ae87fa08149cc651d9b664ce40212ec935ef0c7a89c2eca4",
                "55e948eb91c8d40a3d830b7f18b54212ec17d140b204ad929a38b55f5ae7ce69",
            ],
        );
        check_prk_lengths::<Sha384>(
            "SHA-384",
            [
                "af649a65f7e6691509e00f68f27b2a25721b9f9ebac50c6bb163782a7c8adbc4\
                 e16239e6e357f959c9de504d46b3c7e1",
                "be8d5b3195a3233ec02789b2aedcd139f572c6721e344c313f199725567eec46\
                 631bb8aa64bc08c5f53f5bfc49f8f201",
            ],
        );
        check_prk_lengths::<Sha512>(
            "SHA-512",
            [
                "fcd96c49d07bf7762d10467aade920afbce0655f8419e618b90bab58c85dbe65\
                 6256bb6f76b7f3d0bed876af1d7d3af803587a87d729aaa1a7c8546c8c2aa6b4",
                "e3680c2c9cfb6f675801561bce6ab930948bff0ee4c29649886c6127bd9e1a02\
                 6235d9679808ac04c3cc518225ffc0a5d9e891ebec483af3d724f405f833bb4a",
            ],
        );
        check_prk_lengths::<Sha512_224>(
            "SHA-512/224",
            [
                "7ecf6f914c11fe92502aaede3af925861569cc640ae881dfc1ac75bf",
                "1d60727f0bb8cca6ef8187146330d47cdc05c59826b8f9d90acdd46e",
            ],
        );
        check_prk_lengths::<Sha512_256>(
            "SHA-512/256",
            [
                "5a8cc7d50be41112d503caf0c3437f0efa84149b052b458c2d6e5043550c7f51",
                "2644f4fb81752a107a1de66714c670f67c798ed04088be3de4145cc698b0f949",
            ],
        );
    }

    /// Checks the longest output, 255 blocks, with RFC 5869 A.1's inputs
    /// (`expected` is its SHA-256 digest), then one byte more, which would take
    /// a 256th block and so a counter that does not fit in a byte. Then checks
    /// that outputs ending at the edges of the first and the last blocks are
    /// the start of the longest one, down to no output at all.
    fn check_longest<D: Digest>(name: &str, expected: &str) {
        let hkdf = Hkdf::<D>::extract(&counting(13), &A1_IKM);
        let max = Hkdf::<D>::MAX_OUTPUT_LEN;

        let mut longest = vec![0; max];
        hkdf.expand(&A1_INFO, &mut longest).unwrap();
        assert_eq!(hex(&Sha256::digest(&longest)), expected, "{name}");

        let mut too_long = vec![0; max + 1];
        let refused = Err(Error::InvalidLength);
        assert_eq!(hkdf.expand(&A1_INFO, &mut too_long), refused, "{name}");
        let derived = Hkdf::<D>::derive(&counting(13), &A1_IKM, &A1_INFO, &mut too_long);
        assert_eq!(derived, refused, "{name}");
        assert!(too_long.iter().all(|&b| b == 0), "{name}: written to");

        // `last` is where block 255 starts.
        let (h, last) = (D::OUTPUT_LEN, max - D::OUTPUT_LEN);
        for len in [0, 1, h - 1, h, h + 1, last - 1, last, last + 1, max - 1] {
            let mut okm = vec![0; len];
            hkdf.expand(&A1_INFO, &mut okm).unwrap();
            assert_eq!(okm, longest[..len], "{name}, {len} bytes");
        }
    }

    /// The digests come from the same two implementations.
    #[test]
    fn longest_output() {
        check_longest::<Md5>(
            "MD5",
            "e68d46b997c50c7d73f0b2345e4f960467285fc7681ed6ea54054e9cf4909ca0",
        );
        check_longest::<Sha1>(
            "SHA-1",
            "3dd47bf3122324d646b8b0f436af48a863cce06b8ba00858a749cfd032a33d31",
        );
        check_longest::<Sha224>(
            "SHA-224",
            "29e46ae45b4b01a83939b6a19e83bb821b0bd9cb525c2b6d756b1f014737e13c",
        );
        check_longest::<Sha256>(
            "SHA-256",
            "06ce7419405a88a66ba5c9795579cb05130c85101924d187552a0f7f57deb091",
        );
        check_longest::<Sha384>(
            "SHA-384",
            "e5108cb51f12039dc902ba5cd8bceb93f3c67dd3dad3129a45ef7642dabea5ce",
        );
        check_longest::<Sha512>(
            "SHA-512",
            "d623a5f5bc03bad6fef4c74bef4bf03770338d155b256c333cae9a3ca8f77e45",
        );
        check_longest::<Sha512_224>(
            "SHA-512/224",
            "5d5bd9820263c8fcc59a716da7f1d565e68a5010d25db9845dbda1942d4e0eaf",
        );
        check_longest::<Sha512_256>(
            "SHA-512/256",
            "0c90a7febf1b78ff515a92c4b7e47385f540c829a6003f95477ebcf11ef97661",
        );
    }

    /// Checks two blocks of HKDF from a 1000-byte IKM (`counting(1000)`, which
    /// wraps) with a 1000-byte info of `0xf0`, and A.1's salt: every message
    /// HMAC hashes is then longer than any block, and longer than the HMAC
    /// puts together on the stack.
    fn check_long_inputs<D: Digest>(name: &str, expected: &str) {
        let mut okm = vec![0; 2 * D::OUTPUT_LEN];
        Hkdf::<D>::derive(&counting(13), &counting(1000), &[0xf0; 1000], &mut okm).unwrap();
        assert_eq!(hex(&okm), expected, "{name}");
    }

    /// From the same two implementations.
    #[test]
    fn long_inputs() {
        check_long_inputs::<Sha256>(
            "SHA-256",
            "b6c2a534da8d848b7f8347e087add474ffe2ed2770c157d93dadf9369895bb3e\
             13f94baa3ab84b272e82ecf5a08edabed2b68193fcd5fc49e36c75978ef41739",
        );
        check_long_inputs::<Sha512>(
            "SHA-512",
            "3426192bb35416dee40036bd7d986917048577119e43d8c08af5323ea38ba1f5\
             6609915176e571f7018b237174da191a52f3a9d8518a40e7de5490fc76b45a1f\
             1a1d3c13b76e89deefd833cb60d9f1d4af14fb9a60d38e3f381d4acfb0c30843\
             465694eecf96302ea9c143e2739063f91816c1435eb3efb0d4147cd8f54e92b2",
        );
    }

    /// An empty salt must give the PRK that HashLen zero bytes give, which is
    /// the salt RFC 5869 section 2.2 says to use when there is none. A short
    /// PRK must be refused, and one of exactly HashLen bytes accepted.
    fn check_lengths_of_inputs<D: Digest>(name: &str) {
        let empty = extract_prk::<D>(&[], &A1_IKM);
        let zeros = extract_prk::<D>(&vec![0; D::OUTPUT_LEN], &A1_IKM);
        assert_eq!(empty.as_ref(), zeros.as_ref(), "{name}: empty salt");

        for len in [0, D::OUTPUT_LEN - 1] {
            let short = Hkdf::<D>::from_prk(&vec![0x42; len]);
            assert!(
                matches!(short, Err(Error::InvalidPrkLength)),
                "{name}: {len}-byte PRK"
            );
        }
        assert!(Hkdf::<D>::from_prk(&vec![0x42; D::OUTPUT_LEN]).is_ok());
    }

    #[test]
    fn lengths_of_inputs() {
        check_lengths_of_inputs::<Md5>("MD5");
        check_lengths_of_inputs::<Sha1>("SHA-1");
        check_lengths_of_inputs::<Sha224>("SHA-224");
        check_lengths_of_inputs::<Sha256>("SHA-256");
        check_lengths_of_inputs::<Sha384>("SHA-384");
        check_lengths_of_inputs::<Sha512>("SHA-512");
        check_lengths_of_inputs::<Sha512_224>("SHA-512/224");
        check_lengths_of_inputs::<Sha512_256>("SHA-512/256");
    }

    /// The Debug output must not show the PRK.
    #[test]
    fn debug_hides_the_prk() {
        let hkdf = Hkdf::<Sha256>::extract(b"salt", b"secret");
        assert_eq!(format!("{hkdf:?}"), "Hkdf { .. }");
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release hkdf:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        /// Longest outputs expanded per pass.
        const EXPANDS: usize = 4096;
        /// Short keys derived per pass.
        const DERIVES: usize = 200_000;

        /// Runs `pass` once to warm up, then five times, and returns the best
        /// of the five in passes per second.
        fn best_rate(mut pass: impl FnMut()) -> f64 {
            // The first pass is slowed down by page faults and CPU clock
            // ramp-up, not just HKDF itself, so it is not timed.
            pass();
            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass();
                best = best.max(1.0 / start.elapsed().as_secs_f64());
            }
            best
        }

        fn run<D: Digest>(name: &str) {
            // RFC 5869 A.1's salt and info, the same bytes as on the Go side.
            let salt = counting(13);

            // Expand as far as it goes, 255 blocks at a time. The output is
            // the same every time; its last bytes are those of block 255.
            let hkdf = Hkdf::<D>::extract(&salt, &A1_IKM);
            let mut okm = vec![0; Hkdf::<D>::MAX_OUTPUT_LEN];
            let rate = best_rate(|| {
                for _ in 0..EXPANDS {
                    hkdf.expand(black_box(&A1_INFO), black_box(&mut okm))
                        .unwrap();
                }
            });
            let mib = (EXPANDS * okm.len()) as f64 / (1024.0 * 1024.0);
            println!(
                "hkdf-{name} expand {} bytes [cryptors]: {EXPANDS} per pass, best {:.1} MiB/s \
                 (last bytes {})",
                okm.len(),
                rate * mib,
                hex(&okm[okm.len() - 8..])
            );

            // Extract and Expand from a 32-byte secret to a 32-byte key, as
            // after a key exchange. Each key is the secret of the next, so the
            // calls form one chain and the last key identifies the whole run.
            let mut key: [u8; 32] = counting(32).try_into().unwrap();
            let rate = best_rate(|| {
                for _ in 0..DERIVES {
                    let secret = key;
                    Hkdf::<D>::derive(&salt, &secret, &A1_INFO, &mut key).unwrap();
                }
            });
            println!(
                "hkdf-{name} derive 32 bytes [cryptors]: {DERIVES} per pass, best {:.0} ops/s \
                 (last key {}...)",
                rate * DERIVES as f64,
                hex(&key[..8])
            );
        }

        run::<Sha256>("sha256");
        run::<Sha512>("sha512");
    }
}
