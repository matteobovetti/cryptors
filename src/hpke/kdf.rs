//! HMAC (RFC 2104, FIPS 198-1) and HKDF (RFC 5869), generic over [`Digest`],
//! and the labelled forms of them that HPKE derives every key with (RFC 9180
//! section 4).
//!
//! **Internal.** This is a private stand-in, written so that HPKE could land
//! before the crate's own HMAC and HKDF modules, which are planned. It is meant
//! to be superseded by them when they land: HPKE would then keep only
//! [`labeled_extract`] and [`labeled_expand`], on top of the public functions.
//!
//! [`Digest`] hashes a whole message in one call and has no incremental form.
//! HMAC's inner hash is over the padded key followed by the message, so each
//! call assembles the two in one buffer, and wipes it afterwards, since it holds
//! the key.

use super::secret::Secret;
use crate::Digest;
use crate::wipe::wipe;

/// The largest block of the hashes HPKE uses: 128 bytes, for SHA-384 and
/// SHA-512.
const MAX_BLOCK_LEN: usize = 128;

/// The largest digest of the hashes HPKE uses: 64 bytes, for SHA-512.
const MAX_OUTPUT_LEN: usize = 64;

/// The version label that starts every derivation in HPKE (RFC 9180 section
/// 4), so that its secrets are bound to the scheme and its version.
const VERSION: &[u8] = b"HPKE-v1";

/// HKDF-Expand was asked for more than 255 digests of output (RFC 5869
/// section 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OutputTooLong;

/// HMAC with the hash `D` (RFC 2104 section 2) of the concatenation of the
/// parts of `message`, under `key`.
///
/// The message comes in parts so that callers need not concatenate them: HKDF
/// and the labelled functions all hash a few fixed strings around one input.
pub(super) fn hmac<D: Digest>(key: &[u8], message: &[&[u8]]) -> Secret {
    const { assert!(D::BLOCK_LEN <= MAX_BLOCK_LEN && D::OUTPUT_LEN <= MAX_OUTPUT_LEN) };
    let block_len = D::BLOCK_LEN;

    // K0: the key padded with zeros to a whole block, after hashing it first if
    // it is longer than a block.
    let mut k0 = [0u8; MAX_BLOCK_LEN];
    if key.len() > block_len {
        k0[..D::OUTPUT_LEN].copy_from_slice(D::digest(key).as_ref());
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    // H((K0 ^ ipad) || message). The buffer is allocated at its final size, so
    // it never moves and leaves no copy of the key behind.
    let message_len: usize = message.iter().map(|part| part.len()).sum();
    let mut inner = Vec::with_capacity(block_len + message_len);
    inner.extend(k0[..block_len].iter().map(|byte| byte ^ 0x36));
    for part in message {
        inner.extend_from_slice(part);
    }
    let inner_digest = D::digest(&inner);
    wipe(&mut inner);

    // H((K0 ^ opad) || H((K0 ^ ipad) || message)).
    let mut outer = [0u8; MAX_BLOCK_LEN + MAX_OUTPUT_LEN];
    for (byte, key_byte) in outer.iter_mut().zip(&k0[..block_len]) {
        *byte = key_byte ^ 0x5c;
    }
    outer[block_len..][..D::OUTPUT_LEN].copy_from_slice(inner_digest.as_ref());
    let mac = Secret::from_slice(D::digest(&outer[..block_len + D::OUTPUT_LEN]).as_ref());

    wipe(&mut k0);
    wipe(&mut outer);
    mac
}

/// HKDF-Extract (RFC 5869 section 2.2): the pseudorandom key
/// `HMAC(salt, ikm)`, with the input keying material in parts.
///
/// An empty `salt` is the salt that "is not provided", which the RFC sets to a
/// string of zeros as long as a digest. As an HMAC key the two are the same key,
/// since HMAC pads both with zeros to a whole block.
pub(super) fn extract<D: Digest>(salt: &[u8], ikm: &[&[u8]]) -> Secret {
    hmac::<D>(salt, ikm)
}

/// HKDF-Expand (RFC 5869 section 2.3): fills `okm` with output keying material
/// from the pseudorandom key `prk` and the parts of `info`.
///
/// Fails if `okm` is longer than 255 digests, the most that HKDF defines.
pub(super) fn expand<D: Digest>(
    prk: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), OutputTooLong> {
    if okm.len() > 255 * D::OUTPUT_LEN {
        return Err(OutputTooLong);
    }

    // T(0) is empty, and T(i) = HMAC(PRK, T(i - 1) || info || i) for i = 1, 2,
    // ...; the output is T(1) || T(2) || ..., cut to length.
    let mut t = Secret::zeroed(0);
    for (i, chunk) in okm.chunks_mut(D::OUTPUT_LEN).enumerate() {
        let counter = [u8::try_from(i + 1).expect("at most 255 blocks, checked above")];
        let mut message = Vec::with_capacity(info.len() + 2);
        message.push(t.as_bytes());
        message.extend_from_slice(info);
        message.push(&counter);
        t = hmac::<D>(prk, &message);
        chunk.copy_from_slice(&t.as_bytes()[..chunk.len()]);
    }
    Ok(())
}

/// `LabeledExtract(salt, label, ikm)` (RFC 9180 section 4): HKDF-Extract of
/// `"HPKE-v1" || suite_id || label || ikm`.
///
/// `suite_id` says where in HPKE the call is made: `"KEM"` and the KEM's
/// identifier inside the KEM, `"HPKE"` and the whole suite's elsewhere.
pub(super) fn labeled_extract<D: Digest>(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Secret {
    extract::<D>(salt, &[VERSION, suite_id, label, ikm])
}

/// `LabeledExpand(prk, label, info, L)` (RFC 9180 section 4): HKDF-Expand with
/// the info `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`, where `L`
/// is the length of `out`.
pub(super) fn labeled_expand<D: Digest>(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), OutputTooLong> {
    // Every length that `expand` accepts, at most 255 * 64 bytes, fits in the
    // two bytes of I2OSP(L, 2).
    let len = u16::try_from(out.len())
        .map_err(|_| OutputTooLong)?
        .to_be_bytes();
    expand::<D>(prk, &[&len, VERSION, suite_id, label, info], out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::hex;
    use crate::hpke::tests::{stream, unhex};
    use crate::sha2::{Sha256, Sha384, Sha512};

    fn hmac_hex<D: Digest>(key: &[u8], data: &[u8]) -> String {
        hex(hmac::<D>(key, &[data]).as_bytes())
    }

    /// The test cases of RFC 4231, for the three hashes HPKE uses: (key, data,
    /// HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512). Test case 5, whose outputs the
    /// RFC truncates to 128 bits, is checked on that prefix.
    const RFC_4231: [(&str, &str, &str, &str, &str); 7] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
        (
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
        (
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "546573742057697468205472756e636174696f6e",
            "a3b6167473100ee06e0c796c2955552b",
            "3abf34c3503b2a23a46efc619baef897",
            "415fad6271580a531d4179bc891d87a6",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ];

    #[test]
    fn rfc4231_hmac() {
        for (i, (key, data, sha256, sha384, sha512)) in RFC_4231.into_iter().enumerate() {
            let (key, data) = (unhex(key), unhex(data));
            let case = i + 1;
            // Test case 5 publishes only the first 128 bits of each output.
            let prefix = |mac: String, want: &str| mac[..want.len()].to_string();
            assert_eq!(
                prefix(hmac_hex::<Sha256>(&key, &data), sha256),
                sha256,
                "SHA-256, case {case}"
            );
            assert_eq!(
                prefix(hmac_hex::<Sha384>(&key, &data), sha384),
                sha384,
                "SHA-384, case {case}"
            );
            assert_eq!(
                prefix(hmac_hex::<Sha512>(&key, &data), sha512),
                sha512,
                "SHA-512, case {case}"
            );
        }
    }

    /// RFC 5869 Appendix A, the three SHA-256 cases: (IKM, salt, info, PRK,
    /// OKM).
    const RFC_5869: [(&str, &str, &str, &str, &str); 3] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];

    #[test]
    fn rfc5869_hkdf() {
        for (i, (ikm, salt, info, prk, okm)) in RFC_5869.into_iter().enumerate() {
            let (ikm, salt, info, okm) = (unhex(ikm), unhex(salt), unhex(info), unhex(okm));
            let case = i + 1;
            let ours = extract::<Sha256>(&salt, &[&ikm]);
            assert_eq!(hex(ours.as_bytes()), prk, "PRK, case {case}");
            let mut out = vec![0u8; okm.len()];
            expand::<Sha256>(ours.as_bytes(), &[&info], &mut out).unwrap();
            assert_eq!(out, okm, "OKM, case {case}");
        }
    }

    /// HKDF with SHA-384 and SHA-512, which RFC 5869 has no vectors for, from
    /// Go's crypto/hkdf: (hash, i, IKM length, salt length, info length, L,
    /// OKM) with the inputs `stream("hkdf ikm", i, ...)`, `stream("hkdf salt",
    /// ...)` and `stream("hkdf info", ...)`. Where L is the most HKDF allows,
    /// the OKM column is the SHA-256 of the output. The 200-byte salt is longer
    /// than a block, so HMAC hashes it first.
    const GO_HKDF: [(u32, u32, usize, usize, usize, usize, &str); 8] = [
        (
            384,
            0,
            22,
            13,
            10,
            42,
            "c1e5aebf19f4069711885eb1eaecf59cdadf0e100f4e6bc17772d0e3a21b45f974547ad626b09c9b436a",
        ),
        (
            384,
            1,
            80,
            80,
            80,
            82,
            "d538f278e015ec105160c6f6f63c9b1f40c83e8167d0531cbb87494ee5f9d2e5bbc3145bd8c5dc64c32f686c7a9c0c3969f4f11dbe7e3b0da52cb759b2dd600250319279e56521af1febb133d23ca3caa050",
        ),
        (
            384,
            2,
            22,
            0,
            0,
            49,
            "55ef716459e4b4d37d40e1014f070eb25c21216cedbf942b9c278bec7eadc5652e51b796999f7926f12925a3ad9406a699",
        ),
        (
            384,
            3,
            7,
            200,
            7,
            255 * 48,
            "8004ad87f553895b6fab0f843263ad5aa327a66d39a064642955e47c35f0196f",
        ),
        (
            512,
            0,
            22,
            13,
            10,
            42,
            "3e5566a8c01b1faf46fb4837cf863a975e43b704104149c5a85893b4b7ab6de2f3fe90480790d450f3ee",
        ),
        (
            512,
            1,
            80,
            80,
            80,
            82,
            "f3df37c0828b158e7890c4babf375ecb4cc49e20d7d8d7d64c3b35bcc11de063b5a630969d56da82d9b233ab50e377b1a6d5d728e44874dabc12bfa851d80de27e3be51fa018870b8e2e404fe2699e73ae0f",
        ),
        (
            512,
            2,
            22,
            0,
            0,
            65,
            "03bb14b706be4e3ca6af3b89a1b55f2a909785ce1ebae308263489d1dbfd9b187b765d5b3162616f2f1ee61f70e00b7fa6660109c8e692a3759d701cf6b1f3f6a1",
        ),
        (
            512,
            3,
            7,
            200,
            7,
            255 * 64,
            "305b2363d3a65d7a1895adbd92e2b6f3b655bff1af9058870910bd0914827d57",
        ),
    ];

    fn hkdf_with<D: Digest>(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let prk = extract::<D>(salt, &[ikm]);
        let mut okm = vec![0u8; len];
        expand::<D>(prk.as_bytes(), &[info], &mut okm).unwrap();
        okm
    }

    #[test]
    fn go_hkdf_sha384_sha512() {
        for (bits, i, ikm_len, salt_len, info_len, len, want) in GO_HKDF {
            let ikm = stream(b"hkdf ikm", i, ikm_len);
            let salt = stream(b"hkdf salt", i, salt_len);
            let info = stream(b"hkdf info", i, info_len);
            let (okm, max) = match bits {
                384 => (hkdf_with::<Sha384>(&ikm, &salt, &info, len), 255 * 48),
                _ => (hkdf_with::<Sha512>(&ikm, &salt, &info, len), 255 * 64),
            };
            let got = if len == max {
                hex(&Sha256::digest(&okm))
            } else {
                hex(&okm)
            };
            assert_eq!(got, want, "HKDF-SHA-{bits}, i = {i}, L = {len}");
        }
    }

    #[test]
    fn expand_stops_at_255_digests() {
        let prk = [7u8; 32];
        let mut okm = vec![0u8; 255 * 32 + 1];
        assert_eq!(expand::<Sha256>(&prk, &[], &mut okm), Err(OutputTooLong));
        assert_eq!(expand::<Sha256>(&prk, &[], &mut okm[..255 * 32]), Ok(()));

        let mut okm = vec![0u8; 255 * 64 + 1];
        assert_eq!(
            labeled_expand::<Sha512>(b"HPKE", &prk, b"sec", b"", &mut okm),
            Err(OutputTooLong)
        );
        assert_eq!(
            labeled_expand::<Sha512>(b"HPKE", &prk, b"sec", b"", &mut okm[..255 * 64]),
            Ok(())
        );
    }
}
