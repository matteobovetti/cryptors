//! RSAES-OAEP's padding (RFC 8017, section 7.1): `EME-OAEP` encoding and
//! decoding of the block that the RSA primitive encrypts.

use super::bytes::Wiped;
use super::error::Error;
use super::mgf1::mgf1_xor;
use crate::Digest;
use crate::ec::ct;

/// `EME-OAEP` encoding of `message` into a block of `k` bytes, the length of the
/// modulus, with the given `seed` of `D::OUTPUT_LEN` bytes:
///
/// ```text
/// EM = 0x00 || maskedSeed || maskedDB
/// DB = lHash || PS || 0x01 || M            (PS is zero bytes)
/// maskedDB = DB xor MGF(seed, k - hLen - 1)
/// maskedSeed = seed xor MGF(maskedDB, hLen)
/// ```
///
/// `D` hashes the label and `M` is the hash of MGF1. The message has to leave
/// room for the two digests and the two marker bytes.
pub(super) fn encode<D: Digest, M: Digest>(
    k: usize,
    message: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<Wiped, Error> {
    let h = D::OUTPUT_LEN;
    assert_eq!(seed.len(), h);
    if k < 2 * h + 2 || message.len() > k - 2 * h - 2 {
        return Err(Error::MessageTooLong);
    }

    let mut em = Wiped::zero(k);
    let (seed_block, db) = em[1..].split_at_mut(h);
    seed_block.copy_from_slice(seed);
    db[..h].copy_from_slice(D::digest(label).as_ref());
    let message_at = db.len() - message.len();
    db[message_at - 1] = 1;
    db[message_at..].copy_from_slice(message);

    mgf1_xor::<M>(db, seed_block);
    mgf1_xor::<M>(seed_block, db);
    Ok(em)
}

/// `EME-OAEP` decoding of the block `em` of `k` bytes, which is overwritten:
/// the message, or [`Error::Decryption`] if the block is not the encoding of one
/// under `label`.
///
/// All the checks (the leading zero byte, the digest of the label, the zero
/// bytes up to a one) are made on every byte and combined into one answer
/// before it is looked at, and the message is found without a branch on the
/// bytes, so that the time does not tell which check failed or where the message
/// starts: that is what Manger's attack on OAEP needs. The only thing it
/// reveals is whether the block decoded, and the length of the message when it
/// did, which the caller learns anyway.
pub(super) fn decode<D: Digest, M: Digest>(em: &mut [u8], label: &[u8]) -> Result<Vec<u8>, Error> {
    let h = D::OUTPUT_LEN;
    if em.len() < 2 * h + 2 {
        return Err(Error::Decryption);
    }

    let l_hash = D::digest(label);
    let first_is_zero = ct::eq(u64::from(em[0]), 0);
    let (seed, db) = em[1..].split_at_mut(h);
    mgf1_xor::<M>(seed, db);
    mgf1_xor::<M>(db, seed);

    let (stored_hash, rest) = db.split_at(h);
    let hash_matches = u64::from(ct::bytes_eq(l_hash.as_ref(), stored_hash));

    // Looking at each byte of `rest` in turn:
    //   looking: 1 while the 0x01 has not been seen,
    //   index: where the first 0x01 is,
    //   invalid: 1 if a byte other than 0x00 came before it.
    let mut looking = 1;
    let mut index = 0;
    let mut invalid = 0;
    for (i, &byte) in rest.iter().enumerate() {
        let is_zero = ct::eq(u64::from(byte), 0);
        let is_one = ct::eq(u64::from(byte), 1);
        index = ct::select(ct::mask(looking & is_one), i as u64, index);
        looking &= is_one ^ 1;
        invalid |= looking & (is_zero ^ 1);
    }

    if first_is_zero & hash_matches & (invalid ^ 1) & (looking ^ 1) != 1 {
        return Err(Error::Decryption);
    }
    Ok(rest[index as usize + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha256, Sha512};

    #[test]
    fn decode_inverts_encode() {
        // Every length of message the block takes, for two hashes and a key of
        // 128 bytes: 0 to 86 with SHA-1 and 0 to 62 with SHA-256.
        for message_len in 0..=86 {
            let message: Vec<u8> = (0..message_len as u8).map(|i| i | 1).collect();
            let seed = [0x5a; 20];
            let mut em = encode::<Sha1, Sha1>(128, &message, b"label", &seed).unwrap();
            assert_eq!(em[0], 0);
            assert_eq!(decode::<Sha1, Sha1>(&mut em, b"label"), Ok(message));
        }
        for message_len in 0..=62 {
            let message = vec![0; message_len];
            let mut em = encode::<Sha256, Sha256>(128, &message, b"", &[7; 32]).unwrap();
            assert_eq!(decode::<Sha256, Sha256>(&mut em, b""), Ok(message));
        }
    }

    #[test]
    fn encode_leaves_no_room_for_a_longer_message() {
        assert_eq!(
            encode::<Sha1, Sha1>(128, &[0; 87], b"", &[0; 20]).err(),
            Some(Error::MessageTooLong)
        );
        assert!(encode::<Sha1, Sha1>(128, &[0; 86], b"", &[0; 20]).is_ok());
        // A key too short for the hash has no room for any message at all.
        assert_eq!(
            encode::<Sha512, Sha512>(128, b"", b"", &[0; 64]).err(),
            Some(Error::MessageTooLong)
        );
        assert!(encode::<Sha512, Sha512>(130, b"", b"", &[0; 64]).is_ok());
    }

    #[test]
    fn decode_refuses_every_wrong_block() {
        let message = b"attack at dawn";
        let good = encode::<Sha256, Sha256>(128, message, b"label", &[9; 32]).unwrap();
        let decode = |em: &[u8], label: &[u8]| decode::<Sha256, Sha256>(&mut em.to_vec(), label);
        assert_eq!(decode(&good, b"label").unwrap(), message);

        // Another label.
        assert_eq!(decode(&good, b"labels"), Err(Error::Decryption));
        // A change to any one byte of the block, the first one included.
        for i in 0..good.len() {
            let mut bad = good.to_vec();
            bad[i] ^= 1;
            assert_eq!(decode(&bad, b"label"), Err(Error::Decryption), "byte {i}");
        }
        // A block too short to hold the two digests.
        assert_eq!(decode(&good[..65], b"label"), Err(Error::Decryption));
        assert_eq!(decode(&[], b"label"), Err(Error::Decryption));
    }

    /// A block whose data block is all zeros after the label's hash has no 0x01 to
    /// mark the message, and one with another byte before the 0x01 has junk
    /// padding: neither decodes. They are built here by undoing the masking.
    #[test]
    fn decode_refuses_a_missing_or_corrupt_marker() {
        fn block(data: &[u8]) -> Vec<u8> {
            // The block that decodes to `data` (hash of the empty label, then
            // `data`) with a seed of 0x42.
            let h = Sha256::digest(b"");
            let mut db = h.as_ref().to_vec();
            db.extend_from_slice(data);
            let seed = [0x42u8; 32];
            let mut masked_seed = seed;
            mgf1_xor::<Sha256>(&mut db, &seed);
            mgf1_xor::<Sha256>(&mut masked_seed, &db);
            let mut em = vec![0];
            em.extend_from_slice(&masked_seed);
            em.extend_from_slice(&db);
            em
        }
        let decode = |em: &[u8]| decode::<Sha256, Sha256>(&mut em.to_vec(), b"");

        // 128 bytes less the zero byte, the seed and the label's hash.
        let mut data = vec![0u8; 128 - 1 - 2 * 32];
        // No marker at all.
        assert_eq!(decode(&block(&data)), Err(Error::Decryption));
        // A marker after the padding: a message of one byte.
        let n = data.len();
        data[n - 2] = 1;
        data[n - 1] = 0xaa;
        assert_eq!(decode(&block(&data)), Ok(vec![0xaa]));
        // A byte that is neither 0x00 nor 0x01 before the marker.
        data[3] = 2;
        assert_eq!(decode(&block(&data)), Err(Error::Decryption));
        // The first 0x01 is the marker, whatever follows.
        data[3] = 0;
        data[n - 1] = 1;
        assert_eq!(decode(&block(&data)), Ok(vec![1]));
    }
}
