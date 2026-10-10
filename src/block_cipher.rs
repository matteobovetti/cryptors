//! The [`BlockCipher`] trait: the interface shared by every block cipher in
//! this crate.

/// A block cipher: a keyed permutation of fixed-size blocks, such as AES or
/// DES.
///
/// This is to ciphers what [`Digest`](crate::Digest) is to hashes, with one
/// difference. A hash is a zero-sized marker and its functions carry no state;
/// a cipher is built from a key, runs the key schedule once in [`new`], and
/// every block it then transforms reuses the result. Code that needs "some
/// block cipher", such as a mode of operation, takes `C: BlockCipher` and stays
/// independent of which one it is. Everything is resolved at compile time, so
/// a generic call compiles to the same thing as a direct one.
///
/// A block cipher is only the permutation. Encrypting a message with it takes a
/// mode of operation as well, and calling [`encrypt_block`] on every block of a
/// message independently (ECB) encrypts equal blocks to equal ciphertext, which
/// reveals the structure of the message.
///
/// Bring the trait into scope to call the functions:
///
/// ```
/// use cryptors::{BlockCipher, aes::Aes128};
///
/// let cipher = Aes128::new(&[0; 16]);
/// let ciphertext = cipher.encrypt_block(&[0; 16]);
/// assert_eq!(ciphertext[..4], [0x66, 0xe9, 0x4b, 0xd4]);
/// assert_eq!(cipher.decrypt_block(&ciphertext), [0; 16]);
/// ```
///
/// And, in generic code, treat the cipher as a parameter. The block and the key
/// are types of the cipher, so ciphers whose blocks and keys differ in size, as
/// AES (16-byte blocks) and DES (8-byte blocks) do, fit the same code:
///
/// ```
/// use cryptors::{BlockCipher, aes::{Aes128, Aes256}, des::Des};
///
/// /// Encrypts the all-zero block under `key`, whichever cipher `C` is.
/// fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
///     C::new(key).encrypt_block(&C::Block::default())
/// }
///
/// assert_eq!(encrypt_zeros::<Aes128>(&[0; 16]).as_ref().len(), Aes128::BLOCK_LEN);
/// assert_eq!(encrypt_zeros::<Aes256>(&[0; 32]).as_ref().len(), Aes256::BLOCK_LEN);
/// assert_eq!(encrypt_zeros::<Des>(&[0; 8]).as_ref().len(), Des::BLOCK_LEN);
/// ```
///
/// [`new`]: BlockCipher::new
/// [`encrypt_block`]: BlockCipher::encrypt_block
pub trait BlockCipher: Sized {
    /// Size in bytes of the blocks the cipher transforms. Always equals
    /// `Self::Block`'s length.
    const BLOCK_LEN: usize;

    /// Size in bytes of the key. Always equals `Self::Key`'s length.
    const KEY_LEN: usize;

    /// A key: a `[u8; KEY_LEN]`.
    type Key: AsRef<[u8]>;

    /// A block: a `[u8; BLOCK_LEN]`.
    type Block: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// Builds a cipher from `key`, running the key schedule.
    fn new(key: &Self::Key) -> Self;

    /// Encrypts one block.
    fn encrypt_block(&self, block: &Self::Block) -> Self::Block;

    /// Decrypts one block. The inverse of [`encrypt_block`](Self::encrypt_block)
    /// under the same key.
    fn decrypt_block(&self, block: &Self::Block) -> Self::Block;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{Aes128, Aes192, Aes256};
    use crate::des::{Des, TripleDes};

    /// Checks, for any cipher, that the constants agree with the key and block
    /// types and that decryption undoes encryption. The ciphertexts themselves
    /// are checked against known answers by each algorithm's own tests.
    fn check<C: BlockCipher>(key: &C::Key) {
        assert_eq!(key.as_ref().len(), C::KEY_LEN);

        let mut block = C::Block::default();
        assert_eq!(block.as_ref().len(), C::BLOCK_LEN);
        for (i, byte) in block.as_mut().iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }

        let cipher = C::new(key);
        let ciphertext = cipher.encrypt_block(&block);
        assert_eq!(ciphertext.as_ref().len(), C::BLOCK_LEN);
        assert_eq!(cipher.decrypt_block(&ciphertext).as_ref(), block.as_ref());
    }

    #[test]
    fn every_cipher_satisfies_the_contract() {
        check::<Aes128>(&[1; 16]);
        check::<Aes192>(&[2; 24]);
        check::<Aes256>(&[3; 32]);
        check::<Des>(&[4; 8]);
        check::<TripleDes>(&[5; 24]);
    }
}
