//! From-scratch implementation of the Advanced Encryption Standard
//! (FIPS 197): the block cipher that NIST standardised in 2001, taken from the
//! Rijndael family, in its three key sizes.
//!
//! | Cipher | Type | Key | Block | Rounds |
//! |--------|------|-----|-------|--------|
//! | AES-128 | [`Aes128`] | 16 bytes | 16 bytes | 10 |
//! | AES-192 | [`Aes192`] | 24 bytes | 16 bytes | 12 |
//! | AES-256 | [`Aes256`] | 32 bytes | 16 bytes | 14 |
//!
//! All three implement [`BlockCipher`](crate::BlockCipher).
//!
//! # How it works
//!
//! AES turns a 16-byte block into another 16-byte block. Each key selects a
//! different permutation of the blocks, and the same key undoes it. The block
//! is laid out column by column as a 4x4 matrix of bytes, the state, and goes
//! through a number of rounds that depends on the key size. Every round but the
//! last has four steps:
//!
//! - **SubBytes** replaces each byte by its image under the S-box: the
//!   multiplicative inverse of the byte in the field GF(2^8) (with 0 staying 0),
//!   followed by a fixed affine transformation. It is the only step that is not
//!   linear, and the one that keeps the cipher from falling to algebra.
//! - **ShiftRows** rotates the second, third and fourth rows of the state by
//!   one, two and three places.
//! - **MixColumns** replaces each column by its product with a fixed matrix over
//!   GF(2^8), so that every byte of the column depends on all four before it.
//! - **AddRoundKey** XORs the state with a 16-byte round key.
//!
//! The last round leaves out MixColumns, and one more AddRoundKey comes before
//! the first round. The round keys come from the key by the key expansion: the
//! key itself is the first few words of a longer sequence, and each new word is
//! the word one key-length back XOR the word before it. Every key-length-th
//! word, the word before it first goes through a rotation, the S-box and a
//! round constant; AES-256 also puts a plain S-box step halfway between those.
//!
//! Decryption undoes the steps in reverse order with their inverses. The crate
//! uses the equivalent inverse cipher of section 5.3.5, which applies the
//! inverse of MixColumns to the round keys in advance. A decryption round then
//! has the same shape as an encryption round, which is also the shape the
//! hardware instructions come in. So building a cipher from a key runs the key
//! expansion once and keeps the round keys of both directions.
//!
//! # Using it
//!
//! A block cipher is a building block, not an encryption scheme. It encrypts
//! one block, and a message takes a mode of operation on top, which this crate
//! does not have yet. Calling `encrypt_block` on every block of a message
//! independently (ECB) is not a safe mode: equal plaintext blocks give equal
//! ciphertext blocks, so the structure of the message shows through. Nor does
//! anything here authenticate: a ciphertext that has been altered decrypts to
//! something else without any error.
//!
//! A cipher holds its round keys, which are overwritten with zeros when it is
//! dropped, and its `Debug` output does not show them. The compiler's own
//! copies of them on the stack, while a key is expanded or a block is
//! processed, are out of reach of that, and so is the copy that moving a cipher
//! (into a `Box` or a `Vec`, say) can leave behind where it was. Where that
//! matters, build the cipher where it will stay.
//!
//! AES is not broken. The best known attack on the full cipher, from 2011,
//! finds the key only about 3 to 5 times faster than trying every key, which
//! changes nothing in practice. Related-key attacks on AES-192 and AES-256 are
//! faster than that, but need encryptions under keys that differ in ways the
//! attacker chooses; do not derive one key by changing a few bits of another.
//!
//! # Backends
//!
//! There are three interchangeable backends, picked automatically at runtime:
//!
//! | Backend | Requires | Instructions |
//! |---------|----------|--------------|
//! | `aarch64` | ARMv8 crypto extensions (`aes`: FEAT_AES, which Rust reports together with FEAT_PMULL) | `AESE`, `AESMC`, `AESD`, `AESIMC` |
//! | `x86` | x86 AES instructions (AES-NI) | `AESENC`, `AESENCLAST`, `AESDEC`, `AESDECLAST`, `AESIMC` |
//! | `scalar` | nothing -- always available | table lookups: four tables of 256 words per direction |
//!
//! A round is one instruction on `x86` (`AESENC` does all four steps) and an
//! `AESE` and an `AESMC` on `aarch64`, so a block takes 10, 12 or 14 of them.
//! Both backends also run the key expansion on the instructions. The S-box is
//! all it needs from the cipher, and the substitution step of a round, with an
//! all-zero key, applied to a word copied into every column of the state, is
//! the S-box applied to each byte of that word. `scalar` replaces SubBytes,
//! ShiftRows and MixColumns with sixteen lookups in the tables per round.
//!
//! ## Trust
//!
//! `scalar` is the one we trust to be correct, and it is the one used on any
//! CPU without the instructions above. The tests check that each of the other
//! backends produces the same round keys and the same blocks as it, byte for
//! byte.
//!
//! ## Side channels
//!
//! The hardware backends never use the key or the block as a memory address or
//! as the condition of a branch, and the AES instructions are built to take
//! the same time for every input; no CPU is known to do otherwise. Arm
//! documents that guarantee only while its data-independent-timing mode (DIT)
//! is on, which this crate does not switch on. `scalar` does use the state as
//! an address: its lookups are at positions given by the state, and how long a
//! lookup takes depends on whether the CPU has that part of the table in its
//! cache. That can be measured by a program on the same core, and with more
//! samples from the response times of a server across a network, and it has
//! been used to recover AES keys in practice. It matters wherever `scalar` is
//! what runs, which is any CPU without AES instructions and any target other
//! than `aarch64` and `x86_64`. Unlike the SHA-2 functions, whose work and
//! memory accesses never depend on the message, AES on `scalar` leaks.
//!
//! # Example
//!
//! ```
//! use cryptors::{BlockCipher, aes::{Aes128, Aes256}};
//!
//! // FIPS 197, Appendix B.
//! let key = [
//!     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
//! ];
//! let plaintext = [
//!     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
//! ];
//!
//! let cipher = Aes128::new(&key);
//! let ciphertext: [u8; 16] = cipher.encrypt_block(&plaintext);
//! assert_eq!(
//!     ciphertext,
//!     [
//!         0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
//!         0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
//!     ]
//! );
//! assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);
//!
//! // The three key sizes are three types with the same interface, and a
//! // longer key is a different permutation, not an extension of a shorter one.
//! assert_eq!(Aes128::KEY_LEN, 16);
//! assert_eq!(Aes256::KEY_LEN, 32);
//! let other = Aes256::new(&[0; 32]).encrypt_block(&plaintext);
//! assert_ne!(other, ciphertext);
//! ```

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod cipher;
mod scalar;
mod schedule;
#[cfg(target_arch = "x86_64")]
mod x86;

pub use cipher::{Aes128, Aes192, Aes256};
