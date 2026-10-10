//! From-scratch implementation of the Data Encryption Standard (DES) and the
//! Triple Data Encryption Algorithm (TDEA), as FIPS 46-3 defines them. **DES is
//! broken and TDEA is obsolete.** This module is for reading data that already
//! exists and for talking to systems that have not moved on; use AES
//! ([`aes`](crate::aes)) for anything new.
//!
//! | Cipher | Type | Key | Block | Rounds |
//! |--------|------|-----|-------|--------|
//! | DES | [`Des`] | 8 bytes, 56 bits of which count | 8 bytes | 16 |
//! | TDEA | [`TripleDes`] | 24 bytes: three DES keys | 8 bytes | 3 x 16 |
//!
//! Both implement [`BlockCipher`](crate::BlockCipher).
//!
//! # Security
//!
//! **DES has a 56-bit key, and trying every one is within reach.** In 1998 the
//! Electronic Frontier Foundation's DES Cracker, a machine built for under
//! US$250,000, found a key in 56 hours; the next January it did so in 22 hours
//! and 15 minutes with the help of distributed.net. Since 2006 a machine of
//! commodity FPGAs that costs under US$10,000 does the same in days. The
//! structural attacks on the full 16 rounds, differential and linear
//! cryptanalysis, need far more data than anyone has (2^47 chosen or 2^43 known
//! plaintexts) and have never mattered next to the short key. NIST withdrew
//! FIPS 46-3 on 19 May 2005.
//!
//! **TDEA is stronger, and still not acceptable.** It has three keys of 56
//! bits, but a meet-in-the-middle attack brings it down to about 112 bits, and
//! NIST rates two-key TDEA at no more than 80. The larger problem is the block:
//! at 64 bits, two ciphertext blocks are equal by chance after about 2^32
//! blocks (32 GiB) under one key, and in the usual modes that tells an attacker
//! the XOR of the two plaintexts. The Sweet32 attack (2016) used this against
//! TDEA in TLS and recovered a secret cookie from some 600 GB of traffic. NIST
//! capped a key bundle at 2^20 blocks (8 MiB), no longer allows TDEA to protect
//! data, and withdrew its specification, SP 800-67, on 1 January 2024. It still
//! allows decrypting data that was protected earlier, which is what this
//! module is for.
//!
//! # How it works
//!
//! DES is a Feistel network. The 64-bit block goes through a fixed permutation,
//! `IP`, and is split into two halves, `L` and `R`. Sixteen rounds follow; in
//! each, the new right half is `L` XOR `f(R, K)`, the old right half becomes the
//! new left one, and `K` is that round's key of 48 bits. The halves are then
//! swapped once more and go through the inverse of `IP`. The cipher function `f`
//! does the cryptographic work:
//!
//! - **E** expands the 32-bit half to 48 bits by repeating some of its bits.
//! - The round key is XORed in.
//! - Eight **S-boxes** each replace six bits by four, through a table fixed by
//!   the standard. They are the only step that is not linear.
//! - **P** permutes the resulting 32 bits.
//!
//! Because each round only needs `f` and an XOR, the same circuit that
//! encrypts also decrypts, with the round keys in the opposite order. The round
//! keys come from the key by the key schedule: `PC-1` drops the eight parity
//! bits (the last bit of every byte) and splits the other 56 into two halves of
//! 28; before each round both are rotated left by one or two places, and `PC-2`
//! picks 48 of the 56 bits.
//!
//! TDEA runs DES three times, with three keys `K1`, `K2` and `K3`: it
//! **encrypts** under `K1`, **decrypts** under `K2` and **encrypts** under
//! `K3`. Decrypting in the middle is what keeps it compatible with DES:
//! when the three keys are the same, the first two steps cancel and what is left
//! is a single DES encryption. FIPS 46-3 allows three keying options for the
//! bundle `(K1, K2, K3)`, and [`TripleDes`] takes any of them:
//!
//! | Keying option | Bundle | Remarks |
//! |---------------|--------|---------|
//! | 1 | `K1`, `K2`, `K3` independent | the strongest |
//! | 2 | `K1`, `K2` independent, `K3 = K1` | "two-key" TDEA; 16 bytes of key material |
//! | 3 | `K1 = K2 = K3` | single DES, with a longer key |
//!
//! # Using it
//!
//! A block cipher is a building block, not an encryption scheme. It encrypts
//! one block, and a message takes a mode of operation on top, which this crate
//! does not have yet. Calling `encrypt_block` on every block of a message
//! independently (ECB) is not a safe mode: equal plaintext blocks give equal
//! ciphertext blocks, so the structure of the message shows through. Nor does
//! anything here authenticate: a ciphertext that has been altered decrypts to
//! something else without any error. The short block makes the choice of a
//! mode matter more than it does for AES.
//!
//! The last bit of every byte of a key is a parity bit. The standard sets it so
//! that every byte has an odd number of ones, and the algorithm does not use
//! it: two keys that differ only in those bits are the same key, and neither
//! the key nor its parity is checked. DES has four weak keys, each its own
//! inverse (encrypting twice returns the plaintext), and twelve semi-weak ones,
//! which come in pairs that undo each other. They are accepted like any other
//! key; a random key is one of them with a probability near 2^-52.
//!
//! A cipher holds its round keys, which are overwritten with zeros when it is
//! dropped, and its `Debug` output does not show them. The compiler's own
//! copies of them on the stack, while a key is expanded or a block is
//! processed, are out of reach of that, and so is the copy that moving a cipher
//! (into a `Box` or a `Vec`, say) can leave behind where it was. Where that
//! matters, build the cipher where it will stay.
//!
//! # Backends
//!
//! There is one implementation, `scalar`, and it runs on every CPU. None of the
//! instruction sets the crate has backends for, the x86-64 AES and SHA
//! extensions and the Arm cryptographic extensions, has an instruction for DES.
//! Nor does SIMD help with a block: a round needs the result of the one before
//! it, so the sixteen rounds are one chain. What does run fast on a vector
//! unit is DES in "bitslice" form, which encrypts as many blocks as there are
//! bits in a register, side by side; it needs an interface that takes many
//! blocks at once, and this one takes one.
//!
//! The scalar code folds the permutations of the standard into the rest, so a
//! round costs eight table lookups. `E` becomes two rotations of the half,
//! `P` is applied to the output of each S-box ahead of time, which merges the
//! S-boxes and `P` into eight tables of 64 words, and `IP` and its inverse are
//! five exchanges of pairs of bits each, with no table. TDEA also skips the
//! permutations between its three DES operations, where an inverse `IP` is
//! immediately followed by an `IP`. The tables are computed when the crate is
//! compiled, from the tables of the standard.
//!
//! ## Trust
//!
//! The tests check this against the standard from two sides. The published
//! vectors, and vectors from two independent implementations (which agree with
//! each other), pin down what it computes; and one more implementation, written
//! for the tests only, as slow and as literal as the text of FIPS 46-3,
//! computes the same round keys and the same blocks. TDEA is checked against
//! three runs of DES.
//!
//! ## Side channels
//!
//! `scalar` uses the state as an address: its lookups are at positions given by
//! the message and the key, and how long a lookup takes depends on whether the
//! CPU has that part of the table in its cache. The same measurement has
//! recovered AES keys from software that looks tables up, from a program on the
//! same core and, with more samples, from the response times of a server
//! across a network. The tables are small (2 KiB in all), which makes the
//! signal coarser, not absent. The key schedule only shifts and masks, and does
//! not index memory by the key. Unlike the SHA-2 functions, whose work and
//! memory accesses never depend on the message, DES here leaks.
//!
//! # Example
//!
//! ```
//! use cryptors::{BlockCipher, des::{Des, TripleDes}};
//!
//! // FIPS 81, the ECB example: the key 0123456789abcdef, the text "Now is t".
//! let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
//! let plaintext = *b"Now is t";
//!
//! let cipher = Des::new(&key);
//! let ciphertext: [u8; 8] = cipher.encrypt_block(&plaintext);
//! assert_eq!(ciphertext, [0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15]);
//! assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);
//!
//! // TDEA with three equal keys is single DES. Real use needs three
//! // different ones, and even then it is only for old data.
//! let bundle: Vec<u8> = key.iter().cycle().take(24).copied().collect();
//! let triple = TripleDes::new(bundle.as_slice().try_into().unwrap());
//! assert_eq!(triple.encrypt_block(&plaintext), ciphertext);
//! assert_eq!(TripleDes::KEY_LEN, 3 * Des::KEY_LEN);
//! ```

mod cipher;
#[cfg(test)]
mod reference;
mod scalar;
mod schedule;
mod tables;

pub use cipher::{Des, TripleDes};
