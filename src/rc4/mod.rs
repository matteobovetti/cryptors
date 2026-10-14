//! From-scratch implementation of RC4, the stream cipher that Ron Rivest
//! designed for RSA Security in 1987, as Bruce Schneier's *Applied
//! Cryptography* describes it (it is also known as ARC4 or ARCFOUR). **RC4 is
//! broken.** This module is for reading data that already exists and for
//! talking to systems that have not moved on; use AES ([`aes`](crate::aes)) for
//! anything new.
//!
//! | Cipher | Type | Key | State | Output |
//! |--------|------|-----|-------|--------|
//! | RC4 | [`Rc4`] | 1 to 256 bytes | 256 bytes | one byte per step |
//!
//! # Security
//!
//! **The keystream is not random.** Its bytes are biased from the very first:
//! the second byte is zero with twice the probability of any other value
//! (Mantin and Shamir, 2001), and the bias is felt in the first few hundred
//! bytes and, more weakly, much further on. An attacker who sees the same
//! plaintext encrypted under many keys, which is what a protocol that sends a
//! cookie or a password with every connection gives them, recovers it from the
//! counts. Fluhrer, Mantin and Shamir (2001) showed that keys which share
//! all but a prefix of their bytes give related keystreams, and that broke WEP,
//! whose per-packet key was an initialisation vector followed by the same
//! secret. AlFardan et al. (2013) and Vanhoef and Piessens (2015) turned the
//! biases into practical attacks on TLS and on WPA-TKIP. RFC 7465 (2015)
//! forbids RC4 in TLS, and no current standard asks for it.
//!
//! **There is no nonce.** The same key always gives the same keystream, so two
//! messages encrypted under one key reveal the XOR of the plaintexts, and the
//! key has to change for every message. Mixing a counter into the key is how
//! WEP did it, and is what the attack above broke; hash the key and the nonce
//! together first, or use a cipher with a nonce.
//!
//! **Nothing here authenticates.** Flipping a bit of a ciphertext flips the
//! same bit of the plaintext, and a ciphertext that has been altered decrypts to
//! something else without any error.
//!
//! The advice that came out of the research is to discard the start of the
//! keystream: RFC 4345 asks for the first 1536 bytes to be thrown away, and
//! the example below shows how. It lessens the biases of the start and does not
//! remove the others.
//!
//! # How it works
//!
//! RC4 keeps a permutation `S` of the 256 byte values and two indices, `i` and
//! `j`, that are bytes and so wrap around at 256.
//!
//! - **The key schedule** starts with `S` as the identity (`S[k] = k`) and
//!   walks `i` through 0 to 255 once, with `j` starting at 0: `j` becomes
//!   `j + S[i] + key[i mod len]` (mod 256), and `S[i]` and `S[j]` swap. The key
//!   is used as many times over as it takes to cover the 256 steps.
//! - **The generator** makes a byte per step: `i` becomes `i + 1`, `j` becomes
//!   `j + S[i]`, `S[i]` and `S[j]` swap, and the output is `S[S[i] + S[j]]`.
//!   Nothing else changes: the state is the permutation and the two indices.
//!
//! The cipher XORs the message with the keystream, so decrypting is encrypting
//! again, from the start of the keystream, and the length of the output is the
//! length of the input.
//!
//! # Using it
//!
//! A cipher is built from a key and then carries on: [`Rc4::apply_keystream`]
//! takes the next bytes of the keystream, however a message is cut into calls.
//! A key shorter than one byte or longer than 256 is refused with
//! [`Error::InvalidKeyLen`]. Other keys are all accepted, those of the
//! cryptographic standards (5 to 16 bytes, 40 to 128 bits) among them; the
//! longer the better, but nothing makes up for the biases.
//!
//! The cipher is not `Clone`, because a copy would give the same keystream
//! again, and that is a mistake this type has no reason to make easy. It holds
//! the state, which is overwritten with zeros when it is dropped, and its
//! `Debug` output does not show it. The compiler's own copies of it on the stack
//! while a key is expanded, and the copy that moving a cipher (into a `Box` or
//! a `Vec`, say) can leave behind where it was, are out of reach of that. Where
//! that matters, build the cipher where it will stay.
//!
//! # Backends
//!
//! There is one implementation, and it runs on every CPU. No instruction set the
//! crate has backends for has an instruction for RC4, and the state forbids
//! SIMD: each step reads two positions that the step before it may have
//! swapped, and an index that comes out of the state, so the steps are one
//! chain and can neither run side by side nor be reordered. The stream cipher is
//! not a trait of the crate, as [`BlockCipher`](crate::BlockCipher) is for AES
//! and DES, because it is the only one.
//!
//! ## Trust
//!
//! The tests check this against the 252 vectors of RFC 6229 (14 keys of 40 to
//! 256 bits, at offsets up to 4096), the vectors of the 1994 posting that first
//! published the algorithm, and a SHA-256 of the keystream under every length of
//! key from 1 to 256 bytes, which two other implementations agree on. A third,
//! OpenSSL, computed the keystream of the throughput test.
//!
//! ## Side channels
//!
//! The key schedule and the generator use the state as an address: every access
//! is at a position that the key and the keystream determine, and how long it
//! takes depends on whether the CPU has that part of the 256-byte table in its
//! cache. The same kind of measurement has recovered AES keys from software that
//! looks tables up. Unlike the SHA-2 functions, whose work and memory accesses
//! never depend on the message, RC4 here leaks, and it is hard to see how any
//! RC4 could not.
//!
//! # Example
//!
//! ```
//! use cryptors::rc4::Rc4;
//!
//! // Wikipedia's example: the key "Wiki" and the text "pedia".
//! let mut cipher = Rc4::new(b"Wiki").unwrap();
//! let mut data = *b"pedia";
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [0x10, 0x21, 0xbf, 0x04, 0x20]);
//!
//! // Decrypting is the same operation, from the start of a keystream again.
//! let mut cipher = Rc4::new(b"Wiki").unwrap();
//! cipher.apply_keystream(&mut data);
//! assert_eq!(&data, b"pedia");
//!
//! // The keystream goes on from one call to the next, so a message can be
//! // processed in pieces of any size.
//! let mut cipher = Rc4::new(b"Wiki").unwrap();
//! let mut message = *b"pedia";
//! let (head, tail) = message.split_at_mut(2);
//! cipher.apply_keystream(head);
//! cipher.apply_keystream(tail);
//! assert_eq!(message, [0x10, 0x21, 0xbf, 0x04, 0x20]);
//!
//! // RFC 4345 (arcfour256) throws away the first 1536 bytes of the keystream.
//! let mut cipher = Rc4::new(b"Wiki").unwrap();
//! cipher.apply_keystream(&mut [0; 1536]);
//!
//! // `xor_keystream` leaves the plaintext as it was and writes to another buffer.
//! let plaintext = *b"pedia";
//! let mut ciphertext = [0; 5];
//! cipher.xor_keystream(&mut ciphertext, &plaintext);
//! assert_ne!(ciphertext, plaintext);
//!
//! // A key of the wrong size is refused.
//! assert!(Rc4::new(&[]).is_err());
//! assert!(Rc4::new(&[0; 257]).is_err());
//! ```

mod cipher;

pub use cipher::{Error, Rc4};
