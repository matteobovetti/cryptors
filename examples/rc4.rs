//! RC4 on the vectors of Wikipedia and RFC 6229, with three of the properties
//! that make it unsuitable: no nonce, no authentication, and a keystream that
//! is not random from its first bytes. **RC4 is broken**: this crate has it to
//! read data that already exists. Use AES (`examples/aes.rs`) for anything new.
//!
//! ```sh
//! cargo run --release --example rc4
//! ```

use cryptors::rc4::Rc4;

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Encrypts `plaintext` under `key`, checks the result against `ciphertext`,
/// decrypts it back with a fresh cipher, and prints the line.
fn known_answer(key: &[u8], plaintext: &[u8], ciphertext: &str) {
    let mut data = plaintext.to_vec();
    Rc4::new(key).unwrap().apply_keystream(&mut data);
    assert_eq!(hex(&data), ciphertext);

    Rc4::new(key).unwrap().apply_keystream(&mut data);
    assert_eq!(data, plaintext);
    println!(
        "key {:<8} {:<16} -> {ciphertext}",
        format!("{:?}", String::from_utf8_lossy(key)),
        format!("{:?}", String::from_utf8_lossy(plaintext)),
    );
}

fn main() {
    // The three examples of Wikipedia's article.
    known_answer(b"Key", b"Plaintext", "bbf316e8d940af0ad3");
    known_answer(b"Wiki", b"pedia", "1021bf0420");
    known_answer(b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5");

    // RFC 6229: the first 16 bytes of the keystream under the 40-bit key
    // 0102030405 (encrypting zeros shows the keystream itself), and the 16 at
    // offset 4096.
    let key = unhex("0102030405");
    let mut cipher = Rc4::new(&key).unwrap();
    let mut stream = [0u8; 16];
    cipher.apply_keystream(&mut stream);
    assert_eq!(hex(&stream), "b2396305f03dc027ccc3524a0a1118a8");
    println!("RFC 6229, key {}, offset 0: {}", hex(&key), hex(&stream));
    cipher.apply_keystream(&mut [0; 4096 - 16]);
    stream = [0; 16];
    cipher.apply_keystream(&mut stream);
    assert_eq!(hex(&stream), "ff25b58995996707e51fbdf08b34d875");
    println!("RFC 6229, key {}, offset 4096: {}", hex(&key), hex(&stream));

    // A message can be cut into pieces of any size: the keystream goes on.
    let mut cipher = Rc4::new(b"Secret").unwrap();
    let mut message = *b"Attack at dawn";
    for piece in message.chunks_mut(5) {
        cipher.apply_keystream(piece);
    }
    assert_eq!(hex(&message), "45a01f645fc35b383552544b9bf5");
    println!("the same message in pieces of 5 bytes gives the same ciphertext");

    // Weakness 1, no nonce: one key is one keystream, so two messages under it
    // reveal the XOR of the plaintexts. The key is not needed for that.
    let (first, second) = (*b"Attack at dawn", *b"Attack at dusk");
    let (mut a, mut b) = (first, second);
    Rc4::new(b"Secret").unwrap().apply_keystream(&mut a);
    Rc4::new(b"Secret").unwrap().apply_keystream(&mut b);
    let xor_of_ciphertexts: Vec<u8> = a.iter().zip(&b).map(|(x, y)| x ^ y).collect();
    let xor_of_plaintexts: Vec<u8> = first.iter().zip(&second).map(|(x, y)| x ^ y).collect();
    assert_eq!(xor_of_ciphertexts, xor_of_plaintexts);
    println!(
        "two messages under one key: ciphertexts XOR to {}, which is what the plaintexts XOR to",
        hex(&xor_of_ciphertexts)
    );

    // Weakness 2, no authentication: flipping a bit of the ciphertext flips the
    // same bit of the plaintext, and nothing notices. "dawn" becomes "dusk"
    // without the key.
    let mut forged = a;
    for (byte, (old, new)) in forged[10..]
        .iter_mut()
        .zip(first[10..].iter().zip(&second[10..]))
    {
        *byte ^= old ^ new;
    }
    Rc4::new(b"Secret").unwrap().apply_keystream(&mut forged);
    assert_eq!(&forged, b"Attack at dusk");
    println!(
        "a ciphertext altered without the key decrypts to {:?}",
        String::from_utf8_lossy(&forged)
    );

    // Weakness 3, the keystream is biased: its second byte is zero twice as
    // often as 1 in 256 (Mantin and Shamir, 2001). Count it over many keys.
    let keys = 1u32 << 16;
    let zeros = (0..keys)
        .filter(|&k| {
            let mut stream = [0u8; 2];
            Rc4::new(&k.to_le_bytes())
                .unwrap()
                .apply_keystream(&mut stream);
            stream[1] == 0
        })
        .count();
    println!(
        "second byte of the keystream is zero for {zeros} of {keys} keys; a uniform byte would give about {}",
        keys / 256
    );
    assert!(zeros > 3 * (keys as usize / 256) / 2);
}
