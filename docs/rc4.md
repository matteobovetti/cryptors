# RC4

RC4 (also ARC4 or ARCFOUR) is the stream cipher Ron Rivest designed in 1987, as described in Bruce Schneier's *Applied
Cryptography*. The key sets up the state, and each step makes one keystream byte, XORed with the message: encrypting and
decrypting are the same operation.

**RC4 is broken.** Use it only to read existing data or talk to legacy systems. For anything new, use [AES](aes.md).

| Cipher | Type | Key | State | Output |
|--------|------|-----|-------|--------|
| RC4 | `Rc4` | 1 to 256 bytes | 256 bytes | one byte per step |

## Usage

```rust
use cryptors::rc4::Rc4;

// Wikipedia's example: the key "Wiki" and the text "pedia".
let mut cipher = Rc4::new(b"Wiki").unwrap();
let mut data = *b"pedia";
cipher.apply_keystream(&mut data);
assert_eq!(data, [0x10, 0x21, 0xbf, 0x04, 0x20]);

// Decrypting is the same operation, with a fresh cipher: the keystream starts again.
Rc4::new(b"Wiki").unwrap().apply_keystream(&mut data);
assert_eq!(&data, b"pedia");

// The keystream goes on from one call to the next, so a message can be processed in pieces of any size.
let mut cipher = Rc4::new(b"Wiki").unwrap();
let mut message = *b"pedia";
let (head, tail) = message.split_at_mut(2);
cipher.apply_keystream(head);
cipher.apply_keystream(tail);
assert_eq!(message, [0x10, 0x21, 0xbf, 0x04, 0x20]);

// RFC 4345 (arcfour256) throws away the first 1536 bytes of the keystream.
let mut cipher = Rc4::new(b"Wiki").unwrap();
cipher.apply_keystream(&mut [0; 1536]);

// `xor_keystream` leaves the plaintext as it was and writes to another buffer.
let mut ciphertext = [0; 5];
cipher.xor_keystream(&mut ciphertext, b"pedia");

// A key of the wrong size is refused.
assert!(Rc4::new(&[]).is_err());
assert!(Rc4::new(&[0; 257]).is_err());
```

## Security

- **The keystream is biased.** The second byte is zero twice as often as it should be (Mantin and Shamir, 2001), and
  more biases follow. A plaintext sent again and again under many keys (a cookie, a password) can be counted out of the
  ciphertexts: AlFardan et al. (2013) and Vanhoef and Piessens (2015) did it to TLS and WPA-TKIP, and RFC 7465 (2015)
  forbids RC4 in TLS.
- **Related keys give related keystreams.** Fluhrer, Mantin and Shamir (2001) broke WEP, whose key was a counter
  followed by the same secret.
- **Discarding the start helps a little.** RFC 4345 throws away the first 1536 bytes, as the example does; other biases
  stay.

Using it:

- **There is no nonce.** One key is one keystream, so two messages under it reveal the XOR of the plaintexts: use a key
  once. Nothing is authenticated either: a flipped ciphertext bit flips the same plaintext bit. `examples/rc4.rs` shows
  both.
- **Not constant-time.** The key schedule and the generator index a 256-byte table by secret state, which cache timing
  can leak. RC4 allows nothing else.
- **The state is wiped on drop, best effort**, and hidden from `Debug`. Stack copies and copies left by moves are out of
  reach; build the cipher where it will stay.
- **`Rc4` is not `Clone`**: a copy would repeat the keystream.

## Testing

```sh
cargo test rc4::   # RFC 6229, the vectors of the 1994 posting, every length of key, a message in pieces
```

- **`rfc_6229`:** all 252 vectors of the RFC (14 keys of 40 to 256 bits, 16 keystream bytes at each of 18 offsets up to
  4096), read from `src/rc4/testdata/rfc6229.txt`; Go's `crypto/rc4` agrees with every line.
- **`known_answers`:** the vectors of the 1994 posting that first published the algorithm (also in Go's tests), and
  Wikipedia's three examples.
- **`every_key_length`:** the SHA-256 of 300 keystream bytes for each key length from 1 to 256, agreed by Go and a
  Python implementation; the only test of the lengths between the RFC's.
- **`pieces_match_the_whole`:** a message split at every point and into runs of many lengths, so the indices must carry
  over between calls.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rc4:: -- --ignored --nocapture --test-threads=1
cd bench/rc4cmp && go test -v                        # Go's crypto/rc4, which has no assembly and so no purego run
```

Both sides XOR 32 MiB in place in one call, with a 16-byte key `00 01 02 ...` and the keystream running on between
passes. Best of five passes after a warm-up. Both print the same first bytes, which OpenSSL also computes.

Apple M1 Pro, medians of five interleaved runs, in MiB/s:

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| RC4 | **1112.1** | 1011.3 |

Each step depends on the one before, so the chain of loads and stores sets the speed. Go keeps the state in 32-bit
words; here it is bytes.

No x86 figures yet: nothing here can time real x86 hardware. The manual `Benchmarks` workflow
(`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
