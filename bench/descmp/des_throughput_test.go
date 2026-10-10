// Throughput comparison counterpart to the Rust `throughput` test in
// src/des/cipher.rs: same buffer size, same input, same warm-up, and same
// best-of-5 methodology, so the reported MiB/s numbers are directly
// comparable.
//
// A block cipher transforms one 8-byte block per call, so the buffer is
// processed block by block, each block independent of the others (ECB, with no
// mode of operation on top), through the cipher.Block interface the way a
// caller would use it. The data is transformed in place and the passes are not
// undone, so the first block printed at the end identifies the whole run. It is
// the same for every implementation that is correct, and the Rust test prints
// the same figure for the same input.
//
// crypto/des is portable Go on every platform: it has no assembly, so unlike
// crypto/aes there is no `-tags purego` counterpart to run, and one Go figure
// stands against the one Rust implementation.
//
// Any GODEBUG setting is appended to the label, so such a run cannot be
// mistaken for the default one.
package descmp

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

// impl names what is being timed.
const impl = "Go crypto/des"

func TestThroughput(t *testing.T) {
	const size = 32 * 1024 * 1024

	// Block i starts the byte pattern at 8*i, as in the Rust test.
	pattern := make([]byte, size)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	data := make([]byte, size)
	mib := float64(size) / (1024.0 * 1024.0)

	label := impl
	if godebug := os.Getenv("GODEBUG"); godebug != "" {
		label += ", GODEBUG=" + godebug
	}

	ciphers := []struct {
		name   string
		keyLen int
		new    func(key []byte) (cipher.Block, error)
	}{
		{"des", 8, des.NewCipher},
		{"tdea", 24, des.NewTripleDESCipher},
	}
	for _, c := range ciphers {
		key := make([]byte, c.keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		block, err := c.new(key)
		if err != nil {
			t.Fatal(err)
		}

		directions := []struct {
			name string
			run  func(dst, src []byte)
		}{
			{"encrypt", block.Encrypt},
			{"decrypt", block.Decrypt},
		}
		for _, d := range directions {
			pass := func() {
				for off := 0; off < len(data); off += des.BlockSize {
					b := data[off : off+des.BlockSize]
					d.run(b, b)
				}
			}

			// Warm up: a cold pass over a fresh buffer measures page faults as
			// much as the cipher itself.
			copy(data, pattern)
			pass()

			var best float64
			for i := 0; i < 5; i++ {
				start := time.Now()
				pass()
				if tp := mib / time.Since(start).Seconds(); tp > best {
					best = tp
				}
			}
			fmt.Printf("%s %s [%s]: %.0f MiB, best %.1f MiB/s (first block %x...)\n",
				c.name, d.name, label, mib, best, data[:des.BlockSize])
		}
	}
}

// TestKnownAnswers checks that the function being timed really is DES and
// TDEA, with the ECB example of FIPS 81 (the key 0123456789abcdef and the text
// "Now is the time for all "), so a mislabelled or broken build fails the run
// instead of passing as a throughput figure. TDEA with three equal keys is
// single DES, so the same key bundle repeated three times gives the same
// ciphertext.
func TestKnownAnswers(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef")
	plaintext := []byte("Now is the time for all ")
	want := "3fa40e8a984d4815" + "6a271787ab8883f9" + "893d51ec4b563b53"

	tripleKey := append(append(append([]byte{}, key...), key...), key...)
	ciphers := []struct {
		name string
		new  func() (cipher.Block, error)
	}{
		{"DES", func() (cipher.Block, error) { return des.NewCipher(key) }},
		{"TDEA, three equal keys", func() (cipher.Block, error) { return des.NewTripleDESCipher(tripleKey) }},
	}
	for _, c := range ciphers {
		block, err := c.new()
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, len(plaintext))
		for off := 0; off < len(plaintext); off += des.BlockSize {
			block.Encrypt(got[off:off+des.BlockSize], plaintext[off:off+des.BlockSize])
		}
		if fmt.Sprintf("%x", got) != want {
			t.Errorf("%s encrypt = %x, want %s", c.name, got, want)
		}

		back := make([]byte, len(got))
		for off := 0; off < len(got); off += des.BlockSize {
			block.Decrypt(back[off:off+des.BlockSize], got[off:off+des.BlockSize])
		}
		if string(back) != string(plaintext) {
			t.Errorf("%s decrypt = %q, want the plaintext", c.name, back)
		}
	}
}
