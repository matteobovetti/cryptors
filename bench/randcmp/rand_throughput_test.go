// Throughput comparison counterpart to the Rust `throughput` test in
// src/rand/random.rs: same buffer sizes, same number of calls per pass, same
// warm-up and same best-of-5 methodology, so the reported figures are directly
// comparable.
//
// Five buffer sizes, filled with crypto/rand.Read:
//
//   - 16, 32 and 256 bytes, as a nonce, a salt, a key or a token is: the cost
//     of a call, reported in operations per second (and MiB/s).
//   - 4 KiB and 1 MiB, as a block of key material or a test input is: the cost
//     of a byte, reported in MiB/s.
//
// What is read is random, so unlike the other benchmarks there is no last value
// to print and compare; TestKnownAnswers checks what can be checked instead.
package randcmp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"
)

// bestRate runs pass once to warm up, then five times, and returns the best of
// the five in passes per second.
func bestRate(pass func()) float64 {
	// The first pass is slowed down by page faults and CPU clock ramp-up, not
	// just the generator itself, so it is not timed.
	pass()
	var best float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		pass()
		if rate := 1 / time.Since(start).Seconds(); rate > best {
			best = rate
		}
	}
	return best
}

func TestThroughput(t *testing.T) {
	const mib = 1 << 20

	// Small buffers: the cost of a call.
	for _, size := range []int{16, 32, 256} {
		const calls = 200_000
		buf := make([]byte, size)
		rate := bestRate(func() {
			for i := 0; i < calls; i++ {
				rand.Read(buf)
			}
		})
		fmt.Printf("rand fill %d bytes [Go crypto/rand]: %d per pass, best %.0f ops/s (%.1f MiB/s)\n",
			size, calls, rate*calls, rate*float64(calls*size)/mib)
	}

	// Large buffers: the cost of a byte.
	for _, c := range []struct{ size, calls int }{{4096, 20_000}, {1 << 20, 100}} {
		buf := make([]byte, c.size)
		rate := bestRate(func() {
			for i := 0; i < c.calls; i++ {
				rand.Read(buf)
			}
		})
		fmt.Printf("rand fill %d bytes [Go crypto/rand]: %d per pass, best %.1f MiB/s\n",
			c.size, c.calls, rate*float64(c.calls*c.size)/mib)
	}
}

// below is the table of `BELOW` in src/rand/random.rs: crypto/rand.Int, given
// these bytes by a reader, returns this number after reading this many. The
// Rust test pins the same rows, so the two implementations are held to each
// other, and to what Go does.
var below = []struct {
	max      uint64
	input    string
	want     uint64
	consumed int
}{
	{1, "", 0, 0},
	{2, "fe01", 0, 1},
	{2, "020300", 0, 1},
	{5, "fffefdfc", 4, 4},
	{5, "07060503", 3, 4},
	{6, "0705", 5, 2},
	{10, "ff0a0b0f09", 9, 5},
	{255, "fffe", 254, 2},
	{256, "abcd", 171, 1},
	{257, "ffff0101010002", 256, 6},
	{257, "03000101", 256, 2},
	{1000, "ffff03e803e7", 999, 6},
	{65536, "1234", 4660, 2},
	{65537, "ffffff010001010000", 65536, 9},
	{1 << 32, "deadbeef", 3_735_928_559, 4},
	{1<<32 + 1, "ffffffffff0100000000", 4_294_967_296, 10},
	{1 << 56, "ff123456789abcde", 71_796_135_059_561_148, 7},
	{1<<56 + 1, "ff123456789abcde00123456789abcde", 5_124_095_576_030_430, 16},
	{1 << 63, "ffffffffffffffff", 1<<63 - 1, 8},
	{1<<63 + 1, "ffffffffffffffff80000000000000018000000000000000", 1 << 63, 24},
	{math.MaxUint64, "fffffffffffffffe", math.MaxUint64 - 1, 8},
	{math.MaxUint64, "fffffffffffffffffffffffffffffffe", math.MaxUint64 - 1, 16},
}

// TestKnownAnswers checks that what is being timed really is the system's
// generator filling the whole buffer, so a broken build fails the run instead
// of passing as a throughput figure, and replays the `below` table.
func TestKnownAnswers(t *testing.T) {
	// Every byte of buffers of the sizes that are timed is written: a buffer of
	// 16 bytes or more that is all zeros has a probability of 2^-128.
	for _, size := range []int{16, 32, 256, 4096, 1 << 20} {
		buf := make([]byte, size)
		if n, err := rand.Read(buf); n != size || err != nil {
			t.Fatalf("Read(%d bytes) = %d, %v", size, n, err)
		}
		for i := 0; i < size; i += 16 {
			if bytes.Equal(buf[i:min(i+16, size)], make([]byte, min(16, size-i))) {
				t.Errorf("%d bytes: 16 zero bytes at %d", size, i)
			}
		}
	}

	// A megabyte looks random: every byte value about equally often (chi-square,
	// 255 degrees of freedom: mean 255, standard deviation 22.6) and as many
	// ones as zeros in the bits (standard deviation 1448 in 8,388,608).
	buf := make([]byte, 1<<20)
	rand.Read(buf)
	var counts [256]int
	var ones int
	for _, b := range buf {
		counts[b]++
		for ; b != 0; b &= b - 1 {
			ones++
		}
	}
	expected := float64(len(buf)) / 256
	var chi float64
	for _, c := range counts {
		chi += (float64(c) - expected) * (float64(c) - expected) / expected
	}
	if chi < 120 || chi > 400 {
		t.Errorf("chi-square %.1f", chi)
	}
	if d := ones - len(buf)*4; d > 8688 || d < -8688 {
		t.Errorf("%d ones of %d bits", ones, len(buf)*8)
	}

	// Two draws are never alike.
	a, b := make([]byte, 32), make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	if bytes.Equal(a, b) {
		t.Errorf("two draws of 32 bytes are both %x", a)
	}

	// Text is 26 characters of the RFC 4648 alphabet.
	text := rand.Text()
	if len(text) != 26 {
		t.Errorf("Text() = %q, want 26 characters", text)
	}
	for _, c := range text {
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			t.Errorf("Text() = %q has %q", text, c)
		}
	}

	for _, c := range below {
		input, err := hex.DecodeString(c.input)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(input)
		got, err := rand.Int(r, new(big.Int).SetUint64(c.max))
		if err != nil {
			t.Errorf("Int(%d, %s): %v", c.max, c.input, err)
			continue
		}
		if !got.IsUint64() || got.Uint64() != c.want || len(input)-r.Len() != c.consumed {
			t.Errorf("Int(%d, %s) = %s after %d bytes, want %d after %d",
				c.max, c.input, got, len(input)-r.Len(), c.want, c.consumed)
		}
	}
}
