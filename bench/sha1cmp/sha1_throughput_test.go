// Throughput comparison counterpart to the Rust `throughput` test in
// src/sha/sha1.rs: same buffer size, warm-up, and best-of-5 methodology, so
// the reported MiB/s numbers are directly comparable.
package sha1cmp

import (
	"crypto/sha1"
	"fmt"
	"testing"
	"time"
)

func TestThroughput(t *testing.T) {
	const size = 64 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = 0x61
	}
	mib := float64(len(data)) / (1024.0 * 1024.0)

	// Warm up: a cold pass over a fresh buffer measures page faults as much
	// as SHA-1 itself.
	warm := sha1.Sum(data)
	_ = warm

	var best float64
	var digest [20]byte
	for i := 0; i < 5; i++ {
		start := time.Now()
		digest = sha1.Sum(data)
		elapsed := time.Since(start).Seconds()
		if throughput := mib / elapsed; throughput > best {
			best = throughput
		}
	}

	fmt.Printf("sha1 [Go crypto/sha1]: %.0f MiB, best %.1f MiB/s (digest %x)\n", mib, best, digest)
}
