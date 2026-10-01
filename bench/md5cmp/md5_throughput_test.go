// Throughput comparison counterpart to the Rust `throughput` test in
// src/md5/digest.rs: same buffer size, message split, warm-up, and best-of-5
// methodology, so the reported MiB/s numbers are directly comparable.
//
// Both figures below call Go's crypto/md5 one message at a time, because that
// is all its API offers -- there is no multi-buffer MD5 in the Go standard
// library. The second figure exists so that the batch comparison is apples to
// apples on input shape: it is the same 1024 messages the Rust batch test
// hashes, and the difference against cryptors' `digest_many` is precisely what
// filling SIMD lanes with independent messages buys.
package md5cmp

import (
	"crypto/md5"
	"fmt"
	"testing"
	"time"
)

const (
	total   = 64 * 1024 * 1024
	msgSize = 64 * 1024
)

func TestThroughput(t *testing.T) {
	data := make([]byte, total)
	for i := range data {
		data[i] = 0x61
	}
	mib := float64(len(data)) / (1024.0 * 1024.0)

	// Single message. Warm up first: a cold pass over a fresh buffer measures
	// page faults as much as MD5 itself.
	warm := md5.Sum(data)
	_ = warm

	var single float64
	var digest [16]byte
	for i := 0; i < 5; i++ {
		start := time.Now()
		digest = md5.Sum(data)
		if tp := mib / time.Since(start).Seconds(); tp > single {
			single = tp
		}
	}
	fmt.Printf("md5 single [Go crypto/md5]: %.0f MiB, best %.1f MiB/s (digest %x)\n",
		mib, single, digest)

	// Batch: the same 64 MiB split into independent messages, hashed in a loop.
	messages := make([][]byte, 0, total/msgSize)
	for off := 0; off+msgSize <= len(data); off += msgSize {
		messages = append(messages, data[off:off+msgSize])
	}
	sumAll(messages)

	var batch float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		sumAll(messages)
		if tp := mib / time.Since(start).Seconds(); tp > batch {
			batch = tp
		}
	}
	fmt.Printf("md5 batch [Go crypto/md5, sequential]: %d x %d KiB = %.0f MiB, "+
		"best %.1f MiB/s (%.2fx single)\n",
		len(messages), msgSize/1024, mib, batch, batch/single)
}

func sumAll(messages [][]byte) [][16]byte {
	out := make([][16]byte, len(messages))
	for i, m := range messages {
		out[i] = md5.Sum(m)
	}
	return out
}
