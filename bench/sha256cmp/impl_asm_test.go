//go:build !purego

package sha256cmp

// impl names what crypto/sha256 runs in this build: its assembly where Go has
// one for the platform (SHA-NI or AVX2 on amd64, the SHA-2 instructions on
// arm64), its portable code elsewhere.
const impl = "Go crypto/sha256"
