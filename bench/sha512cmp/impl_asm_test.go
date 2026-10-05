//go:build !purego

package sha512cmp

// impl names what crypto/sha512 runs in this build: its assembly where Go has
// one for the platform (AVX2 on amd64, the SHA-512 instructions on arm64), its
// portable code elsewhere.
const impl = "Go crypto/sha512"
