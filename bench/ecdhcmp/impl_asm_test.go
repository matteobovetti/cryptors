//go:build !purego

package ecdhcmp

// impl names what crypto/ecdh runs in this build: its assembly where Go has
// some for the platform (P-256 on amd64, arm64, ppc64le and s390x; the field
// arithmetic of X25519 on amd64), its portable code elsewhere. P-384 and P-521
// are portable code everywhere.
const impl = "Go crypto/ecdh"
