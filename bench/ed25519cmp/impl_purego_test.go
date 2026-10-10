//go:build purego

package ed25519cmp

// impl names what crypto/ed25519 runs in this build: portable Go throughout,
// SHA-512 included.
const impl = "Go crypto/ed25519, purego"
