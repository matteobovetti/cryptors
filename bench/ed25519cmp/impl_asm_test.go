//go:build !purego

package ed25519cmp

// impl names what crypto/ed25519 runs in this build: assembly for the field
// multiplication on amd64 and for SHA-512 on amd64 and arm64, portable Go
// for everything else.
const impl = "Go crypto/ed25519"
