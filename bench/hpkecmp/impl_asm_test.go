//go:build !purego

package hpkecmp

// impl names what crypto/hpke runs on in this build: Go's assembly for
// AES-GCM and X25519 where it has some for the platform (AES and PMULL on
// arm64, AES-NI and PCLMULQDQ on amd64), its portable code elsewhere.
const impl = "Go crypto/hpke"
