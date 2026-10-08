//go:build !purego

package aescmp

// impl names what crypto/aes runs in this build: its assembly where Go has one
// for the platform (AES-NI on amd64, the AES instructions on arm64), its
// portable code elsewhere.
const impl = "Go crypto/aes"
