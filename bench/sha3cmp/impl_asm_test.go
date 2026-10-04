//go:build !purego

package sha3cmp

// impl names what crypto/sha3 runs in this build: its assembly where Go has
// one for the platform (amd64 always, arm64 on macOS), its portable code
// elsewhere.
const impl = "Go crypto/sha3"
