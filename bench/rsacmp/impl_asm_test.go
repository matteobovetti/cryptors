//go:build !purego

package rsacmp

// impl names what crypto/rsa runs in this build. Its arithmetic
// (crypto/internal/fips140/bigmod) has the inner loop of Montgomery's product,
// the multiplication of a number by a word added to another, in assembly for
// numbers of exactly 1,024, 1,536 and 2,048 bits (the primes of keys of 2,048,
// 3,072 and 4,096 bits, and the modulus of a 2,048-bit key) on 386, amd64, arm,
// arm64, loong64, ppc64, ppc64le, riscv64 and s390x; for every other size, such
// as the modulus of a 3,072-bit key, it is portable code. The SHA-2 under OAEP
// and PSS is assembly where Go has some for the platform.
const impl = "Go crypto/rsa"
