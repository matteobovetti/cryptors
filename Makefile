.PHONY: all build release check test fmt fmt-check lint doc doc-open \
	clean bench bench-throughput bench-go audit publish-dry-run publish ci

all: fmt check lint test

build:
	cargo build --all

release:
	cargo build --all --release

check:
	cargo check --all

test:
	cargo test --all

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all -- -D warnings

doc:
	cargo doc --all --no-deps

doc-open:
	cargo doc --all --no-deps --open

clean:
	cargo clean

bench:
	cargo bench --all

# The throughput tests are `#[ignore]`d so that `make test` stays fast; each
# one names the backend it selected on this machine. One thread, because
# benchmarks timed side by side compete for the same cores and memory.
bench-throughput:
	cargo test --release -- --ignored --nocapture --test-threads=1

# The Go standard-library counterparts, same buffer sizes and methodology.
# `-tags purego` is Go's portable AES, ECDH, ECDSA, SHA-2 and SHA-3, the counterpart of
# our scalar backends (for ECDH and ECDSA, of our one implementation). On x86-64,
# `GODEBUG=cpu.sha=off` makes Go's SHA-256 skip SHA-NI and run its AVX2 path,
# the counterpart of our AVX2 backend; other architectures have no such path,
# so the run is skipped there. Go's DES is portable code on every platform, so
# it has no `purego` run.
bench-go:
	cd bench/aescmp && go test -v
	cd bench/aescmp && go test -tags purego -v
	cd bench/descmp && go test -v
	cd bench/ecdhcmp && go test -v
	cd bench/ecdhcmp && go test -tags purego -v
	cd bench/ecdsacmp && go test -v
	cd bench/ecdsacmp && go test -tags purego -v
	cd bench/sha1cmp && go test -v
	cd bench/md5cmp && go test -v
	cd bench/sha256cmp && go test -v
	cd bench/sha256cmp && go test -tags purego -v
	if [ "$$(go env GOARCH)" = amd64 ]; then cd bench/sha256cmp && GODEBUG=cpu.sha=off go test -v; fi
	cd bench/sha512cmp && go test -v
	cd bench/sha512cmp && go test -tags purego -v
	cd bench/sha3cmp && go test -v
	cd bench/sha3cmp && go test -tags purego -v

audit:
	cargo audit

publish-dry-run:
	cargo publish --dry-run

publish:
	cargo publish

ci: fmt-check lint check test
