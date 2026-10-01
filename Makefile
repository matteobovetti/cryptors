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
# one names the backend it selected on this machine.
bench-throughput:
	cargo test --release -- --ignored --nocapture

# The Go standard-library counterparts, same buffer sizes and methodology.
bench-go:
	cd bench/sha1cmp && go test -v
	cd bench/md5cmp && go test -v

audit:
	cargo audit

publish-dry-run:
	cargo publish --dry-run

publish:
	cargo publish

ci: fmt-check lint check test
