# IBC commitment paths, the SMT and its ICS-23 proofs

lints := "-D warnings -A clippy::manual_is_multiple_of -A clippy::too_many_arguments -A clippy::result_large_err"

default:
    @just --list

# everything CI runs, in CI's order
ci: fmt-check lint test lean audit

fmt:
    cargo +nightly fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --locked --all-targets -- {{lints}}

test:
    cargo test --locked

# the proof primitives must build without a chain toolchain
lean:
    cargo build --locked --no-default-features

# both ignores reach us through soroban-client's reqwest 0.11, so they are in
# the chains feature only; the default-features-off build carries neither
audit:
    cargo audit --file Cargo.lock --ignore RUSTSEC-2026-0009 --ignore RUSTSEC-2026-0258

# what crates.io would receive, without sending it
package:
    cargo package --locked

clean:
    cargo clean
