# IBC commitment paths, the SMT and its ICS-23 proofs

lints := "-D warnings -A clippy::manual_is_multiple_of -A clippy::too_many_arguments -A clippy::result_large_err"

default:
    @just --list

# everything CI runs, in CI's order
ci: fmt-check lint test audit

fmt:
    cargo +nightly fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --locked --all-targets -- {{lints}}

test:
    cargo test --locked

audit:
    cargo audit --file Cargo.lock

# what crates.io would receive, without sending it
package:
    cargo package --locked

clean:
    cargo clean
