#!/bin/sh
# Everything a change must pass.
set -eu
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo clippy --all-targets -- -D warnings
results=$(mktemp)
cargo test --features test-hooks > "$results" 2>&1 || { cat "$results"; exit 1; }
grep -q '^test result: ok\. [1-9]' "$results" || { cat "$results"; echo "no tests ran"; exit 1; }
