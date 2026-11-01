#!/bin/sh
# Everything a change must pass.
set -eu
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo clippy --all-targets -- -D warnings
results=$(cargo test --features test-hooks 2>&1 | tee /dev/stderr | grep '^test result:')
echo "$results" | grep -q 'ok\. [1-9]' || { echo "no tests ran"; exit 1; }
