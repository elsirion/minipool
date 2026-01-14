# Minipool development commands

# List available commands (default)
default:
    @just --list

# Run minipool locally using Bitcoin Core cookie auth
run *args:
    ./scripts/run-local.sh {{args}}

# Run endpoint tests against minipool
test url:
    ./scripts/test-endpoints.sh {{url}}

# Build the project
build:
    cargo build

# Build release
build-release:
    cargo build --release

# Run clippy
lint:
    cargo clippy

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt --check

# Run all checks (build, lint, format)
check: build lint fmt-check

# Start minipool and run tests
run-and-test:
    #!/usr/bin/env bash
    cleanup() {
        echo "Stopping minipool..."
        kill $pid 2>/dev/null || true
        wait $pid 2>/dev/null || true
    }
    trap cleanup EXIT
    echo "Starting minipool..."
    ./scripts/run-local.sh &
    pid=$!
    sleep 5
    echo "Running tests..."
    ./scripts/test-endpoints.sh
    test_result=$?
    exit $test_result
