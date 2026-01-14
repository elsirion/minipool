#!/usr/bin/env bash
# Run minipool locally using Bitcoin Core cookie authentication
# Usage: ./run-local.sh [options]
#
# Options:
#   --bind-addr ADDR   Address to bind to (default: 127.0.0.1:9090)
#   --bitcoin-dir DIR  Bitcoin data directory (default: ~/.bitcoin)
#   --testnet          Use testnet
#   --signet           Use signet
#   --regtest          Use regtest
#   --release          Run release build
#   --build            Build before running
#   -h, --help         Show this help

set -e

BIND_ADDR="127.0.0.1:9090"
PROMETHEUS_ADDR="[::]:9091"
BITCOIN_DIR="$HOME/.bitcoin"
NETWORK=""
RELEASE=""
BUILD=""
RPC_PORT=8332

show_help() {
    head -14 "$0" | tail -13 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --bind-addr)
            BIND_ADDR="$2"
            shift 2
            ;;
        --bitcoin-dir)
            BITCOIN_DIR="$2"
            shift 2
            ;;
        --testnet)
            NETWORK="testnet3"
            RPC_PORT=18332
            shift
            ;;
        --signet)
            NETWORK="signet"
            RPC_PORT=38332
            shift
            ;;
        --regtest)
            NETWORK="regtest"
            RPC_PORT=18443
            shift
            ;;
        --release)
            RELEASE="--release"
            shift
            ;;
        --build)
            BUILD="1"
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Determine cookie file location
if [ -n "$NETWORK" ]; then
    COOKIE_FILE="$BITCOIN_DIR/$NETWORK/.cookie"
else
    COOKIE_FILE="$BITCOIN_DIR/.cookie"
fi

# Check if cookie file exists
if [ ! -f "$COOKIE_FILE" ]; then
    echo "Error: Cookie file not found at $COOKIE_FILE"
    echo ""
    echo "Make sure Bitcoin Core is running."
    if [ -n "$NETWORK" ]; then
        echo "  bitcoind -$NETWORK"
    else
        echo "  bitcoind"
    fi
    exit 1
fi

# Read cookie credentials
COOKIE=$(cat "$COOKIE_FILE")
RPC_USER="${COOKIE%%:*}"
RPC_PASS="${COOKIE#*:}"

# Determine RPC URL
RPC_URL="http://127.0.0.1:$RPC_PORT"

echo "Starting minipool..."
echo "  Bitcoin RPC: $RPC_URL"
echo "  Cookie file: $COOKIE_FILE"
echo "  Bind address: $BIND_ADDR"
[ -n "$NETWORK" ] && echo "  Network: $NETWORK"
echo ""

# Build if requested
if [ -n "$BUILD" ]; then
    echo "Building..."
    cargo build $RELEASE
    echo ""
fi

# Run minipool
exec cargo run $RELEASE -- \
    --bitcoin-rpc-url "$RPC_URL" \
    --bitcoin-rpc-user "$RPC_USER" \
    --bitcoin-rpc-pass "$RPC_PASS" \
    --bind-addr "$BIND_ADDR" \
    --prometheus-bind-addr "$PROMETHEUS_ADDR"
