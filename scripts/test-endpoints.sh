#!/usr/bin/env bash
# Test minipool endpoints against mempool.space and blockstream.info
# Usage: ./test-endpoints.sh [minipool_url]

set -e

MINIPOOL_URL="${1:-http://127.0.0.1:9090}"
MEMPOOL_URL="https://mempool.space"
BLOCKSTREAM_URL="https://blockstream.info"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test block hash (block 100000 - well-known testable block)
TEST_BLOCK_HASH="000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
TEST_BLOCK_HEIGHT="100000"

# Test transaction from block 100000
TEST_TXID="8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"

passed=0
failed=0
skipped=0

print_header() {
    echo ""
    echo "========================================"
    echo "$1"
    echo "========================================"
}

print_test() {
    echo -n "Testing: $1... "
}

print_pass() {
    echo -e "${GREEN}PASS${NC}"
    passed=$((passed + 1))
}

print_fail() {
    echo -e "${RED}FAIL${NC}"
    echo "  Expected: $1"
    echo "  Got: $2"
    failed=$((failed + 1))
}

print_skip() {
    echo -e "${YELLOW}SKIP${NC} - $1"
    skipped=$((skipped + 1))
}

compare_values() {
    local name="$1"
    local minipool="$2"
    local reference="$3"

    if [ "$minipool" = "$reference" ]; then
        print_pass
    else
        print_fail "$reference" "$minipool"
    fi
}

compare_binary() {
    local name="$1"
    local minipool_file="$2"
    local reference_file="$3"

    if diff -q "$minipool_file" "$reference_file" > /dev/null 2>&1; then
        print_pass
    else
        print_fail "binary match" "files differ ($(wc -c < "$minipool_file") vs $(wc -c < "$reference_file") bytes)"
    fi
}

# Check if minipool is running
print_header "Checking minipool availability"
print_test "minipool at $MINIPOOL_URL"
if curl -s --connect-timeout 5 "$MINIPOOL_URL/health" > /dev/null 2>&1; then
    print_pass
else
    echo -e "${RED}FAIL${NC}"
    echo "minipool is not running at $MINIPOOL_URL"
    echo ""
    echo "Start minipool with:"
    echo "  cargo run -- --bitcoin-rpc-url http://127.0.0.1:8332 \\"
    echo "               --bitcoin-rpc-user <user> \\"
    echo "               --bitcoin-rpc-pass <pass>"
    exit 1
fi

# Create temp directory for binary comparisons
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

print_header "Testing Block Endpoints"

# Test /api/block/:hash
print_test "/api/block/:hash (block info)"
minipool_block=$(curl -s "$MINIPOOL_URL/api/block/$TEST_BLOCK_HASH" 2>/dev/null | jq -r '.id // empty')
blockstream_block=$(curl -s "$BLOCKSTREAM_URL/api/block/$TEST_BLOCK_HASH" 2>/dev/null | jq -r '.id // empty')
if [ -n "$minipool_block" ] && [ -n "$blockstream_block" ]; then
    compare_values "block id" "$minipool_block" "$blockstream_block"
else
    print_skip "could not fetch block info"
fi

# Test /api/block/:hash (specific fields)
print_test "/api/block/:hash (height field)"
minipool_height=$(curl -s "$MINIPOOL_URL/api/block/$TEST_BLOCK_HASH" 2>/dev/null | jq -r '.height // empty')
if [ "$minipool_height" = "$TEST_BLOCK_HEIGHT" ]; then
    print_pass
else
    print_fail "$TEST_BLOCK_HEIGHT" "$minipool_height"
fi

# Test /api/block/:hash/raw (binary)
print_test "/api/block/:hash/raw (binary data)"
curl -s "$MINIPOOL_URL/api/block/$TEST_BLOCK_HASH/raw" > "$TMPDIR/minipool_block.bin" 2>/dev/null
curl -s "$BLOCKSTREAM_URL/api/block/$TEST_BLOCK_HASH/raw" > "$TMPDIR/blockstream_block.bin" 2>/dev/null
if [ -s "$TMPDIR/minipool_block.bin" ] && [ -s "$TMPDIR/blockstream_block.bin" ]; then
    compare_binary "block raw" "$TMPDIR/minipool_block.bin" "$TMPDIR/blockstream_block.bin"
else
    print_skip "could not fetch raw block"
fi

# Test /api/block/:hash/raw content-type
print_test "/api/block/:hash/raw (content-type header)"
content_type=$(curl -sI "$MINIPOOL_URL/api/block/$TEST_BLOCK_HASH/raw" 2>/dev/null | grep -i "content-type" | tr -d '\r' | awk '{print $2}')
if [ "$content_type" = "application/octet-stream" ]; then
    print_pass
else
    print_fail "application/octet-stream" "$content_type"
fi

# Test /api/block/:hash/header
print_test "/api/block/:hash/header"
minipool_header=$(curl -s "$MINIPOOL_URL/api/block/$TEST_BLOCK_HASH/header" 2>/dev/null)
blockstream_header=$(curl -s "$BLOCKSTREAM_URL/api/block/$TEST_BLOCK_HASH/header" 2>/dev/null)
if [ -n "$minipool_header" ] && [ -n "$blockstream_header" ]; then
    compare_values "block header" "$minipool_header" "$blockstream_header"
else
    print_skip "could not fetch block header"
fi

# Test /api/block-height/:height
print_test "/api/block-height/:height"
minipool_hash=$(curl -s "$MINIPOOL_URL/api/block-height/$TEST_BLOCK_HEIGHT" 2>/dev/null)
blockstream_hash=$(curl -s "$BLOCKSTREAM_URL/api/block-height/$TEST_BLOCK_HEIGHT" 2>/dev/null)
if [ -n "$minipool_hash" ] && [ -n "$blockstream_hash" ]; then
    compare_values "block hash at height" "$minipool_hash" "$blockstream_hash"
else
    print_skip "could not fetch block by height"
fi

# Test /api/blocks/tip/height
print_test "/api/blocks/tip/height (tip height)"
minipool_tip=$(curl -s "$MINIPOOL_URL/api/blocks/tip/height" 2>/dev/null)
blockstream_tip=$(curl -s "$BLOCKSTREAM_URL/api/blocks/tip/height" 2>/dev/null)
if [ -n "$minipool_tip" ] && [ -n "$blockstream_tip" ]; then
    # Allow some variance due to timing
    diff=$((minipool_tip - blockstream_tip))
    if [ "$diff" -ge -2 ] && [ "$diff" -le 2 ]; then
        print_pass
        echo "  (minipool: $minipool_tip, blockstream: $blockstream_tip, diff: $diff)"
    else
        print_fail "within 2 blocks of $blockstream_tip" "$minipool_tip"
    fi
else
    print_skip "could not fetch tip height"
fi

# Test /api/blocks/tip/hash
print_test "/api/blocks/tip/hash (tip hash format)"
minipool_tip_hash=$(curl -s "$MINIPOOL_URL/api/blocks/tip/hash" 2>/dev/null)
if [[ "$minipool_tip_hash" =~ ^[0-9a-f]{64}$ ]]; then
    print_pass
else
    print_fail "64 hex characters" "$minipool_tip_hash"
fi

print_header "Testing Transaction Endpoints"

# Test /api/tx/:txid
print_test "/api/tx/:txid (transaction info)"
minipool_tx=$(curl -s "$MINIPOOL_URL/api/tx/$TEST_TXID" 2>/dev/null | jq -r '.txid // empty')
blockstream_tx=$(curl -s "$BLOCKSTREAM_URL/api/tx/$TEST_TXID" 2>/dev/null | jq -r '.txid // empty')
if [ -n "$minipool_tx" ] && [ -n "$blockstream_tx" ]; then
    compare_values "txid" "$minipool_tx" "$blockstream_tx"
else
    print_skip "could not fetch transaction"
fi

# Test /api/tx/:txid/merkle-proof
print_test "/api/tx/:txid/merkle-proof"
minipool_proof=$(curl -s "$MINIPOOL_URL/api/tx/$TEST_TXID/merkle-proof" 2>/dev/null | jq -r '.block_height // empty')
blockstream_proof=$(curl -s "$BLOCKSTREAM_URL/api/tx/$TEST_TXID/merkle-proof" 2>/dev/null | jq -r '.block_height // empty')
if [ -n "$minipool_proof" ] && [ -n "$blockstream_proof" ]; then
    compare_values "merkle proof block_height" "$minipool_proof" "$blockstream_proof"
else
    print_skip "could not fetch merkle proof"
fi

# Test /api/tx/:txid/merkleblock-proof
print_test "/api/tx/:txid/merkleblock-proof (binary)"
curl -s "$MINIPOOL_URL/api/tx/$TEST_TXID/merkleblock-proof" > "$TMPDIR/minipool_merkle.bin" 2>/dev/null
curl -s "$BLOCKSTREAM_URL/api/tx/$TEST_TXID/merkleblock-proof" > "$TMPDIR/blockstream_merkle.bin" 2>/dev/null
if [ -s "$TMPDIR/minipool_merkle.bin" ] && [ -s "$TMPDIR/blockstream_merkle.bin" ]; then
    compare_binary "merkleblock proof" "$TMPDIR/minipool_merkle.bin" "$TMPDIR/blockstream_merkle.bin"
else
    print_skip "could not fetch merkleblock proof"
fi

print_header "Testing Fee Estimates"

# Test /api/fee-estimates
print_test "/api/fee-estimates (format check)"
minipool_fees=$(curl -s "$MINIPOOL_URL/api/fee-estimates" 2>/dev/null)
if echo "$minipool_fees" | jq -e 'has("1") and has("6") and has("144")' > /dev/null 2>&1; then
    print_pass
else
    print_fail "JSON with keys 1, 6, 144" "$minipool_fees"
fi

print_header "Testing Error Handling"

# Test invalid block hash
print_test "Invalid block hash returns 400"
status=$(curl -s -o /dev/null -w "%{http_code}" "$MINIPOOL_URL/api/block/invalid-hash")
if [ "$status" = "400" ]; then
    print_pass
else
    print_fail "400" "$status"
fi

# Test non-existent block
print_test "Non-existent block returns 404"
status=$(curl -s -o /dev/null -w "%{http_code}" "$MINIPOOL_URL/api/block/0000000000000000000000000000000000000000000000000000000000000000")
if [ "$status" = "404" ]; then
    print_pass
else
    print_fail "404" "$status"
fi

# Test invalid txid
print_test "Invalid txid returns 400"
status=$(curl -s -o /dev/null -w "%{http_code}" "$MINIPOOL_URL/api/tx/invalid-txid")
if [ "$status" = "400" ]; then
    print_pass
else
    print_fail "400" "$status"
fi

print_header "Summary"
echo ""
total=$((passed + failed + skipped))
echo -e "Total tests: $total"
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"
echo -e "${YELLOW}Skipped: $skipped${NC}"
echo ""

if [ "$failed" -gt 0 ]; then
    exit 1
fi
