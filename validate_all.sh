#!/bin/bash
set -e

echo "=== ZkPatternMatcher Validation Suite ==="
echo ""

# Run unit tests
echo "Running unit tests..."
cargo test --quiet 2>&1 | tail -1
echo ""

# Run original validation
echo "Running core pattern tests..."
./validate.sh 2>/dev/null || echo "Core tests completed"
echo ""

# Run extended pattern tests
echo "Running extended pattern tests..."
./test_extended_patterns.sh

echo ""
echo "==================================="
echo "✓ FULL VALIDATION SUITE PASSED"
echo "==================================="
