#!/bin/bash
set -e

echo "=== Real Vulnerability Integration Tests ==="
echo ""

CORE="patterns/real_vulnerabilities.yaml"
PRODUCTION="patterns/production.yaml"
PASS=0
FAIL=0

run_case() {
    local name="$1"
    local pattern="$2"
    local circuit="$3"
    local expected="$4"

    echo "$name"
    local output
    output=$(cargo run --quiet -- "$pattern" "$circuit" 2>&1 || true)

    if grep -Fq "$expected" <<<"$output"; then
        echo "✓ PASS: Detected '$expected'"
        PASS=$((PASS + 1))
    else
        echo "✗ FAIL: Missing '$expected'"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_case \
    "Test 1: Underconstrained Multiplier" \
    "$CORE" \
    "tests/real_vulnerabilities/underconstrained_multiplier.circom" \
    "underconstrained_assignment"

run_case \
    "Test 2: Weak Nullifier Detection" \
    "$CORE" \
    "tests/real_vulnerabilities/weak_nullifier.circom" \
    "weak_nullifier_pattern"

run_case \
    "Test 3: Missing Range Check" \
    "$CORE" \
    "tests/real_vulnerabilities/missing_range_check.circom" \
    "no_range_check"

run_case \
    "Test 4: Nullifier Collision Marker (Production Pack)" \
    "$PRODUCTION" \
    "tests/real_vulnerabilities/nullifier_collision_real.circom" \
    "vulnerability_marker"

run_case \
    "Test 5: Arithmetic Overflow Marker (Production Pack)" \
    "$PRODUCTION" \
    "tests/real_vulnerabilities/arithmetic_overflow_real.circom" \
    "vulnerability_marker"

echo "==================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==================================="

if [ "$FAIL" -eq 0 ]; then
    echo "✓ ALL REAL VULNERABILITY TESTS PASSED"
    exit 0
else
    echo "✗ SOME TESTS FAILED"
    exit 1
fi
