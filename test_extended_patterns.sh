#!/bin/bash
set -e

echo "=== Extended Pattern Integration Tests ==="
echo ""

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
    "Test 1: Signal aliasing pattern pack" \
    "patterns/signal_aliasing.yaml" \
    "tests/real_vulnerabilities/signal_aliasing.circom" \
    "intermediate_array_unconstrained"

run_case \
    "Test 2: Unchecked division pattern pack" \
    "patterns/unchecked_division.yaml" \
    "tests/real_vulnerabilities/unchecked_division.circom" \
    "division_operator_detected"

run_case \
    "Test 3: Underconstrained pattern pack" \
    "patterns/underconstrained.yaml" \
    "tests/real_vulnerabilities/underconstrained_multiplier.circom" \
    "unconstrained_assignment"

run_case \
    "Test 4: Production marker detection" \
    "patterns/production.yaml" \
    "tests/real_vulnerabilities/nullifier_collision_real.circom" \
    "vulnerability_marker"

echo "Test 5: Safe circuit should avoid critical findings"
safe_output=$(cargo run --quiet -- patterns/real_vulnerabilities.yaml \
    tests/safe_circuits/safe_multiplier.circom 2>&1 || true)
if grep -Fq "[Critical]" <<<"$safe_output"; then
    echo "✗ FAIL: Safe circuit emitted critical findings"
    FAIL=$((FAIL + 1))
else
    echo "✓ PASS: No critical findings on safe circuit"
    PASS=$((PASS + 1))
fi
echo ""

echo "==================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==================================="

if [ "$FAIL" -eq 0 ]; then
    echo "✓ ALL EXTENDED PATTERN TESTS PASSED"
    exit 0
else
    echo "✗ SOME TESTS FAILED"
    exit 1
fi
