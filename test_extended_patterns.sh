#!/bin/bash
set -e

echo "=== Extended Pattern Integration Tests ==="
echo ""

PATTERNS="patterns/extended_vulnerabilities.yaml"
PASS=0
FAIL=0

# Test 1: Signal Aliasing
echo "Test 1: Signal Aliasing Detection"
if cargo run --quiet -- "$PATTERNS" tests/real_vulnerabilities/signal_aliasing.circom 2>/dev/null | grep -q "signal_name_reuse\|array_access_no_bounds"; then
    echo "✓ PASS: Detected signal aliasing or array access issues"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Did not detect signal aliasing"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 2: Missing IsZero
echo "Test 2: Missing IsZero Detection"
if cargo run --quiet -- "$PATTERNS" tests/real_vulnerabilities/missing_iszero.circom 2>/dev/null | grep -q "missing_iszero_check\|equality_check_no_constraint"; then
    echo "✓ PASS: Detected missing IsZero or equality check"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Did not detect missing IsZero"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 3: Unchecked Division
echo "Test 3: Unchecked Division Detection"
if cargo run --quiet -- "$PATTERNS" tests/real_vulnerabilities/unchecked_division.circom 2>/dev/null | grep -q "unchecked_division"; then
    echo "✓ PASS: Detected unchecked division"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Did not detect unchecked division"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 4: Array No Bounds
echo "Test 4: Array Bounds Check Detection"
if cargo run --quiet -- "$PATTERNS" tests/real_vulnerabilities/array_no_bounds.circom 2>/dev/null | grep -q "array_access_no_bounds"; then
    echo "✓ PASS: Detected array access without bounds"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Did not detect array bounds issue"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 5: Equality Check
echo "Test 5: Equality Check Detection"
if cargo run --quiet -- "$PATTERNS" tests/real_vulnerabilities/equality_no_constraint.circom 2>/dev/null | grep -q "equality_check_no_constraint"; then
    echo "✓ PASS: Detected == instead of ==="
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Did not detect equality check issue"
    FAIL=$((FAIL + 1))
fi
echo ""

# Test 6: Safe circuit should have minimal findings
echo "Test 6: Safe Circuit (Low False Positives)"
FINDINGS=$(cargo run --quiet -- "$PATTERNS" tests/safe_circuits/safe_multiplier.circom 2>/dev/null | grep -c "Critical\|High" || true)
if [ "$FINDINGS" -lt 2 ]; then
    echo "✓ PASS: Safe circuit has $FINDINGS critical/high findings (acceptable)"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: Safe circuit has $FINDINGS critical/high findings (too many)"
    FAIL=$((FAIL + 1))
fi
echo ""

# Summary
echo "==================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==================================="

if [ $FAIL -eq 0 ]; then
    echo "✓ ALL EXTENDED PATTERN TESTS PASSED"
    exit 0
else
    echo "✗ SOME TESTS FAILED"
    exit 1
fi
