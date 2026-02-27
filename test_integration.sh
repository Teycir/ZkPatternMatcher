#!/usr/bin/env bash
# Integration smoke tests for the current zkpm CLI and stable pattern packs.

set -e

PATTERNS_DIR="patterns"
CIRCUITS_DIR="tests/real_vulnerabilities"
RESULTS_FILE="integration_test_results.txt"
PASS=0
FAIL=0

echo "=== ZkPatternMatcher Integration Test ===" > "$RESULTS_FILE"
echo "Testing stable pattern packs with current CLI interface" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

run_case() {
  local name="$1"
  local pattern="$2"
  local target="$3"
  local expected="$4"

  echo "$name" | tee -a "$RESULTS_FILE"
  local output
  output=$(cargo run --release --bin zkpm -- "$pattern" "$target" 2>&1 || true)
  echo "$output" >> "$RESULTS_FILE"

  if grep -Fq "$expected" <<<"$output"; then
    echo "✓ PASS: found '$expected'" | tee -a "$RESULTS_FILE"
    PASS=$((PASS + 1))
  else
    echo "✗ FAIL: missing '$expected'" | tee -a "$RESULTS_FILE"
    FAIL=$((FAIL + 1))
  fi
  echo "" >> "$RESULTS_FILE"
}

run_case \
  "[1/5] Signal aliasing pack" \
  "$PATTERNS_DIR/signal_aliasing.yaml" \
  "$CIRCUITS_DIR/signal_aliasing.circom" \
  "intermediate_array_unconstrained"

run_case \
  "[2/5] Unchecked division pack" \
  "$PATTERNS_DIR/unchecked_division.yaml" \
  "$CIRCUITS_DIR/unchecked_division.circom" \
  "division_operator_detected"

run_case \
  "[3/5] Real vulnerabilities pack (underconstrained)" \
  "$PATTERNS_DIR/real_vulnerabilities.yaml" \
  "$CIRCUITS_DIR/underconstrained_multiplier.circom" \
  "underconstrained_assignment"

run_case \
  "[4/5] Real vulnerabilities pack (weak nullifier)" \
  "$PATTERNS_DIR/real_vulnerabilities.yaml" \
  "$CIRCUITS_DIR/weak_nullifier.circom" \
  "weak_nullifier_pattern"

run_case \
  "[5/5] Production pack marker detection" \
  "$PATTERNS_DIR/production.yaml" \
  "$CIRCUITS_DIR/nullifier_collision_real.circom" \
  "vulnerability_marker"

echo "[SARIF] Recursive scan smoke test" | tee -a "$RESULTS_FILE"
sarif_output=$(cargo run --release --bin zkpm -- --format sarif -r \
  "$PATTERNS_DIR/real_vulnerabilities.yaml" "$CIRCUITS_DIR" 2>&1 || true)
echo "$sarif_output" >> "$RESULTS_FILE"
if grep -Fq "\"ruleId\"" <<<"$sarif_output" && grep -Fq "\"uri\"" <<<"$sarif_output"; then
  echo "✓ PASS: SARIF contains rule IDs and artifact URIs" | tee -a "$RESULTS_FILE"
  PASS=$((PASS + 1))
else
  echo "✗ FAIL: SARIF missing expected fields" | tee -a "$RESULTS_FILE"
  FAIL=$((FAIL + 1))
fi

echo "" | tee -a "$RESULTS_FILE"
echo "=== Integration Test Complete ===" | tee -a "$RESULTS_FILE"
echo "Results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "Passed: $PASS  Failed: $FAIL" | tee -a "$RESULTS_FILE"

if [ "$FAIL" -eq 0 ]; then
  echo "✓ ALL INTEGRATION TESTS PASSED"
  exit 0
else
  echo "✗ INTEGRATION TESTS FAILED"
  exit 1
fi
