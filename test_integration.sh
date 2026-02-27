#!/usr/bin/env bash
# Integration test: Validate all patterns against real vulnerable circuits
# Tests fancy-regex, semantic analysis, and all 8 pattern files

set -e

PATTERNS_DIR="patterns"
CIRCUITS_DIR="tests/real_vulnerabilities"
RESULTS_FILE="integration_test_results.txt"

echo "=== ZkPatternMatcher Integration Test ===" > "$RESULTS_FILE"
echo "Testing 32 patterns across 8 YAML files" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Test 1: Signal aliasing patterns (3 patterns)
echo "[1/8] Testing signal_aliasing.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/signal_aliasing.circom" \
  --pattern "$PATTERNS_DIR/signal_aliasing.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 2: Equality check patterns (5 patterns)
echo "[2/8] Testing equality_check.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/equality_no_constraint.circom" \
  --pattern "$PATTERNS_DIR/equality_check.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 3: Missing IsZero patterns (3 patterns)
echo "[3/8] Testing missing_iszero.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/missing_iszero.circom" \
  --pattern "$PATTERNS_DIR/missing_iszero.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 4: Unchecked division patterns (3 patterns)
echo "[4/8] Testing unchecked_division.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/unchecked_division.circom" \
  --pattern "$PATTERNS_DIR/unchecked_division.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 5: Array bounds patterns (3 patterns)
echo "[5/8] Testing array_bounds.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/array_no_bounds.circom" \
  --pattern "$PATTERNS_DIR/array_bounds.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 6: Public input validation patterns (5 patterns)
echo "[6/8] Testing public_input_validation.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/missing_range_check.circom" \
  --pattern "$PATTERNS_DIR/public_input_validation.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 7: Merkle path patterns (5 patterns)
echo "[7/8] Testing merkle_path.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/underconstrained_merkle_real.circom" \
  --pattern "$PATTERNS_DIR/merkle_path.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test 8: Commitment soundness patterns (6 patterns)
echo "[8/8] Testing commitment_soundness.yaml..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/weak_nullifier.circom" \
  --pattern "$PATTERNS_DIR/commitment_soundness.yaml" \
  2>&1 | tee -a "$RESULTS_FILE"

# Test semantic analysis (2-pass scan)
echo "" >> "$RESULTS_FILE"
echo "=== Semantic Analysis Test ===" >> "$RESULTS_FILE"
echo "Testing orphaned_unconstrained_assignment detection..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/signal_aliasing.circom" \
  --semantic \
  2>&1 | tee -a "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "Testing component_input_aliasing detection..." | tee -a "$RESULTS_FILE"
cargo run --release --bin zkpm -- scan \
  "$CIRCUITS_DIR/merkle_path/unconstrained_direction_vuln.circom" \
  --semantic \
  2>&1 | tee -a "$RESULTS_FILE"

# Summary
echo "" >> "$RESULTS_FILE"
echo "=== Integration Test Complete ===" >> "$RESULTS_FILE"
echo "Results saved to: $RESULTS_FILE"
echo ""
echo "Expected findings:"
echo "  - signal_aliasing.yaml: component_port_assignment, intermediate_array_unconstrained"
echo "  - equality_check.yaml: comparison_instead_of_constraint, bare_hint_assignment"
echo "  - merkle_path.yaml: unconstrained_path_direction, merkle_root_comparison_not_constraint"
echo "  - commitment_soundness.yaml: nullifier_without_secret, commitment_not_exposed"
echo "  - Semantic: orphaned_unconstrained_assignment, component_input_aliasing"
