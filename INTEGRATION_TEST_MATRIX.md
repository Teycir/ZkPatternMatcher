# Integration Test Validation Matrix

## Real Circuits → Expected Pattern Matches

### 1. signal_aliasing.circom
**Source**: Synthetic based on zkBugs array aliasing patterns  
**Expected Matches**:
- `intermediate_array_unconstrained` (MEDIUM) - Line 11-12: `intermediate[0] <--`, `intermediate[1] <--`
- **Semantic**: `orphaned_unconstrained_assignment` (CRITICAL) - intermediate[0], intermediate[1] never constrained

### 2. equality_no_constraint.circom
**Expected Matches**:
- `comparison_instead_of_constraint` (CRITICAL) - Uses `==` instead of `===`
- `bare_hint_assignment` (HIGH) - Unconstrained `<--` without paired `===`

### 3. missing_iszero.circom
**Expected Matches**:
- `missing_iszero_check` (MEDIUM) - Boolean selector without IsZero component
- `selector_not_binary` (HIGH) - Selector signal not constrained to {0,1}

### 4. unchecked_division.circom
**Expected Matches**:
- `division_without_zero_check` (HIGH) - Division operator without IsZero guard
- `inverse_without_constraint` (CRITICAL) - Inverse computation unconstrained

### 5. array_no_bounds.circom
**Expected Matches**:
- `array_access_no_bounds_check` (HIGH) - Array index without range validation
- `loop_bound_unchecked` (MEDIUM) - Loop variable not constrained

### 6. missing_range_check.circom
**Expected Matches**:
- `public_input_declared` (INFO) - Public input signal declared
- `unchecked_public_input_arithmetic` (MEDIUM) - Public input used without range check
- `num2bits_range_check_present` (INFO) - Should NOT fire (no Num2Bits present)

### 7. underconstrained_merkle_real.circom
**Source**: Based on real Tornado Cash/zkBugs Merkle vulnerabilities  
**Expected Matches**:
- `unconstrained_path_direction` (CRITICAL) - Line 11: `pathIndices[levels]` assigned with `<--`, never binary-constrained
- `merkle_selector_mux` (INFO) - Line 26-27: Mux pattern detected (correct pattern, info only)
- **Semantic**: `orphaned_unconstrained_assignment` (CRITICAL) - pathIndices never constrained

### 8. merkle_path/unconstrained_direction_vuln.circom
**Expected Matches**:
- `unconstrained_path_direction` (CRITICAL) - pathIndices[i] not binary-constrained
- `merkle_root_comparison_not_constraint` (CRITICAL) - Line 21: Uses `==` instead of `===`

### 9. weak_nullifier.circom
**Source**: Based on zkBugs StealthDrop, Tornado Cash variants  
**Expected Matches**:
- `commitment_not_exposed` (HIGH) - Line 13: `nullifier <--` (unconstrained)
- **Semantic**: `orphaned_unconstrained_assignment` (CRITICAL) - nullifier never constrained

### 10. commitment_soundness/deterministic_commit_vuln.circom
**Expected Matches**:
- `deterministic_commitment` (HIGH) - Single-input hash (no randomness)
- `commitment_not_exposed` (HIGH) - Commitment assigned with `<--`

### 11. commitment_soundness/nullifier_no_secret_vuln.circom
**Expected Matches**:
- `nullifier_without_secret` (CRITICAL) - Nullifier from single-input hash
- `commitment_not_exposed` (HIGH) - Unconstrained assignment

## Semantic Analysis Expected Findings

### orphaned_unconstrained_assignment
- signal_aliasing.circom: intermediate[0], intermediate[1]
- underconstrained_merkle_real.circom: pathIndices (if not constrained in loop)
- weak_nullifier.circom: nullifier

### component_input_aliasing
- merkle_path/unconstrained_direction_vuln.circom: If same signal wired to multiple ports
- (Requires multi-component test circuit for full validation)

### self_equality_constraint
- (Requires test circuit with `x === x` pattern)

### constraint_on_var
- (Requires test circuit with `var n = 4; n === x;` pattern)

## Fancy-Regex Backreference Test

### same_signal_dual_port_inline (signal_aliasing.yaml pattern 3)
**Test Case**: Requires inline pattern `h1.in <== x; h2.in <== x;` on same line  
**Status**: No existing real circuit has this exact pattern  
**Action**: Document as validated via unit test, not integration test

## Validation Commands

```bash
# Run full integration test
./test_integration.sh

# Test individual pattern file
cargo run --release --bin zkpm -- scan \
  tests/real_vulnerabilities/underconstrained_merkle_real.circom \
  --pattern patterns/merkle_path.yaml

# Test semantic analysis
cargo run --release --bin zkpm -- scan \
  tests/real_vulnerabilities/signal_aliasing.circom \
  --semantic

# Test all patterns on one circuit
cargo run --release --bin zkpm -- scan \
  tests/real_vulnerabilities/underconstrained_merkle_real.circom \
  --pattern patterns/
```

## Success Criteria

- ✅ Each pattern file detects at least 1 vulnerability in corresponding test circuit
- ✅ No false negatives on known vulnerable circuits
- ✅ Semantic analysis detects cross-line issues (orphaned unconstrained, aliasing)
- ✅ Fancy-regex backreference pattern compiles without error
- ✅ All 32 patterns load and execute without crashes

## Known Limitations

1. **Fancy-regex inline aliasing**: No real circuit has `comp.a <== x; comp.b <== x;` on same line
2. **Array normalization**: `vals[0]`, `vals[1]` normalized to `vals` may cause FP in aliasing check
3. **Template scope**: Semantic analysis correctly scopes to template boundaries
