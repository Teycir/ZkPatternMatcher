# Extended Pattern Library

This directory contains 5 additional vulnerability pattern files implementing detection for common ZK circuit vulnerabilities.

⚠️ **Status**: Newly implemented, awaiting validation against real vulnerable circuits.

## Pattern Files

### 1. `signal_aliasing.yaml` - Signal Aliasing Detection
**Vulnerability Class**: Multiple signals sharing the same wire, collapsing proof degrees of freedom

**Patterns**:
- `component_input_aliasing` (HIGH): Same signal wired to multiple component inputs
- `intermediate_array_unconstrained` (MEDIUM): Intermediate array elements using `<--`

**Use Case**: Merkle path circuits, multi-component compositions

**False Positive Risk**: Medium - deliberate aliasing in bus/shared-signal patterns

### 2. `missing_iszero.yaml` - Missing IsZero Component Detection
**Vulnerability Class**: Equality checks without proper IsZero template usage

**Patterns**:
- `unconstrained_boolean_selector` (MEDIUM): Mux pattern without binary constraint
- `missing_binary_constraint` (INFO): Binary constraint pattern recognition
- `iszero_component_present` (INFO): Positive detection of correct IsZero usage

**Use Case**: Conditional logic, equality checks, boolean selectors

**False Positive Risk**: Medium - mux patterns with external binary constraints

### 3. `unchecked_division.yaml` - Division by Zero Detection
**Vulnerability Class**: Division without nonzero constraint on divisor

**Patterns**:
- `division_operator_detected` (HIGH): Any use of `/` operator
- `signal_as_denominator` (HIGH): Signal in denominator position
- `explicit_inverse_call` (HIGH): Explicit `inverse()` function calls

**Use Case**: Arithmetic operations, modular inverse computations

**False Positive Risk**: High - fires on debug `log()` calls and template parameters

### 4. `array_bounds.yaml` - Array Bounds Checking
**Vulnerability Class**: Array access without bounds validation

**Patterns**:
- `signal_indexed_array_access` (MEDIUM): Array indexed by non-literal
- `signal_dependent_loop_bound` (HIGH): Loop bound depends on signal
- `lessthan_component_present` (INFO): Positive detection of LessThan usage

**Use Case**: Merkle trees, lookup tables, dynamic array access

**False Positive Risk**: Medium - template parameters used as indices

### 5. `equality_check.yaml` - Equality Operator Misuse
**Vulnerability Class**: Using comparison operators instead of constraints

**Patterns**:
- `comparison_instead_of_constraint` (CRITICAL): `==` instead of `===`
- `assignment_in_circuit_context` (HIGH): `=` instead of `<==` or `<--`
- `separate_assignment_and_constraint` (MEDIUM): `<--` followed by `===`
- `orphaned_unconstrained_assignment` (HIGH): `<--` without following `===`
- `correct_constraint_operator` (INFO): Positive detection of `<==`

**Use Case**: All circuits - fundamental operator correctness

**False Positive Risk**: Low to Medium depending on pattern

## Usage

### Scan with All Extended Patterns

```bash
# Scan with all 5 new pattern files
zkpm patterns/signal_aliasing.yaml circuit.circom
zkpm patterns/missing_iszero.yaml circuit.circom
zkpm patterns/unchecked_division.yaml circuit.circom
zkpm patterns/array_bounds.yaml circuit.circom
zkpm patterns/equality_check.yaml circuit.circom
```

### Batch Scan

```bash
# Scan with all patterns at once
for pattern in patterns/*.yaml; do
    echo "Scanning with $pattern..."
    zkpm "$pattern" circuit.circom
done
```

### CI/CD Integration

```yaml
# .github/workflows/extended-scan.yml
name: Extended ZK Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install zkpm --locked
      - name: Scan with extended patterns
        run: |
          for pattern in patterns/*.yaml; do
            zkpm "$pattern" circuits/*.circom || exit 1
          done
```

## Known Limitations

### Regex Engine Compatibility

⚠️ **Critical Limitation**: Standard Rust `regex` crate does not support:
- **Backreferences** (`\1`, `\2`) - patterns like `(\w+).*\1` will fail
- **Lookahead/Lookbehind** (`(?=)`, `(?!)`) - patterns with these will fail
- **Multiline spans** - `[\s\S]{0,200}` across line boundaries not supported

**Impact on Patterns**:
- `signal_aliasing.yaml`: Backreference pattern removed, replaced with info-level manual check
- `equality_check.yaml`: Lookahead pattern removed, replaced with single-line heuristic
- Cross-line signal tracking (orphaned `<--` detection) requires manual review

**Workarounds**:
1. Use info-level patterns to flag lines for manual cross-reference
2. Simplify to single-line heuristics (higher false positive rate)
3. Future: Add `fancy-regex` crate (requires code changes)
4. Future: Implement two-pass semantic analyzer (major refactor)

**Current Status**: All patterns use standard `regex` crate features only.

### False Positive Management

**High FP Risk Patterns**:
- `division_operator_detected`: Fires on `log()` debug calls
- `orphaned_unconstrained_assignment`: May miss constraints in external files

**Recommended `.zkpmignore`**:
```gitignore
# Suppress known false positives
# zkpm-ignore: division_operator_detected
# zkpm-ignore: component_input_aliasing
```

### Multiline Pattern Limitations

Some patterns span multiple lines (e.g., `orphaned_unconstrained_assignment`). Verify your scanner:
- Reads files in full-text mode (not line-by-line)
- Supports `[\s\S]` for multiline matching
- Has sufficient lookahead buffer (200+ chars)

## Validation Status

| Pattern File | Vulnerable Test | Safe Test | Status |
|--------------|----------------|-----------|---------|
| signal_aliasing | ❌ Needed | ❌ Needed | ⚠️ Unvalidated |
| missing_iszero | ❌ Needed | ❌ Needed | ⚠️ Unvalidated |
| unchecked_division | ❌ Needed | ❌ Needed | ⚠️ Unvalidated |
| array_bounds | ❌ Needed | ❌ Needed | ⚠️ Unvalidated |
| equality_check | ❌ Needed | ❌ Needed | ⚠️ Unvalidated |

## Contributing Test Cases

To validate these patterns, we need:

1. **Vulnerable Circuits**: Real-world examples exhibiting each vulnerability
2. **Safe Circuits**: Correct implementations that should NOT trigger patterns
3. **Test Integration**: Add to `tests/real_vulnerabilities/` and `tests/safe_circuits/`

### Example Test Structure

```
tests/
├── real_vulnerabilities/
│   ├── signal_aliasing_merkle.circom
│   ├── missing_iszero_mux.circom
│   ├── unchecked_division_inverse.circom
│   ├── array_bounds_lookup.circom
│   └── equality_check_comparison.circom
└── safe_circuits/
    ├── safe_aliasing_bus.circom
    ├── safe_iszero_equality.circom
    ├── safe_division_nonzero.circom
    ├── safe_array_bounds.circom
    └── safe_equality_constraints.circom
```

## Pattern Sources

These patterns are derived from:
- [zkBugs](https://zkbugs.com) vulnerability database
- [0xPARC ZK Bug Tracker](https://github.com/0xPARC/zk-bug-tracker)
- [Circom Documentation](https://docs.circom.io)
- [Trail of Bits Audit Reports](https://github.com/trailofbits/publications)

## Next Steps

1. **Validation**: Test against real vulnerable circuits
2. **Refinement**: Adjust patterns based on false positive rates
3. **Documentation**: Add examples to REGEX_REFERENCE.md
4. **Integration**: Merge validated patterns into `real_vulnerabilities.yaml`

## Feedback

Found a false positive? Have a vulnerable circuit these patterns miss? 

- Open an issue: [GitHub Issues](https://github.com/Teycir/ZkPatternMatcher/issues)
- Email: teycir@pxdmail.net
- See [CONTRIBUTING.md](../docs/CONTRIBUTING.md)
