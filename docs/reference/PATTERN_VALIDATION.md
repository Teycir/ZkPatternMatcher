# Pattern Validation Report

## Test Methodology

- **Baseline Corpus:** 3 real vulnerable circuits + 2 safe circuits (`patterns/real_vulnerabilities.yaml`)
- **Integration Matrix:** 16 vulnerable fixtures + 10 safe controls (`tests/real_world_validation_matrix_tests.rs`)
- **Validation Gate:** Expected pattern IDs must be hit for each vulnerable fixture; safe controls must emit 0 high/critical findings
- **Validation Date:** Baseline corpus snapshot (see git history for latest updates)

## Pattern Performance

| Pattern ID | Real Vuln Detected | False Positives | Notes |
|------------|-------------------|-----------------|-------|
| `underconstrained_assignment` | ✅ (baseline + matrix) | 0 high/critical in controls | Core baseline rule |
| `weak_nullifier_pattern` | ✅ (baseline) | 0 high/critical in controls | Core baseline rule |
| `no_range_check` | ✅ (baseline) | 0 high/critical in controls | Literal baseline rule |
| Extended packs (`array_bounds`, `equality_check`, `merkle_path`, `commitment_soundness`, `public_input_validation`, `missing_iszero`, etc.) | ✅ targeted fixtures | 0 high/critical in matrix controls | Fixture-level matrix validation |

## Known Limitations

### Pattern Scope
- **Syntax-first default:** Pattern matching is line-by-line and syntax-based by default
- **Limited semantic coverage:** `--semantic` adds heuristic cross-line checks, not full AST/constraint-graph analysis
- **Regex-only false positives:** Regex/literal scans can match comments/strings; semantic mode strips comments and reduces this class of noise

### False Positive Scenarios

**Pattern: `unconstrained_assignment`**
- May match: Template parameter assignments (rare in practice)
- Mitigation: Word boundary anchors reduce noise

**Pattern: `weak_nullifier_assignment`**
- May match: Variable names containing "nullifier" substring
- Mitigation: Requires `signal` keyword prefix

**Pattern: `signal_without_constraint`**
- May match: Signals constrained on subsequent lines
- Classification: Heuristic hint, not definitive vulnerability

## Test Cases

### Baseline Real Vulnerabilities (3)
1. `underconstrained_multiplier.circom` - Unconstrained assignment
2. `weak_nullifier.circom` - Nullifier without constraint
3. `missing_range_check.circom` - Missing range validation

### Baseline Safe Circuits (2)
1. `safe_multiplier.circom` - Properly constrained operations
2. `safe_merkle.circom` - Validated Merkle proof

### Integration Matrix Coverage
- 16 vulnerable fixtures across baseline + extended pattern packs
- 10 safe controls used for high/critical false-positive gating

## Recommendations

1. **Prefer semantic mode for review scans:** Use `--semantic` to reduce comment/string-based noise
2. **Context awareness:** Upgrade to AST-based matching for production-grade precision
3. **Severity classification:** Mark heuristic patterns as "hints" not "detections"
4. **Continuous validation:** Expand test corpus to 50+ circuits for stronger confidence bounds

## Regex Flags

All patterns use:
- **Multiline mode:** Disabled (line-by-line matching)
- **Case sensitivity:** Enabled
- **File types:** `.circom` files only (configurable)
