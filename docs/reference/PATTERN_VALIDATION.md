# Pattern Validation Report

## Test Methodology

- **Test Corpus:** 3 real vulnerable circuits + 2 safe circuits
- **Total Lines Scanned:** ~150 LOC
- **Validation Date:** Baseline corpus snapshot (see git history for latest updates)

## Pattern Performance

| Pattern ID | Real Vuln Detected | False Positives | Notes |
|------------|-------------------|-----------------|-------|
| `unconstrained_assignment` | ✅ 3/3 | 0 | Context-aware with word boundaries |
| `weak_nullifier_assignment` | ✅ 1/1 | 0 | Requires `signal` keyword context |
| `missing_constraint_marker` | ✅ 1/1 | 0 | Documentation-based detection |
| `vulnerability_marker` | ✅ 1/1 | 0 | Explicit vulnerability markers |
| `missing_range_check_doc` | ✅ 1/1 | 0 | Literal string match |
| `signal_without_constraint` | ⚠️ Heuristic | Unknown | May produce false positives |

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

### Real Vulnerabilities (3)
1. `underconstrained_multiplier.circom` - Unconstrained assignment
2. `weak_nullifier.circom` - Nullifier without constraint
3. `missing_range_check.circom` - Missing range validation

### Safe Circuits (2)
1. `safe_multiplier.circom` - Properly constrained operations
2. `safe_merkle.circom` - Validated Merkle proof

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
