# ZkPatternMatcher Regex Reference

## Overview

This document catalogs all regex patterns currently implemented in ZkPatternMatcher for detecting vulnerabilities in Zero-Knowledge proof circuits.

**Transparency Note**: The scanner is stable and includes:
- Baseline validation: **3 vulnerability patterns + 2 developer markers**
- Integration-test matrix validation: **16 vulnerable fixtures + 10 safe controls** (see `tests/real_world_validation_matrix_tests.rs`)

## Implemented Patterns (in `patterns/real_vulnerabilities.yaml`)

### 1. Underconstrained Assignment ✅ VALIDATED
**Pattern:** `<--`  
**Target:** Unconstrained signal assignments  
**Example Match:** `signal output <-- value`  
**Vulnerability:** Signal assigned without constraint, allowing prover to forge values  
**Severity:** Critical  
**Test:** `tests/real_vulnerabilities/underconstrained_multiplier.circom`

### 2. Weak Nullifier Assignment ✅ VALIDATED
**Pattern:** `nullifier\s*<--`  
**Target:** Nullifier using unconstrained assignment  
**Example Match:** `signal nullifier <-- hash(secret)`  
**Vulnerability:** Enables replay/double-spend attacks  
**Severity:** Critical  
**Test:** `tests/real_vulnerabilities/weak_nullifier.circom`

### 3. Missing Range Check ⚠️ LITERAL MATCH
**Pattern:** `No constraint that value is in valid range` (literal string)  
**Target:** Comment indicating missing range constraint  
**Example Match:** Exact comment text in test circuit  
**Vulnerability:** Missing bounds validation  
**Severity:** High  
**Test:** `tests/real_vulnerabilities/missing_range_check.circom`  
**Note:** This is a literal string match on a specific comment, not a general pattern. Will not detect real-world range check issues unless developers write this exact comment.

## Developer Markers (Not Vulnerability Patterns)

### 4. BUG Marker
**Pattern:** `BUG:`  
**Target:** Developer-written vulnerability markers  
**Purpose:** Detect circuits with known issues marked by developers  
**Severity:** Critical (marker severity, not pattern detection)

### 5. MISSING Constraint Marker
**Pattern:** `MISSING:`  
**Target:** TODO comments for missing constraints  
**Purpose:** Detect incomplete circuit implementations  
**Severity:** High

## Additional Pattern Files (Targeted Matrix Validation)

The following pattern packs now have targeted fixture-based validation in the integration matrix:

### Signal Aliasing (`patterns/signal_aliasing.yaml`) ✅
- Component input aliasing detection
- Intermediate array unconstrained assignments
- Status: Targeted matrix validation

### Missing IsZero (`patterns/missing_iszero.yaml`) ✅
- Unconstrained boolean selector detection
- Binary constraint pattern recognition
- IsZero component usage tracking
- Status: Targeted matrix validation

### Unchecked Division (`patterns/unchecked_division.yaml`) ✅
- Division operator detection
- Signal as denominator detection
- Explicit inverse() call detection
- Status: Targeted matrix validation

### Array Bounds (`patterns/array_bounds.yaml`) ✅
- Signal-indexed array access detection
- Signal-dependent loop bound detection
- LessThan component usage tracking
- Status: Targeted matrix validation

### Equality Check (`patterns/equality_check.yaml`) ✅
- Comparison operator (==) vs constraint (===) detection
- Assignment operator (=) misuse detection
- Separate assignment and constraint pattern detection
- Status: Targeted matrix validation

### Merkle Path (`patterns/merkle_path.yaml`) ✅
- Root comparison misuse checks
- Selector/path-direction integrity checks
- Status: Targeted matrix validation

### Commitment Soundness (`patterns/commitment_soundness.yaml`) ✅
- Deterministic commitment checks
- Nullifier-without-secret checks
- Status: Targeted matrix validation

### Public Input Validation (`patterns/public_input_validation.yaml`) ✅
- Public-input declaration/usage heuristics
- Hash-input validation heuristics
- Status: Targeted matrix validation

See individual pattern files in `patterns/` directory for detailed documentation.

## Regex Design Principles

### Bounded Quantifiers
All patterns use bounded quantifiers like `\w{1,50}` to prevent infinite loops and ReDoS attacks.

### No Lookahead/Lookbehind
Patterns avoid `(?!)` and `(?=)` constructs for compatibility with Rust regex engine.

⚠️ **Important**: Do not use lookahead/lookbehind in pattern contributions - they will fail at runtime.

### Specific Targeting
Each pattern targets specific vulnerability classes found in real ZK circuits.

## Pattern Validation Status

| Pattern | Real Vuln Test | False Positive Test | Status |
|---------|---------------|---------------------|---------|
| Underconstrained Assignment | ✅ | ✅ | Validated |
| Weak Nullifier Assignment | ✅ | ✅ | Validated |
| Missing Range Check | ⚠️ | ✅ | Literal match only |
| BUG Marker | ✅ | ✅ | Developer marker |
| MISSING Marker | ✅ | ✅ | Developer marker |
| Signal Aliasing | ✅ | ✅ | Targeted matrix validation |
| Missing IsZero | ✅ | ✅ | Targeted matrix validation |
| Unchecked Division | ✅ | ✅ | Targeted matrix validation |
| Array Bounds | ✅ | ✅ | Targeted matrix validation |
| Equality Check | ✅ | ✅ | Targeted matrix validation |
| Merkle Path | ✅ | ✅ | Targeted matrix validation |
| Commitment Soundness | ✅ | ✅ | Targeted matrix validation |
| Public Input Validation | ✅ | ✅ | Targeted matrix validation |

## Usage Examples

### CLI Usage
```bash
zkpm patterns/real_vulnerabilities.yaml circuit.circom
```

### Library Usage
```rust
use zk_pattern_matcher::{load_pattern_library, PatternMatcher};

let library = load_pattern_library("patterns/real_vulnerabilities.yaml")?;
let matcher = PatternMatcher::new(library)?;
let matches = matcher.scan_file("circuit.circom")?;
```

## Contributing New Patterns

We actively seek pattern contributions! See [PATTERN_GUIDE.md](../patterns/PATTERN_GUIDE.md) for:

1. **Identify Vulnerability:** Find real vulnerable circuit code
2. **Create Regex:** Write bounded, compatible regex pattern (no lookahead/lookbehind!)
3. **Test Pattern:** Validate against vulnerable and safe circuits
4. **Document:** Add to this reference with examples
5. **Submit:** Include test cases in pull request

## Current Limitations

- **Two-tier Validation**: Baseline set (3 vulnerability patterns) plus fixture-level matrix validation for extended packs
- **Syntax-First Matching**: Default regex/literal scans are line-based and can match comments/strings
- **Limited Semantic Coverage**: `--semantic` adds heuristic cross-line checks, not full data-flow/AST analysis
- **No Invariant Enforcement**: Invariant YAML blocks are parsed but not enforced (warnings are emitted)
- **Still-Limited Corpus**: 16 vulnerable fixtures + 10 safe controls is better, but still small vs ecosystem diversity

See [LIMITATIONS.md](LIMITATIONS.md) for complete transparency on current capabilities.

## Security Considerations

- Patterns primarily detect syntax-level issues; semantic mode adds limited heuristic checks
- Manual review still required for complex vulnerabilities
- Tool itself not audited; dependencies not pinned
- Not production-ready without pattern library expansion

## Performance (Estimated)

- **Scan Speed:** ~1000 lines/second (untested on large codebases)
- **Memory Usage:** <10MB for typical circuits
- **False Positive Gate:** 0 high/critical findings on 10 safe controls (matrix sample)
- **Detection Gate:** Expected pattern IDs hit across 16 vulnerable fixtures (matrix sample)

⚠️ Performance metrics are estimates based on small test corpus. Real-world performance may vary.
