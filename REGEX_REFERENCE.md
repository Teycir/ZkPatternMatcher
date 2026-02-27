# ZkPatternMatcher Regex Reference

## Overview

This document catalogs all regex patterns currently implemented in ZkPatternMatcher for detecting vulnerabilities in Zero-Knowledge proof circuits.

⚠️ **Transparency Note**: This is a proof-of-concept tool with **3 validated patterns**. Extended patterns listed below are planned but not yet implemented.

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

## Planned Patterns (Not Yet Implemented)

See [LIMITATIONS.md](LIMITATIONS.md#pattern-coverage-critical) for full list of missing coverage:

- Signal aliasing (name reuse)
- Missing IsZero constraint checks
- Unchecked division (zero divisor)
- Field arithmetic overflow
- Merkle path validation issues
- Signature verification weaknesses
- Commitment uniqueness problems
- Array bounds checks
- Bitwise operations without range proofs
- Equality checks vs constraints (`==` vs `===`)

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
| Signal Aliasing | ❌ | ❌ | Not implemented |
| Missing IsZero | ❌ | ❌ | Not implemented |
| Unchecked Division | ❌ | ❌ | Not implemented |
| Array Bounds | ❌ | ❌ | Not implemented |
| Equality Check | ❌ | ❌ | Not implemented |

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

We actively seek pattern contributions! See [PATTERN_GUIDE.md](PATTERN_GUIDE.md) for:

1. **Identify Vulnerability:** Find real vulnerable circuit code
2. **Create Regex:** Write bounded, compatible regex pattern (no lookahead/lookbehind!)
3. **Test Pattern:** Validate against vulnerable and safe circuits
4. **Document:** Add to this reference with examples
5. **Submit:** Include test cases in pull request

## Current Limitations

- **Small Pattern Library**: Only 3 validated patterns
- **Syntax-Only Detection**: No semantic analysis or data flow tracking
- **No Invariant Checking**: Invariant YAML blocks are parsed but not enforced
- **Limited Test Corpus**: 3 vulnerable + 2 safe circuits

See [LIMITATIONS.md](LIMITATIONS.md) for complete transparency on current capabilities.

## Security Considerations

- Patterns detect syntax-level issues, not semantic bugs
- Manual review still required for complex vulnerabilities
- Tool itself not audited; dependencies not pinned
- Not production-ready without pattern library expansion

## Performance (Estimated)

- **Scan Speed:** ~1000 lines/second (untested on large codebases)
- **Memory Usage:** <10MB for typical circuits
- **False Positive Rate:** 0% on 2 safe test circuits (small sample)
- **Detection Rate:** 100% on 3 vulnerable test circuits (small sample)

⚠️ Performance metrics are estimates based on small test corpus. Real-world performance may vary.
