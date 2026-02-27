# Known Limitations

This document transparently lists current limitations and areas for improvement.

## Pattern Coverage (Critical)

**Current State**: 3 validated patterns + 5 newly implemented (unvalidated)

**Validated Patterns** (in `real_vulnerabilities.yaml`):
- ✅ Underconstrained assignments (`<--` operator)
- ✅ Weak nullifier assignments
- ✅ Missing range checks (via comment detection)

**Newly Implemented - Awaiting Validation** (separate YAML files):
- ⚠️ Signal aliasing attacks (`signal_aliasing.yaml`)
- ⚠️ Missing IsZero constraint checks (`missing_iszero.yaml`)
- ⚠️ Unchecked division (`unchecked_division.yaml`)
- ⚠️ Array bounds checks (`array_bounds.yaml`)
- ⚠️ Equality operator misuse (`equality_check.yaml`)

**Still Missing Coverage**:
- Field arithmetic overflow
- Merkle tree path validation issues
- EdDSA signature malleability
- Commitment scheme weaknesses
- Proof malleability attacks
- Constraint system rank deficiency
- Trusted setup vulnerabilities
- Non-unique witness generation

**Impact**: New patterns expand coverage significantly but require validation against real vulnerable circuits before production use.

**Mitigation**: Actively seeking pattern contributions. See [PATTERN_GUIDE.md](PATTERN_GUIDE.md).

## Pattern Matching Limitations

**Current State**: Regex and literal string matching only

**Limitations**:
- No semantic analysis (can't detect logic bugs)
- No data flow tracking
- No constraint system analysis
- No witness generation testing
- No proof verification testing

**Impact**: Can only detect syntactic patterns, not semantic vulnerabilities.

**Future**: AST-based matching planned but not implemented.

## Invariant System

**Current State**: YAML schema exists but functionality is aspirational

**Status**: The `invariants` section in YAML patterns is parsed but not enforced. Examples in docs are placeholders.

**Impact**: Cannot verify constraint system properties or mathematical invariants.

**Future**: Requires constraint system solver integration (Z3, CVC5, or custom).

## Testing Coverage

**Current State**: 
- 23 unit tests
- 3 real vulnerable circuits
- 2 safe circuits

**Limitations**:
- Small test corpus
- Limited backend coverage (Circom only)
- No Noir/Halo2/Cairo pattern testing
- No large-scale circuit testing

**Impact**: Unknown false positive/negative rates on diverse codebases.

## CI/CD Integration

**Current State**: Example workflow provided, no live CI badge

**Limitations**:
- No automated CI for this repo
- Test badge is static (always green)
- No regression testing on pattern changes
- No performance benchmarking

**Impact**: Contributors can't verify their changes don't break existing patterns.

**Planned**: GitHub Actions workflow with live badge.

## Performance

**Current State**: Untested on large codebases

**Limitations**:
- No benchmarks on >10K LOC circuits
- No parallel scanning
- No incremental analysis
- Regex performance not profiled

**Impact**: May be slow on large projects.

## Security Considerations

**Supply Chain**:
- Tool itself not audited
- Dependencies not pinned in Cargo.toml
- No SBOM (Software Bill of Materials)
- No signed releases

**Pattern Trust**:
- No pattern signing/verification
- No pattern author attribution
- No malicious pattern detection

**Impact**: In security-critical contexts, verify patterns manually.

## Documentation Gaps

**Missing**:
- Formal pattern specification
- False positive handling guide
- Integration with other tools (Circomspect, Picus)
- Performance tuning guide
- Threat model document

## Roadmap Priority

1. **Critical**: Expand pattern library (10+ patterns minimum)
2. **High**: Add live CI with real badge
3. **High**: AST-based pattern matching
4. **Medium**: Implement invariant checking
5. **Medium**: Multi-backend support (Noir, Halo2)
6. **Low**: Performance optimization

## Contributing

Help address these limitations! See:
- [PATTERN_GUIDE.md](PATTERN_GUIDE.md) - Add patterns
- [CONTRIBUTING.md](docs/CONTRIBUTING.md) - General contributions
- GitHub Issues - Report bugs or request features

## Transparency Commitment

This document will be updated as limitations are addressed or new ones discovered. Last updated: 2025-02-23
