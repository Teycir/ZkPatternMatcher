# Known Limitations

This document transparently lists current limitations and areas for improvement.

## Pattern Coverage (Critical)

**Current State**: Baseline validation covers 3 vulnerability patterns, and integration-test matrix coverage now validates extended packs across 16 vulnerable fixtures + 10 safe controls.

**Validated Patterns** (in `real_vulnerabilities.yaml`):
- ✅ Underconstrained assignments (`<--` operator)
- ✅ Weak nullifier assignments
- ✅ Missing range checks (via comment detection)

**Targeted Matrix-Validated Extended Packs** (fixture-level):
- ✅ Signal aliasing attacks (`signal_aliasing.yaml`)
- ✅ Missing IsZero constraint checks (`missing_iszero.yaml`)
- ✅ Unchecked division (`unchecked_division.yaml`)
- ✅ Array bounds checks (`array_bounds.yaml`)
- ✅ Equality operator misuse (`equality_check.yaml`)
- ✅ Merkle path checks (`merkle_path.yaml`)
- ✅ Commitment soundness checks (`commitment_soundness.yaml`)
- ✅ Public input validation checks (`public_input_validation.yaml`)

**Still Missing Coverage**:
- Field arithmetic overflow
- Merkle tree path validation issues
- EdDSA signature malleability
- Commitment scheme weaknesses
- Proof malleability attacks
- Constraint system rank deficiency
- Trusted setup vulnerabilities
- Non-unique witness generation

**Impact**: Coverage is significantly stronger than baseline-only validation, but still relies on targeted fixtures rather than broad ecosystem benchmarking.

**Mitigation**: Actively seeking pattern contributions. See [PATTERN_GUIDE.md](../patterns/PATTERN_GUIDE.md).

## Pattern Matching Limitations

**Current State**: Regex, fancy-regex, and literal string matching with optional two-pass semantic checks (`--semantic`).

**Regex Engine Limitations**:
- Standard `kind: regex` patterns use Rust `regex` (no backreferences or lookaround)
- `kind: fancy_regex` supports advanced constructs but may be slower for complex patterns
- Pattern matching still runs line-by-line (no multiline pattern scope)
- Complex semantic/contextual properties still require manual review

**Semantic Analysis Limitations**:
- Semantic mode is heuristic and currently covers a limited rule set
- No full data-flow or constraint-graph solving
- No witness generation testing
- No proof verification testing
- Invariant blocks are not enforced

**Impact**: Default mode is syntax-first; semantic mode improves cross-line signal checks but still does not replace a full circuit audit.

**Future Options**:
1. Expand semantic rule coverage and reduce heuristic false positives
2. AST-based matching (requires Circom parser integration)
3. Invariant checking with solver-backed enforcement

## Invariant System

**Current State**: YAML schema exists, but invariant enforcement is not implemented.

**Status**: The `invariants` section in YAML patterns is parsed but not enforced. The CLI and matcher emit warnings when invariants are present.

**Impact**: Cannot verify constraint system properties or mathematical invariants.

**Future**: Requires constraint system solver integration (Z3, CVC5, or custom).

## Testing Coverage

**Current State**:
- Workspace unit/integration test suites run in CI
- Baseline fixtures: 3 vulnerable + 2 safe
- Real-world integration matrix: 16 vulnerable + 10 safe controls

**Limitations**:
- Corpus is still small relative to diverse production circuit styles
- Limited backend coverage (Circom only)
- No Noir/Halo2/Cairo pattern testing
- No large-scale circuit testing

**Impact**: Unknown false positive/negative rates on diverse codebases.

## CI/CD Integration

**Current State**: GitHub Actions CI is enabled (test, clippy, fmt, release build) with a live status badge.

**Limitations**:
- No dedicated benchmark/performance regression job
- No fuzzing job in CI
- Pattern quality still depends on corpus expansion and manual validation

**Impact**: Functional regressions are caught, but performance and deeper security regressions may still slip through.

**Planned**: Add benchmark and fuzz/regression tracks to CI.

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
- [PATTERN_GUIDE.md](../patterns/PATTERN_GUIDE.md) - Add patterns
- [CONTRIBUTING.md](../development/CONTRIBUTING.md) - General contributions
- GitHub Issues - Report bugs or request features

## Transparency Commitment

This document will be updated as limitations are addressed or new ones discovered. Last updated: 2026-02-27
