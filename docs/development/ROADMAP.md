# ZkPatternMatcher Roadmap

## Current Status
- ✅ Pattern coverage expanded across multiple YAML libraries
- ✅ Fancy-regex support for backreferences
- ✅ Two-pass semantic analysis (orphaned unconstrained, signal aliasing, self-equality, var equality)
- ✅ Integration test suite with real vulnerable circuits
- ✅ Manifest-style real-world validation matrix in `cargo test` (vuln + safe control fixtures)

## Short Term (Next 2 Weeks)

### 1. Add --warn-only Mode
**Priority**: HIGH  
**Effort**: 1 day

Add CLI flag to treat all findings as warnings, not confirmed vulnerabilities.

```bash
zkpm patterns/production.yaml circuit.circom --warn-only
```

**Implementation**:
- Add `--warn-only` flag to CLI
- Prefix all output with "⚠️ POTENTIAL:" instead of severity emoji
- Update documentation to clarify regex matches are hints

### 2. Downgrade Pattern Severities
**Priority**: HIGH  
**Effort**: 2 hours

Downgrade regex-only patterns from critical/high to medium unless paired with semantic checks.

**Changes**:
- `comparison_instead_of_constraint`: critical → medium (regex hint only)
- `bare_hint_assignment`: high → medium (semantic check is authoritative)
- `unconstrained_path_direction`: critical → high (needs semantic confirmation)
- Keep semantic findings at critical/high (structural validation)

### 3. Document Pattern Confidence Levels
**Priority**: HIGH  
**Effort**: 1 day

Add confidence field to pattern schema and documentation.

```yaml
patterns:
  - id: comparison_instead_of_constraint
    kind: regex
    confidence: medium  # regex hint, needs manual review
    pattern: '\w+\s*==\s*\w+\s*;'
    
  - id: orphaned_unconstrained_assignment
    kind: semantic
    confidence: high    # structural validation
```

## Medium Term (Next 2 Months)

### 4. Circom-Aware Parsing (Subset Grammar)
**Priority**: HIGH  
**Effort**: 2 weeks

Implement minimal Circom parser for constraint-pairing checks.

**Scope** (subset sufficient):
- Signal declarations: `signal input x;`
- Assignments: `<--`, `<==`, `===`
- Component instantiation: `component h = Hasher();`
- Template boundaries: `template T() { ... }`

**Benefits**:
- Eliminate false positives from regex patterns
- Enable precise constraint-pairing validation
- Support multi-line statement analysis

**Implementation**:
```rust
// crates/circom-parser/src/lib.rs
pub struct CircomParser {
    // Minimal AST for constraint analysis
}

pub enum Statement {
    SignalDecl { name: String, is_input: bool },
    Assignment { lhs: String, op: AssignOp, rhs: Expr },
    Constraint { lhs: Expr, rhs: Expr },
}
```

### 5. Benchmark Against Public Repositories
**Priority**: HIGH  
**Effort**: 1 week

Measure FP/FN rates on real codebases.

**Target Repositories**:
- `iden3/circomlib` (standard library - expect 0 FP)
- `tornadocash/tornado-core` (known vulnerabilities - measure recall)
- `semaphore-protocol/semaphore` (production code - measure precision)

**Metrics**:
- False Positive Rate (FPR): findings on safe circuits
- False Negative Rate (FNR): missed vulnerabilities on known-vulnerable circuits
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)

**Deliverable**: `BENCHMARK_RESULTS.md` with FP/FN analysis

### 6. Constraint-Pairing Validation
**Priority**: MEDIUM  
**Effort**: 1 week

Flag `<--` only when assigned signal lacks corresponding `===`.

**Current** (semantic check):
```rust
// Flags all <-- without === in template
check_orphaned_unconstrained(&assignments)
```

**Enhanced** (with parser):
```rust
// Flags <-- only if no === within N lines or same scope
check_constraint_pairing(&ast, max_distance: 10)
```

## Long Term (6+ Months)

### 7. Integrate with Circom's Official Parser
**Priority**: MEDIUM  
**Effort**: 1 month

Use `circom_parser` crate (if available) or FFI to Circom's Rust parser.

**Benefits**:
- Full AST access (no subset limitations)
- Guaranteed correctness (matches Circom compiler)
- Support for all Circom language features

**Challenges**:
- Circom parser may not be published as library
- May require forking/vendoring Circom source
- Dependency on Circom version compatibility

**Alternative**: Contribute parser library to Circom project

### 8. Symbolic Execution Integration
**Priority**: LOW  
**Effort**: 2 months

Integrate with Z3/CVC5 for constraint satisfiability checks.

**Use Cases**:
- Prove `<--` assignment is always constrained
- Detect unreachable constraints
- Validate range bounds

### 9. IDE Integration (LSP)
**Priority**: LOW  
**Effort**: 1 month

Implement Language Server Protocol for real-time linting.

**Features**:
- Inline warnings in VSCode/Vim
- Quick-fix suggestions
- Hover documentation for patterns

## Implementation Priority

1. **Week 1-2**: Short-term items (--warn-only, severity downgrade, confidence docs)
2. **Month 1**: Benchmark suite + FP/FN analysis
3. **Month 2**: Circom subset parser + constraint-pairing
4. **Month 3+**: Evaluate Circom official parser integration

## Success Metrics

- **Short term**: <5% FPR on circomlib, clear "hint not proof" messaging
- **Medium term**: <2% FPR, >95% recall on zkBugs dataset
- **Long term**: Full Circom language support, LSP integration

## Community Feedback

Open issues for:
- Pattern false positives (label: `false-positive`)
- Missing vulnerability classes (label: `pattern-request`)
- Parser feature requests (label: `parser`)

Track metrics in `BENCHMARK_RESULTS.md` (updated quarterly).
