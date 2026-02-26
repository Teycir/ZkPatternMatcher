# Contributing to ZkPatternMatcher

Thank you for your interest in contributing! This guide will help you add new vulnerability patterns to the library.

## Pattern Contribution Workflow

### 1. Discover a Vulnerability

Patterns come from:
- Manual security audits
- Public CVEs (zkBugs, GitHub advisories)
- Research papers
- Bug bounty reports

### 2. Create a Pattern File

Create `patterns/your_pattern.yaml`:

```yaml
patterns:
  - id: your_vulnerability_id
    kind: regex  # or 'literal'
    pattern: 'vulnerable_code_pattern'
    message: 'Description of the vulnerability'
    severity: high  # critical, high, medium, low, info

invariants:
  - name: expected_property
    invariant_type: constraint
    relation: "output == expected"
    oracle: must_hold
    severity: critical
    description: "What should always be true"
```

### 3. Test Your Pattern

Create a test circuit in `examples/`:

```circom
// examples/test_your_pattern.circom
template VulnerableExample() {
    // Code that should trigger your pattern
}
```

Test it:

```bash
cargo run --bin zkpm patterns/your_pattern.yaml examples/test_your_pattern.circom
```

### 4. Add Integration Test

Add to `tests/integration_tests.rs`:

```rust
#[test]
fn test_your_pattern() {
    let library = load_pattern_library("patterns/your_pattern.yaml").unwrap();
    let matcher = PatternMatcher::new(library).unwrap();
    let matches = matcher.scan_file("examples/test_your_pattern.circom").unwrap();
    
    assert!(!matches.is_empty(), "Pattern should match vulnerable code");
}
```

### 5. Submit Pull Request

- Fork the repository
- Create a feature branch: `git checkout -b pattern/your-vulnerability`
- Commit your changes: `git commit -am 'Add pattern for X vulnerability'`
- Push: `git push origin pattern/your-vulnerability`
- Open a Pull Request

## Pattern Guidelines

### Good Patterns

✅ **Specific**: Target a well-defined vulnerability class
✅ **Tested**: Include test cases demonstrating detection
✅ **Documented**: Clear message explaining the issue
✅ **Accurate**: Low false positive rate

### Pattern Examples

**Underconstrained Assignment:**
```yaml
- id: unconstrained_assignment
  kind: regex
  pattern: '<--'
  severity: high
```

**Missing Nullifier Check:**
```yaml
- id: nullifier_without_check
  kind: regex
  pattern: 'nullifier(?!.*unique)'
  severity: critical
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Ensure `cargo test` passes

## Questions?

Open an issue or discussion on GitHub.
