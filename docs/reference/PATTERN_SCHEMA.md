# Pattern Schema Documentation

## Pattern Format

### Required Fields

```yaml
patterns:
  - id: unique_pattern_identifier
    kind: regex | literal | ast
    pattern: 'detection pattern'
    message: 'Short description (1 line)'
    severity: critical | high | medium | low | info
```

### Extended Fields (Recommended)

```yaml
patterns:
  - id: pattern_id
    kind: regex
    pattern: 'regex_pattern'
    message: 'Short message'
    description: |
      Detailed explanation of the vulnerability.
      Include remediation guidance and context.
    severity: critical
    confidence: high | medium | low
    references:
      - https://zkbugs.com/vuln-id
      - https://audit-report-url
    false_positive_note: "Explanation of when false positives occur"
```

## Field Descriptions

### Core Fields

- **id**: Unique identifier (snake_case)
- **kind**: Detection method
  - `regex`: Regular expression matching
  - `literal`: Exact string matching
  - `ast`: AST-based analysis (not yet implemented)
- **pattern**: The actual detection pattern
- **message**: Short one-line description for display
- **severity**: Impact level

### Extended Fields

- **description**: Multi-line explanation with remediation guidance
- **confidence**: Pattern reliability
  - `high`: Low false positive rate (<5%)
  - `medium`: Moderate false positives (5-20%)
  - `low`: High false positives (>20%) - heuristic only
- **references**: Links to vulnerability databases, audit reports, documentation
- **false_positive_note**: When/why false positives occur

## Invariant Format (Future)

```yaml
# Note: Invariant checking requires AST analysis - not yet implemented
invariants:
  - name: invariant_name
    invariant_type: constraint | metamorphic | differential
    relation: "mathematical relation or property"
    oracle: must_hold | must_fail | should_hold
    severity: critical | high | medium
    description: "What this invariant ensures"
    references:
      - https://relevant-documentation
```

## Limitations

### Current (v0.1.0)
- **Syntax-only detection**: Patterns match code structure, not semantics
- **No AST analysis**: Cannot understand constraint flow or signal dependencies
- **Comment-blind**: May match patterns in comments (mitigated by context)
- **Line-by-line**: No multi-line pattern support

### Future Improvements
- AST-based pattern matching for structural analysis
- Constraint graph analysis for semantic bugs
- Multi-line pattern support
- Comment filtering pre-processing

## Best Practices

### Writing Patterns

1. **Use word boundaries** for regex: `\b\w+\s*<--` not `<--`
2. **Add context** to reduce false positives: `signal\s+nullifier` not `nullifier`
3. **Document confidence** honestly - mark heuristics as `low` confidence
4. **Provide references** to validate the pattern
5. **Explain false positives** so users know what to expect

### Testing Patterns

```bash
# Validate syntax
zkpm validate patterns/your_pattern.yaml

# Test against known vulnerable circuit
zkpm patterns/your_pattern.yaml tests/vulnerable_circuit.circom

# Test against safe circuit (check false positives)
zkpm patterns/your_pattern.yaml tests/safe_circuit.circom
```

## Examples

### High Confidence Pattern

```yaml
- id: unconstrained_assignment
  kind: regex
  pattern: '\b\w+\s*<--\s*\w+'
  message: 'Unconstrained assignment detected'
  description: |
    The <-- operator creates witness assignments without constraints.
    Use <== for constrained assignments.
  severity: critical
  confidence: high
  references:
    - https://docs.circom.io/circom-language/constraint-generation/
  false_positive_note: "May match <-- in comments"
```

### Low Confidence Pattern (Heuristic)

```yaml
- id: potential_issue
  kind: regex
  pattern: 'suspicious_pattern'
  message: 'Potential issue detected'
  description: |
    This is a heuristic check. Manual review required.
  severity: medium
  confidence: low
  references: []
  false_positive_note: "High false positive rate - use as triage hint only"
```
