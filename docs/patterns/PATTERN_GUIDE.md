# Contributing Patterns

Thank you for contributing to ZkPatternMatcher! This guide makes it easy to add new vulnerability patterns.

## Quick Start (3 Steps)

### 1. Copy the Template

```bash
cp patterns/TEMPLATE.yaml patterns/your_pattern_name.yaml
```

### 2. Fill in Your Pattern

Edit `patterns/your_pattern_name.yaml`:

```yaml
patterns:
  - id: your_vulnerability_name
    kind: regex
    pattern: 'vulnerable_code_pattern'
    message: 'What vulnerability this detects'
    severity: high
```

### 3. Test It

```bash
# Validate syntax
zkpm validate patterns/your_pattern_name.yaml

# Test on a vulnerable circuit
zkpm patterns/your_pattern_name.yaml path/to/test_circuit.circom
```

## Pattern Examples

### Simple Regex Pattern

```yaml
patterns:
  - id: missing_range_check
    kind: regex
    pattern: 'signal\s+input\s+\w{1,50};'
    message: 'Input signal detected - verify range check exists'
    severity: medium
```

⚠️ **Important**: Do NOT use lookahead `(?!)` or lookbehind `(?<=)` - the Rust regex engine does not support them and patterns will fail at runtime.

### Literal String Pattern

```yaml
patterns:
  - id: unsafe_operator
    kind: literal
    pattern: '<--'
    message: 'Unconstrained assignment operator'
    severity: critical
```

### Pattern with Invariant (NOT IMPLEMENTED)

⚠️ **WARNING**: The invariant system is aspirational. This YAML will parse but invariants are not enforced. See [LIMITATIONS.md](LIMITATIONS.md#invariant-system).

```yaml
patterns:
  - id: output_check
    kind: regex
    pattern: 'signal\s+output'
    message: 'Output signal detected'
    severity: info

# This section is parsed but NOT enforced
invariants:
  - name: output_constrained
    invariant_type: constraint
    relation: "output === constrained_value"
    oracle: must_hold
    severity: critical
    description: "Output must be fully constrained"
```

## Severity Guidelines

- **critical**: Exploitable vulnerability (e.g., proof forgery, underconstrained circuits)
- **high**: Likely vulnerability requiring manual review (e.g., missing range checks)
- **medium**: Suspicious pattern (e.g., complex logic without comments)
- **low**: Code smell (e.g., unused signals)
- **info**: Informational (e.g., pattern statistics)

## Pattern Sources

Good places to find vulnerabilities to encode:

1. **zkBugs**: https://zkbugs.com - Real ZK vulnerabilities
2. **Audit Reports**: Search "circom audit" or "zk-snark audit"
3. **GitHub Advisories**: Filter by "zero-knowledge" or "circom"
4. **Your Own Audits**: Encode vulnerabilities you discover

## Submission Checklist

- [ ] Pattern ID is descriptive and unique
- [ ] Pattern tested on at least one vulnerable circuit
- [ ] Pattern validated with `zkpm validate`
- [ ] Severity level is appropriate
- [ ] Message clearly describes the issue
- [ ] (Optional) Added test circuit in `tests/real_vulnerabilities/`
- [ ] (Optional) Added references to CVE/advisory

## Example PR Description

```
## New Pattern: [Pattern Name]

**Vulnerability**: Brief description

**Severity**: Critical/High/Medium/Low/Info

**Source**: zkBugs CVE-XXXX / Audit Report / Personal Discovery

**Testing**:
- ✅ Detects vulnerable circuit: `tests/real_vulnerabilities/example.circom`
- ✅ No false positives on safe circuits

**References**:
- https://zkbugs.com/vulnerability-id
```

## Need Help?

- Check existing patterns in `patterns/` for examples
- Open an issue with "Pattern Help" label
- Email: teycir@pxdmail.net
