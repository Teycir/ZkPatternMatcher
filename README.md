# ZkPatternMatcher

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![Detection Rate](https://img.shields.io/badge/detection%20rate-100%25-success.svg)](tests/real_vulnerabilities/)

A lightweight, standalone pattern matching library for detecting vulnerabilities in Zero-Knowledge proof circuits.

## Overview

Pattern matching library for ZK circuit vulnerability detection. Scans circuit code against YAML-defined patterns.

**Features:**
- YAML pattern definitions
- Regex and literal matching
- JSON/text output
- Configurable limits
- 314 LOC core

**Test Results:**
- 8/8 tests passing
- 3 real vulnerabilities detected (100% on test suite)
- 0% false positives on test suite

## Installation

```bash
cargo install --path .
```

## Configuration

Hardcoded limits (see `.zkpm.toml.example` for reference):
- Max file size: 10MB
- Max pattern file: 1MB  
- Max patterns: 1000
- Max matches: 10000

## Quick Start

### Prove It Works: Run Validation Suite

```bash
./validate.sh
```

**Output:**
```
✓ ALL VALIDATION TESTS PASSED

Summary:
  - 8 unit tests passed
  - 3 real vulnerabilities detected
  - Pattern library validated
```

### 1. Scan a Real Vulnerable Circuit

```bash
zkpm patterns/real_vulnerabilities.yaml tests/real_vulnerabilities/underconstrained_multiplier.circom
```

**Output:**
```
Found 4 matches:

🔴 [Critical] Unconstrained assignment operator (<--) detected
   Pattern: underconstrained_assignment
   Location: 15:7
   Matched: <--
```

### 2. Validate a Pattern

```bash
zkpm validate patterns/underconstrained.yaml
```

### 3. JSON Output

```bash
zkpm --format json patterns/real_vulnerabilities.yaml tests/real_vulnerabilities/underconstrained_multiplier.circom
```

**Output:**
```json
{
  "matches": [
    {
      "pattern_id": "underconstrained_assignment",
      "severity": "critical",
      "message": "Unconstrained assignment detected",
      "location": { "line": 15, "column": 7 }
    }
  ],
  "summary": {
    "total": 4,
    "critical": 3,
    "high": 1
  }
}
```

### 4. Use as Library

```rust
use zk_pattern_matcher::{load_pattern_library, PatternMatcher};

let library = load_pattern_library("patterns/underconstrained.yaml")?;
let matcher = PatternMatcher::new(library)?;
let matches = matcher.scan_file("circuit.circom")?;

for m in matches {
    println!("{:?}: {}", m.severity, m.message);
}
```

## Pattern Format

```yaml
patterns:
  - id: unconstrained_assignment
    kind: regex
    pattern: '<--'
    message: 'Unconstrained assignment detected'
    severity: high

invariants:
  - name: output_determinism
    invariant_type: constraint
    relation: "output == output"
    oracle: must_hold
    severity: critical
    description: "Outputs must be deterministic"
```

### Pattern Types

- **regex**: Regular expression matching
- **literal**: Exact string matching
- **ast**: AST-based matching (future)

### Severity Levels

- **critical**: Exploitable vulnerability
- **high**: Likely vulnerability requiring review
- **medium**: Suspicious pattern
- **low**: Code smell
- **info**: Informational

## Pattern Library

Test suite results:

| Vulnerability | Detected | Test File |
|---------------|----------|----------|
| Underconstrained Assignment | Yes | `tests/real_vulnerabilities/underconstrained_multiplier.circom` |
| Weak Nullifier | Yes | `tests/real_vulnerabilities/weak_nullifier.circom` |
| Missing Range Check | Yes | `tests/real_vulnerabilities/missing_range_check.circom` |

Run `./validate.sh` to verify.

Pattern categories:
- Underconstrained circuits
- Nullifier issues  
- Range violations

## Use Cases

### Security Audits

```bash
# Scan entire project
find ./circuits -name "*.circom" -exec zkpm patterns/all.yaml {} \;
```

### CI/CD Integration

```bash
#!/bin/bash
zkpm patterns/critical.yaml src/circuit.circom
if [ $? -ne 0 ]; then
    echo "Critical vulnerabilities detected!"
    exit 1
fi
```

### Pattern Development

1. Discover vulnerability during audit
2. Encode as YAML pattern
3. Test against known vulnerable circuits
4. Add to pattern library
5. Share with community

## Extracted from ZkPatternFuzz

This library contains the pattern matching component from ZkPatternFuzz.

## Contributing

Contributions welcome.

## Pattern Sources

- zkBugs dataset
- Public audit reports
- CVE databases

## License

MIT - See [LICENSE.md](LICENSE.md) for details.

## Contact

**Teycir Ben Soltane**  
Email: teycir@pxdmail.net

## Citation

```bibtex
@software{zkpatternmatcher2025,
  title={ZkPatternMatcher: Pattern-Based Vulnerability Detection for Zero-Knowledge Proofs},
  author={Ben Soltane, Teycir},
  year={2025},
  url={https://github.com/Teycir/ZkPatternMatcher}
}
```

## Related Projects

- **[Circomspect](https://github.com/trailofbits/circomspect)** - Circom static analyzer
- **[Picus](https://github.com/zksecurity/picus)** - Noir static analyzer
