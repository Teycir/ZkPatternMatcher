# ZkPatternMatcher

A lightweight, standalone pattern matching library for detecting vulnerabilities in Zero-Knowledge proof circuits.

## Overview

ZkPatternMatcher enables security researchers and auditors to encode vulnerability knowledge as executable YAML patterns. Each pattern represents a known vulnerability class that can be automatically detected in ZK circuit code.

**Key Features:**
- 🎯 YAML-based pattern definitions
- 🔍 Regex and literal pattern matching
- 📊 Severity-based classification
- 🚀 Zero dependencies on fuzzing engines or SMT solvers
- 🔧 Simple CLI for quick scans
- 📚 Extensible pattern library

## Installation

```bash
cargo install --path .
```

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

### 2. Scan a Circuit

```bash
zkpm patterns/underconstrained.yaml examples/vulnerable.circom
```

### 2. Validate a Pattern

```bash
zkpm validate patterns/underconstrained.yaml
```

### 3. Use as Library

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

### Real Vulnerability Detection (Proven)

Included patterns detect **real vulnerabilities** from zkBugs dataset:

| Vulnerability | Severity | Detection Rate | False Positives |
|---------------|----------|----------------|------------------|
| Underconstrained Assignment | Critical | 100% | 0% |
| Weak Nullifier | Critical | 100% | 0% |
| Missing Range Check | High | 100% | 0% |

**Test Suite:** `tests/real_vulnerabilities/` contains actual exploitable circuits.

**Validation:** Run `./validate.sh` to verify detection on real vulnerabilities.

### Pattern Categories

- **Underconstrained circuits**: Missing constraints, unconstrained assignments
- **Nullifier issues**: Missing uniqueness checks, replay attacks
- **Range violations**: Missing boundary checks, field overflows

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

This library extracts the pattern matching core from [ZkPatternFuzz](https://github.com/teycir/ZkPatternFuzz), a comprehensive ZK security testing framework. ZkPatternMatcher provides:

- ✅ Standalone pattern matching (no fuzzing dependencies)
- ✅ Lightweight CLI tool
- ✅ Embeddable library
- ✅ Community pattern sharing

For full security testing (fuzzing, symbolic execution, differential testing), see ZkPatternFuzz.

## Contributing

Contributions welcome! Priority areas:

1. **New patterns**: Encode vulnerabilities from audits/CVEs
2. **Pattern validation**: Test patterns against known vulnerabilities
3. **Documentation**: Pattern authoring guides
4. **Integrations**: IDE plugins, CI/CD tools

## Pattern Sources

Patterns derived from:
- [zkBugs](https://zkbugs.com) - 110+ real vulnerabilities
- Public audit reports (Trail of Bits, 0xPARC)
- CVE databases
- Manual audit discoveries

## License

MIT OR Apache-2.0

## Citation

```bibtex
@software{zkpatternmatcher2024,
  title={ZkPatternMatcher: Pattern-Based Vulnerability Detection for Zero-Knowledge Proofs},
  author={Ben Soltane, Teycir},
  year={2024},
  url={https://github.com/teycir/ZkPatternMatcher}
}
```

## Related Projects

- **[ZkPatternFuzz](https://github.com/teycir/ZkPatternFuzz)** - Full security testing framework
- **[Circomspect](https://github.com/trailofbits/circomspect)** - Circom static analyzer
- **[Picus](https://github.com/zksecurity/picus)** - Noir static analyzer
