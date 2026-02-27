# ZkPatternMatcher

<div align="center">

```
                ┌─────────┐      ┌──────────┐      ┌─────────────────┐
                │ Circuit │ ───▶ │ Patterns │ ───▶ │ Vulnerabilities │
                │ ZK Code │      │  .yaml   │      │    Detected     │
                └─────────┘      └──────────┘      └─────────────────┘
```

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

</div>

A lightweight, standalone pattern matching library for detecting vulnerabilities in Zero-Knowledge proof circuits.

## Table of Contents

- [ZkPatternMatcher](#zkpatternmatcher)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Quick Start](#quick-start)
    - [Prove It Works: Run Validation Suite](#prove-it-works-run-validation-suite)
    - [1. Scan a Real Vulnerable Circuit](#1-scan-a-real-vulnerable-circuit)
    - [2. Validate a Pattern](#2-validate-a-pattern)
    - [3. List Patterns](#3-list-patterns)
    - [4. JSON Output](#4-json-output)
    - [5. Use as Library](#5-use-as-library)
  - [Pattern Format](#pattern-format)
    - [Pattern Types](#pattern-types)
    - [Severity Levels](#severity-levels)
  - [Pattern Library](#pattern-library)
  - [Use Cases](#use-cases)
    - [1. Pre-Audit Scanning](#1-pre-audit-scanning)
    - [2. CI/CD Integration](#2-cicd-integration)
    - [3. Pattern Development](#3-pattern-development)
    - [4. Batch Scanning](#4-batch-scanning)
    - [5. Differential Analysis](#5-differential-analysis)
  - [Documentation](#documentation)
  - [Contributing](#contributing)
  - [Pattern Sources](#pattern-sources)
  - [License](#license)
  - [Contact](#contact)
  - [Citation](#citation)
  - [Related Projects](#related-projects)

## Overview

Pattern matching library for ZK circuit vulnerability detection. Scans circuit code against YAML-defined patterns.

**Features:**
- YAML pattern definitions
- Regex and literal matching
- JSON/text output
- Configurable limits
- 314 LOC core

**Test Results:**
- 23/23 tests passing
- 3 real vulnerabilities detected
- 0 critical/high false positives on 2 safe circuits

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

### 3. List Patterns

```bash
zkpm list patterns/real_vulnerabilities.yaml
```

**Output:**
```
🔴 underconstrained_assignment [Critical] - Unconstrained assignment detected
🟠 missing_constraint_comment [High] - Missing constraint

Total: 5 patterns
```

### 4. JSON Output

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

### 5. Use as Library

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

### 1. Pre-Audit Scanning

```bash
# Scan circuits before manual review
for circuit in circuits/*.circom; do
    zkpm --format json patterns/critical.yaml "$circuit" >> scan_results.json
done
```

### 2. CI/CD Integration

```yaml
# .github/workflows/security.yml
name: ZK Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install zkpm
      - run: zkpm patterns/critical.yaml circuits/main.circom
```

### 3. Pattern Development

```bash
# Encode new vulnerability as pattern
cat > patterns/new_pattern.yaml <<EOF
patterns:
  - id: example_pattern
    kind: regex
    pattern: 'pattern_text'
    message: 'Description'
    severity: high
EOF

# Test pattern
zkpm patterns/new_pattern.yaml test_circuit.circom
```

### 4. Batch Scanning

```bash
# Scan multiple repositories
for repo in repos/*; do
    find "$repo" -name "*.circom" | while read file; do
        zkpm --format json patterns/all.yaml "$file" >> "results/${repo##*/}.json"
    done
done
```

### 5. Differential Analysis

```bash
# Compare scans before/after changes
git checkout main
zkpm --format json patterns/all.yaml circuit.circom > before.json

git checkout feature-branch
zkpm --format json patterns/all.yaml circuit.circom > after.json

diff <(jq -S . before.json) <(jq -S . after.json)
```

## Documentation

See [docs/INDEX.md](docs/INDEX.md) for complete documentation.

- **[QUICKSTART.md](docs/QUICKSTART.md)** - Step-by-step tutorial
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Contribution guide
- **[SECURITY.md](docs/SECURITY.md)** - Security policy
- **[CHANGELOG.md](docs/CHANGELOG.md)** - Version history
- **[CODE_OF_CONDUCT.md](docs/CODE_OF_CONDUCT.md)** - Community guidelines

## Contributing

Contributions welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## Pattern Sources

- zkBugs dataset
- Public audit reports
- CVE databases

## License

MIT - See [LICENSE.md](LICENSE.md) for details.

## Contact

**Teycir Ben Soltane**  
Email: teycir@pxdmail.net  
Website: https://teycirbensoltane.tn

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

- **[HoneypotScan](https://github.com/Teycir/honeypotscan)** - Smart contract honeypot detection
- **[Sanctum](https://github.com/Teycir/Sanctum)** - Privacy-focused security tools
- **[GhostChat](https://github.com/Teycir/GhostChat)** - Secure messaging platform
- **[Timeseal](https://github.com/Teycir/Timeseal)** - Timestamping and verification
