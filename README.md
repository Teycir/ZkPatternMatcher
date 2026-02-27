# ZkPatternMatcher

<div align="center">

**Circuit Code → YAML Patterns → Vulnerabilities Detected**

[![CI](https://github.com/Teycir/ZkPatternMatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/Teycir/ZkPatternMatcher/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

⭐ **If you find this useful, please star the repo!** ⭐

![zkpm demo](docs/demo.gif)

</div>

A lightweight, standalone pattern matching library for detecting vulnerabilities in Zero-Knowledge proof circuits.

⚠️ **Status**: Early proof-of-concept with 3 core validated patterns + 2 developer markers. See [LIMITATIONS.md](LIMITATIONS.md) for full transparency on current capabilities.

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

**Status: Proof-of-Concept** - Currently detects 3 validated vulnerability patterns. Expanding pattern library actively.

**Core Validated Patterns:**
- ✅ Underconstrained assignments (`<--` operator)
- ✅ Weak nullifier assignments
- ✅ Missing range checks (via comment detection)

**Developer Markers (not vulnerability patterns):**
- 🔍 `BUG:` comment markers
- 🔍 `MISSING:` constraint markers

**⚠️ Important Limitations:**
- Regex/literal matching is syntax-based by default; this can match markers inside comments/strings
- Use `--semantic` to enable two-pass cross-line checks and reduce false positives
- Invariant system is aspirational (YAML parsed but not enforced yet; runtime warning emitted)
- Small test corpus (3 vulnerable + 2 safe circuits)
- See [LIMITATIONS.md](LIMITATIONS.md) for complete transparency

**Test Results:**
- 29/29 tests passing (23 unit + 6 integration)
- 3 real vulnerabilities validated (from ZkPatternFuzz)
- 0 false positives on 2 safe circuits
- Pattern files: `patterns/real_vulnerabilities.yaml` (5 entries: 3 patterns + 2 markers)

## Installation

```bash
# Install from source
cargo install --path . --locked
```

⚠️ **Security Note**: Use `--locked` to ensure reproducible builds with pinned dependencies. Dependencies are not pinned in `Cargo.toml` - see [LIMITATIONS.md](LIMITATIONS.md#security-considerations).

## Configuration

Configurable limits via `.zkpm.toml` (see `.zkpm.toml.example`):
- Max file size: 10MB
- Max pattern file: 1MB  
- Max patterns: 1000
- Max matches: 10000

## Quick Start

### Prove It Works: Run Validation Suite

```bash
# Run full validation (core + extended patterns)
./validate_all.sh

# Or run just extended pattern tests
./test_extended_patterns.sh
```

**Output:**
```
✓ ALL VALIDATION TESTS PASSED

Summary:
  - 29 unit + integration tests passed
  - 3 real vulnerabilities detected
  - 0 false positives on safe circuits
  - Pattern library: 3 core + 2 markers
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
```

⚠️ **IMPORTANT: Invariant System is Not Implemented**

The YAML schema includes an `invariants` section, but **this functionality does not exist yet**. Invariant blocks are parsed but silently ignored. Do not rely on invariant checking.

```yaml
# This section is ASPIRATIONAL - not functional
invariants:
  - name: output_fully_constrained
    invariant_type: constraint
    relation: "rank(constraint_matrix) == num_signals - 1"
    oracle: must_hold
    severity: critical
    description: "Output signals must be fully constrained"
```

See [LIMITATIONS.md](LIMITATIONS.md#invariant-system) for details.

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

**Current Status: 3 Core Patterns (Proof-of-Concept)**

⚠️ **Transparency Note**: This is an early-stage tool. The pattern library is intentionally small and focused on validation.

Validated patterns:

| Pattern | Status | Test File |
|---------|--------|----------|
| Underconstrained Assignment (`<--`) | ✅ Validated | `tests/real_vulnerabilities/underconstrained_multiplier.circom` |
| Weak Nullifier (`nullifier <--`) | ✅ Validated | `tests/real_vulnerabilities/weak_nullifier.circom` |
| Missing Range Check (comment) | ⚠️ Literal match | `tests/real_vulnerabilities/missing_range_check.circom` |

Developer markers (not vulnerability patterns):
- `BUG:` - Matches developer-written vulnerability markers
- `MISSING:` - Matches constraint TODO comments

Run `./validate.sh` to verify.

**Missing Coverage** (see [LIMITATIONS.md](LIMITATIONS.md)):
- Signal aliasing (name reuse)
- Missing IsZero constraints
- Unchecked division (zero divisor)
- Field arithmetic overflow
- Merkle path validation issues
- Signature verification weaknesses
- Commitment uniqueness problems
- Array bounds checks
- Bitwise operations without range proofs
- Equality checks vs constraints (`==` vs `===`)

**Pattern Files:**
- `patterns/real_vulnerabilities.yaml` - 3 validated patterns + 2 developer markers
- `patterns/signal_aliasing.yaml` - ⚠️ NEW: Signal aliasing detection (unvalidated)
- `patterns/missing_iszero.yaml` - ⚠️ NEW: IsZero component checks (unvalidated)
- `patterns/unchecked_division.yaml` - ⚠️ NEW: Division by zero detection (unvalidated)
- `patterns/array_bounds.yaml` - ⚠️ NEW: Array bounds checking (unvalidated)
- `patterns/equality_check.yaml` - ⚠️ NEW: Equality operator misuse (unvalidated)
- `patterns/extended_vulnerabilities.yaml` - Experimental patterns (not validated)
- `patterns/TEMPLATE.yaml` - Template for new patterns

⚠️ Only `real_vulnerabilities.yaml` is validated against real test circuits. New patterns in separate files are awaiting validation. See [patterns/EXTENDED_PATTERNS.md](patterns/EXTENDED_PATTERNS.md) for details.

See [PATTERN_GUIDE.md](PATTERN_GUIDE.md) to contribute patterns.

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
      - run: cargo install zkpm --version 0.1.0  # Pin version for reproducibility
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

### Adding New Patterns (Easy!)

**3-Step Process:**

1. **Copy template**: `cp patterns/TEMPLATE.yaml patterns/your_pattern.yaml`
2. **Fill in details**: Edit the YAML with your vulnerability pattern
3. **Test it**: `zkpm validate patterns/your_pattern.yaml`

See [PATTERN_GUIDE.md](PATTERN_GUIDE.md) for detailed instructions and examples.

**Quick Example:**
```yaml
patterns:
  - id: your_vulnerability
    kind: regex
    pattern: 'vulnerable_code_pattern'
    message: 'What this detects'
    severity: high
```

All contributions welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for full guidelines.

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
