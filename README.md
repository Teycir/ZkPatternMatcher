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

**Status**: Stable scanner and CLI supporting `regex`, `fancyregex`, `literal`, and optional two-pass semantic checks (`--semantic`). Validation includes a baseline pack (3 vulnerability patterns + 2 developer markers) and an automated real-world matrix (16 vulnerable fixtures + 10 safe controls). See [docs/reference/LIMITATIONS.md](docs/reference/LIMITATIONS.md) for full transparency on current capabilities.

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
    - [Adding New Patterns (Easy!)](#adding-new-patterns-easy)
  - [Pattern Sources](#pattern-sources)
  - [License](#license)
  - [Contact](#contact)
  - [Citation](#citation)
  - [Related Projects](#related-projects)

## Overview

Pattern matching library for ZK circuit vulnerability detection. Scans circuit code against YAML-defined patterns.

**Status: Stable** - Baseline validation is stable (3 vulnerability patterns + 2 markers), and the automated real-world matrix currently covers 16 vulnerable fixtures (+ 10 safe controls).

**Baseline Validated Patterns:**
- ✅ Underconstrained assignments (`<--` operator)
- ✅ Weak nullifier assignments
- ✅ Missing range checks (via comment detection)

**Developer Markers (not vulnerability patterns):**
- 🔍 `BUG:` comment markers
- 🔍 `MISSING:` constraint markers

**⚠️ Important Limitations:**
- Matching engines include regex/fancyregex/literal, but default scanning is syntax-first and can match markers in comments/strings
- Use `--semantic` to enable two-pass cross-line checks and reduce false positives
- Invariant blocks are parsed and surfaced as runtime warnings; solver-backed enforcement is planned
- Real-world corpus is expanding; automated matrix currently includes 16 vulnerable fixtures + 10 safe controls
- See [docs/reference/LIMITATIONS.md](docs/reference/LIMITATIONS.md) for complete transparency

**Test Results:**
- `cargo test -q` passes locally (39 passed, 1 ignored integration test)
- 16 real-world vulnerability fixtures validated in the automated matrix (+ 10 safe controls)
- 0 high/critical false positives on 10 safe controls in the matrix
- Pattern files: `patterns/real_vulnerabilities.yaml` (5 entries: 3 patterns + 2 markers)

## Installation

MSRV: **Rust 1.80+** (uses `std::sync::LazyLock` in semantic analysis internals).

```bash
# Install from source
cargo install --path . --locked
```

⚠️ **Security Note**: Use `--locked` to ensure reproducible builds with pinned dependencies. Dependencies are not pinned in `Cargo.toml` - see [docs/reference/LIMITATIONS.md](docs/reference/LIMITATIONS.md#security-considerations).

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
  - Rust unit + integration suites passed
  - Real-world matrix: 16 vulnerable fixtures + 10 safe controls
  - 0 high/critical false positives on the safe controls
  - Pattern packs include baseline + extended libraries
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

⚠️ **IMPORTANT: Invariant Enforcement Status**

The YAML schema includes an `invariants` section. In the current release, invariants are parsed and surfaced via runtime warnings, but they are not solver-enforced yet. Treat them as structured metadata/check intent, not as cryptographic proof guarantees.

```yaml
# This section is schema-level metadata (warning-only in current release)
invariants:
  - name: output_fully_constrained
    invariant_type: constraint
    relation: "rank(constraint_matrix) == num_signals - 1"
    oracle: must_hold
    severity: critical
    description: "Output signals must be fully constrained"
```

See [docs/reference/LIMITATIONS.md](docs/reference/LIMITATIONS.md#invariant-system) for details.

### Pattern Types

- **regex**: Regular expression matching
- **fancyregex**: Advanced regex matching (supports backreferences/lookaround)
- **literal**: Exact string matching
- **ast**: Reserved schema kind; currently rejected at load time with an explicit error

### Severity Levels

- **critical**: Exploitable vulnerability
- **high**: Likely vulnerability requiring review
- **medium**: Suspicious pattern
- **low**: Code smell
- **info**: Informational

## Pattern Library

**Current Status: Stable baseline + expanding matrix validation (16 vulnerable fixtures, 10 safe controls)**
⚠️ **Transparency Note**: Baseline coverage is deepest in `real_vulnerabilities.yaml`. Extended packs are validated per-fixture via the matrix and are intended for practical triage with reviewer confirmation.

Baseline validated patterns (`patterns/real_vulnerabilities.yaml`):

| Pattern | Status | Test File |
|---------|--------|----------|
| Underconstrained Assignment (`<--`) | ✅ Validated | `tests/real_vulnerabilities/underconstrained_multiplier.circom` |
| Weak Nullifier (`nullifier <--`) | ✅ Validated | `tests/real_vulnerabilities/weak_nullifier.circom` |
| Missing Range Check (comment) | ⚠️ Literal match | `tests/real_vulnerabilities/missing_range_check.circom` |

Developer markers (not vulnerability patterns):
- `BUG:` - Matches developer-written vulnerability markers
- `MISSING:` - Matches constraint TODO comments

Run `./validate.sh` to verify.

Matrix-validated extended detections:

| Pattern Pack | Expected Detection(s) | Fixture |
|---------|--------|----------|
| `patterns/signal_aliasing.yaml` | `intermediate_array_unconstrained` | `tests/real_vulnerabilities/signal_aliasing.circom` |
| `patterns/unchecked_division.yaml` | `division_operator_detected` | `tests/real_vulnerabilities/unchecked_division.circom` |
| `patterns/production.yaml` | `vulnerability_marker` | `tests/real_vulnerabilities/nullifier_collision_real.circom` |
| `patterns/production.yaml` | `vulnerability_marker` | `tests/real_vulnerabilities/underconstrained_merkle_real.circom` |
| `patterns/array_bounds.yaml` | `signal_indexed_array_access` | `tests/real_vulnerabilities/array_no_bounds.circom` |
| `patterns/array_bounds.yaml` | `signal_dependent_loop_bound` | `tests/real_vulnerabilities/unbounded_loop.circom` |
| `patterns/equality_check.yaml` | `comparison_instead_of_constraint` | `tests/real_vulnerabilities/equality_no_constraint.circom` |
| `patterns/merkle_path.yaml` | `merkle_root_comparison_not_constraint` | `tests/real_vulnerabilities/merkle_path/unconstrained_direction_vuln.circom` |
| `patterns/commitment_soundness.yaml` | `deterministic_commitment` | `tests/real_vulnerabilities/commitment_soundness/deterministic_commit_vuln.circom` |
| `patterns/commitment_soundness.yaml` | `nullifier_without_secret` | `tests/real_vulnerabilities/commitment_soundness/nullifier_no_secret_vuln.circom` |
| `patterns/public_input_validation.yaml` | `public_input_declared` | `tests/real_vulnerabilities/nullifier_collision_real.circom` |
| `patterns/missing_iszero.yaml` | `direct_zero_comparison_branch` | `tests/real_vulnerabilities/missing_iszero.circom` |

**Coverage Notes** (see [docs/reference/LIMITATIONS.md](docs/reference/LIMITATIONS.md)):
- `patterns/real_vulnerabilities.yaml` remains the strongest baseline pack with full end-to-end validation coverage.
- Extended packs now have targeted matrix tests for specific real-world fixtures.
- Validation depth varies by pack; matrix coverage continues to expand.

**Pattern Files:**
- `patterns/real_vulnerabilities.yaml` - 3 validated patterns + 2 developer markers
- `patterns/production.yaml` - curated production-focused set with targeted matrix validation
- `patterns/underconstrained.yaml` - focused underconstrained assignment rules
- `patterns/signal_aliasing.yaml` - Signal aliasing detection (targeted matrix validation)
- `patterns/missing_iszero.yaml` - IsZero-related checks (targeted matrix validation)
- `patterns/unchecked_division.yaml` - Division by zero detection (targeted matrix validation)
- `patterns/array_bounds.yaml` - Array bounds checking (targeted matrix validation)
- `patterns/equality_check.yaml` - Equality operator misuse (targeted matrix validation)
- `patterns/merkle_path.yaml` - Merkle path validation checks (targeted matrix validation)
- `patterns/commitment_soundness.yaml` - Commitment checks (targeted matrix validation)
- `patterns/public_input_validation.yaml` - Public input validation checks (targeted matrix validation)
- `patterns/TEMPLATE.yaml` - Template for new patterns

⚠️ `real_vulnerabilities.yaml` has the deepest validation coverage. Extended packs already have targeted real-world matrix validation, and broader fixture coverage is added incrementally. See [patterns/EXTENDED_PATTERNS.md](patterns/EXTENDED_PATTERNS.md) for details.

See [docs/patterns/PATTERN_GUIDE.md](docs/patterns/PATTERN_GUIDE.md) to contribute patterns.

## Use Cases

### 1. Pre-Audit Scanning

```bash
# Scan circuits before manual review
for circuit in circuits/*.circom; do
    zkpm --format json patterns/production.yaml "$circuit" >> scan_results.json
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
      - run: zkpm patterns/production.yaml circuits/main.circom
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
        zkpm --format json patterns/production.yaml "$file" >> "results/${repo##*/}.json"
    done
done
```

### 5. Differential Analysis

```bash
# Compare scans before/after changes
git checkout main
zkpm --format json patterns/production.yaml circuit.circom > before.json

git checkout feature-branch
zkpm --format json patterns/production.yaml circuit.circom > after.json

diff <(jq -S . before.json) <(jq -S . after.json)
```

## Documentation

See [docs/INDEX.md](docs/INDEX.md) for complete documentation.

- **[QUICKSTART.md](docs/guides/QUICKSTART.md)** - Step-by-step tutorial
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design
- **[CONTRIBUTING.md](docs/development/CONTRIBUTING.md)** - Contribution guide
- **[SECURITY.md](docs/SECURITY.md)** - Security policy
- **[CHANGELOG.md](docs/CHANGELOG.md)** - Version history
- **[CODE_OF_CONDUCT.md](docs/development/CODE_OF_CONDUCT.md)** - Community guidelines

## Contributing

### Adding New Patterns (Easy!)

**3-Step Process:**

1. **Copy template**: `cp patterns/TEMPLATE.yaml patterns/your_pattern.yaml`
2. **Fill in details**: Edit the YAML with your vulnerability pattern
3. **Test it**: `zkpm validate patterns/your_pattern.yaml`

See [docs/patterns/PATTERN_GUIDE.md](docs/patterns/PATTERN_GUIDE.md) for detailed instructions and examples.

**Quick Example:**
```yaml
patterns:
  - id: your_vulnerability
    kind: regex
    pattern: 'vulnerable_code_pattern'
    message: 'What this detects'
    severity: high
```

All contributions welcome. See [CONTRIBUTING.md](docs/development/CONTRIBUTING.md) for full guidelines.

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
