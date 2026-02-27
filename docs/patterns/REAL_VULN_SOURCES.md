# Real Vulnerability Test Case Sources

## Where to Find Real Vulnerable Circuits

### 1. zkBugs Database (Primary Source)
**URL**: https://zkbugs.com  
**Coverage**: 110+ real vulnerabilities from production projects  
**Projects**: Tornado Cash, Semaphore, Iden3, SuccinctLabs, etc.

**How to Extract**:
```bash
# Clone zkBugs repository
git clone https://github.com/0xPARC/zkbugs

# Extract vulnerable circuits
find zkbugs/ -name "*.circom" -type f | grep -i "vuln\|bug\|bad"
```

### 2. Trail of Bits Public Audits
**URL**: https://github.com/trailofbits/publications  
**Filter**: Search for "circom" or "zero-knowledge"

**Example Findings**:
- Semaphore signal aliasing (2022)
- Tornado Cash Merkle path issues (2020)
- EdDSA malleability (CVE-2024-42459)

### 3. GitHub Security Advisories
**Search Query**: `language:Circom is:public archived:false`  
**Filter**: Issues/PRs with labels: `security`, `vulnerability`, `bug`

**Key Repositories**:
- `iden3/circomlib` - Standard library vulnerabilities
- `tornadocash/tornado-core` - Mixer vulnerabilities
- `semaphore-protocol/semaphore` - Identity vulnerabilities

### 4. Solodit ZK Audit Reports
**URL**: https://solodit.xyz  
**Filter**: Tag: `zk-proof`, Severity: `High`/`Critical`

**Extract Patterns**:
1. Read audit report PDF
2. Find "Vulnerable Code" section
3. Extract Circom snippet
4. Add to `tests/real_vulnerabilities/`

### 5. Academic Papers (0xPARC, a16z crypto)
**Sources**:
- 0xPARC Applied ZK Learning Group
- a16z crypto research blog
- IACR ePrint Archive (search: "circom vulnerability")

## Adding New Test Cases

### Step 1: Verify Authenticity
```bash
# Check if circuit is from real project
git log --all --full-history -- path/to/circuit.circom

# Verify CVE/advisory reference
curl -s "https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX"
```

### Step 2: Document Source
```circom
pragma circom 2.0.0;

// VULNERABILITY: [Brief description]
// Source: [Project name, GitHub URL, or CVE ID]
// Impact: [Attack vector and consequences]
// CVE: [CVE-XXXX-XXXXX if applicable]
// Discovered: [Date or audit firm]

template VulnerableCircuit() {
    // ... vulnerable code ...
}
```

### Step 3: Add to Test Suite
```bash
# Place in appropriate subdirectory
cp vulnerable.circom tests/real_vulnerabilities/[category]/

# Update INTEGRATION_TEST_MATRIX.md
echo "### N. vulnerable.circom" >> INTEGRATION_TEST_MATRIX.md
echo "**Source**: [Project/CVE]" >> INTEGRATION_TEST_MATRIX.md
echo "**Expected Matches**: [pattern_id] (SEVERITY)" >> INTEGRATION_TEST_MATRIX.md
```

### Step 4: Validate Detection
```bash
# Test pattern detection
cargo run --release --bin zkpm -- scan \
  tests/real_vulnerabilities/[category]/vulnerable.circom \
  --pattern patterns/[relevant_pattern].yaml

# Verify expected findings match
diff <(cargo run ... | grep "pattern_id") <(echo "expected_pattern_id")
```

## Current Real Test Cases (Verified)

| Circuit | Source | CVE/Reference | Patterns Tested |
|---------|--------|---------------|-----------------|
| underconstrained_merkle_real.circom | Tornado Cash audit | zkBugs #42 | unconstrained_path_direction |
| weak_nullifier.circom | StealthDrop | zkBugs #67 | nullifier_without_secret |
| signal_aliasing.circom | Semaphore audit | Trail of Bits 2022 | intermediate_array_unconstrained |
| equality_no_constraint.circom | Iden3 circomlib | GitHub issue #234 | comparison_instead_of_constraint |

## Synthetic vs Real Distinction

**Real** (keep):
- Extracted from production codebases
- Referenced in public audits/CVEs
- Demonstrates actual exploited vulnerability

**Synthetic** (remove):
- Created for testing only
- No real-world project reference
- Artificial vulnerability patterns

## Validation Checklist

- [ ] Circuit has documented source (project/CVE/audit)
- [ ] Vulnerability was exploited or reported in real audit
- [ ] Code matches original vulnerable version (not fixed)
- [ ] Pattern detection validated against expected findings
- [ ] Added to INTEGRATION_TEST_MATRIX.md
- [ ] Committed with source attribution in header comment
