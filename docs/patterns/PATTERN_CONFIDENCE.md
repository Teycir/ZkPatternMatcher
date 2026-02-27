# Pattern Confidence and Limitations

## ⚠️ Important: Regex Patterns Are Hints, Not Proofs

**ZkPatternMatcher uses two detection methods with different confidence levels:**

### 1. Regex Patterns (Medium Confidence)
- **What they do**: Match text patterns in source code
- **Confidence**: Medium - requires manual review
- **False positives**: Possible (safe code may match patterns)
- **Use case**: Triage and initial screening

**Example**:
```yaml
# This pattern matches ANY use of ==, including safe comparisons
pattern: '\w+\s*==\s*\w+\s*;'
```

### 2. Semantic Analysis (High Confidence)
- **What they do**: Analyze code structure across multiple lines
- **Confidence**: High - structural validation
- **False positives**: Rare (validates actual constraint relationships)
- **Use case**: Confirmed vulnerability detection

**Example**:
```rust
// Detects signal assigned with <-- but never constrained with ===
check_orphaned_unconstrained(&assignments)
```

## Pattern Severity Guidelines

| Severity | Confidence | Meaning |
|----------|-----------|---------|
| **CRITICAL** (Semantic) | High | Structural vulnerability confirmed |
| **HIGH** (Semantic) | High | Likely vulnerability, needs context review |
| **MEDIUM** (Regex) | Medium | Suspicious pattern, manual review required |
| **LOW** (Regex) | Low | Code smell, may be intentional |
| **INFO** (Regex) | N/A | Informational, not a vulnerability |

## Recommended Workflow

```bash
# Step 1: Run pattern scan (triage)
zkpm patterns/ circuit.circom > findings.txt

# Step 2: Review CRITICAL/HIGH findings first (semantic analysis)
grep "CRITICAL\|HIGH" findings.txt

# Step 3: Manually review MEDIUM findings (regex hints)
# - Check if <-- has corresponding ===
# - Verify == is not used for constraints
# - Confirm pathIndices are binary-constrained

# Step 4: Use complementary tools for confirmation
circomspect circuit.circom  # Static analysis
ecne verify circuit.circom  # Formal verification
```

## Known Limitations

### Regex Patterns
1. **Cannot detect multi-line relationships**
   - `x <-- compute()` on line 10
   - `x === expected` on line 15
   - Regex sees these as separate, unrelated lines

2. **Cannot understand context**
   - `if (condition) { x == y; }` may be safe boolean comparison
   - Regex flags all `==` usage

3. **Array normalization**
   - `vals[0]`, `vals[1]` normalized to `vals`
   - May cause false positives in aliasing detection

### Semantic Analysis
1. **Template-scoped only**
   - Does not track signals across template boundaries
   - Component composition analysis not yet implemented

2. **No data flow analysis**
   - Cannot prove constraint is sufficient
   - Only detects missing constraints

## False Positive Mitigation

### Current (v0.1.0)
- Semantic analysis for cross-line validation
- Template-scoped signal tracking
- Array index normalization

### Planned (v0.2.0 - see ROADMAP.md)
- `--warn-only` mode for all findings
- Circom-aware parser (subset grammar)
- Constraint-pairing validation within N lines
- Benchmark suite with FP/FN rates

### Planned (v0.3.0+)
- Full Circom AST integration
- Symbolic execution (Z3/CVC5)
- Data flow analysis

## Reporting False Positives

If you encounter a false positive:

1. **Verify it's actually safe**:
   ```bash
   # Compile and test the circuit
   circom circuit.circom --r1cs --wasm
   # Run witness generation with test inputs
   ```

2. **Open an issue** with:
   - Circuit code snippet
   - Pattern that fired
   - Explanation of why it's safe
   - Label: `false-positive`

3. **We will**:
   - Add to test suite as negative case
   - Refine pattern or add exclusion rule
   - Update documentation

## Benchmark Results

See `BENCHMARK_RESULTS.md` (coming in v0.2.0) for:
- False Positive Rate on circomlib
- Recall on zkBugs dataset
- Precision/Recall by pattern category

## Summary

✅ **Use semantic findings (CRITICAL/HIGH) as strong signals**  
⚠️ **Treat regex findings (MEDIUM/LOW) as hints requiring manual review**  
📊 **Benchmark data coming in v0.2.0 to quantify FP/FN rates**  
🔧 **Parser integration in v0.3.0 will significantly reduce false positives**

**ZkPatternMatcher is a triage tool, not a proof system. Always validate findings manually or with formal verification tools.**
