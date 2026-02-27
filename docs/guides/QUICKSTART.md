# Quick Start Guide

## Installation

```bash
git clone https://github.com/teycir/ZkPatternMatcher.git
cd ZkPatternMatcher
cargo build --release
```

## Your First Scan

### 1. Scan the Example Circuit

```bash
./target/release/zkpm patterns/underconstrained.yaml examples/vulnerable.circom
```

**Output:**
```
Found 4 matches:

🟠 [High] Unconstrained assignment operator detected
   Pattern: unconstrained_assignment
   Location: 9:7
   Matched: <--
```

### 2. Validate a Pattern

```bash
./target/release/zkpm validate patterns/underconstrained.yaml
```

**Output:**
```
✓ Valid pattern library with 3 patterns
  1 invariants defined
```

### 3. Create Your Own Pattern

Create `my_pattern.yaml`:

```yaml
patterns:
  - id: my_check
    kind: literal
    pattern: 'TODO'
    message: 'TODO comment found'
    severity: info
```

Test it:

```bash
echo "// TODO: fix this" > test.txt
./target/release/zkpm my_pattern.yaml test.txt
```

## Use as Library

Add to `Cargo.toml`:

```toml
[dependencies]
zk-pattern-matcher = { path = "../ZkPatternMatcher" }
```

Use in code:

```rust
use zk_pattern_matcher::*;

fn main() -> anyhow::Result<()> {
    let library = load_pattern_library("patterns/underconstrained.yaml")?;
    let matcher = PatternMatcher::new(library)?;
    let matches = matcher.scan_file("circuit.circom")?;
    
    for m in matches {
        println!("{:?}: {}", m.severity, m.message);
    }
    
    Ok(())
}
```

## Next Steps

- Browse `patterns/` for more examples
- Read `../development/CONTRIBUTING.md` to add your own patterns
- Check out the parent project [ZkPatternFuzz](https://github.com/teycir/ZkPatternFuzz) for full security testing
