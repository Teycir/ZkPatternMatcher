# pattern-types

Core types for ZK pattern matching.

## Usage

```rust
use pattern_types::*;

let pattern = Pattern {
    id: "test".to_string(),
    kind: PatternKind::Regex,
    pattern: r"<--".to_string(),
    message: "Unconstrained assignment".to_string(),
    severity: Some(Severity::Critical),
};
```

## Types

- `Pattern` - Pattern definition
- `PatternLibrary` - Collection of patterns
- `PatternMatch` - Match result
- `Severity` - Vulnerability severity levels
- `Invariant` - Constraint specifications

## License

MIT
