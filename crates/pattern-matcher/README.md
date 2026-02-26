# pattern-matcher

Pattern matching engine for ZK vulnerability detection.

## Usage

```rust
use pattern_types::*;
use pattern_matcher::PatternMatcher;

let library = PatternLibrary {
    patterns: vec![/* ... */],
    invariants: vec![],
};

let matcher = PatternMatcher::new(library)?;
let matches = matcher.scan_file("circuit.circom")?;
```

## Features

- Regex pattern matching
- Literal string matching
- Line-by-line scanning
- Location tracking

## License

MIT
