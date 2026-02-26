# pattern-loader

YAML pattern loader for ZK vulnerability detection.

## Usage

```rust
use pattern_loader::load_pattern_library;

let library = load_pattern_library("patterns/my_patterns.yaml")?;
println!("Loaded {} patterns", library.patterns.len());
```

## Features

- Load patterns from YAML files
- Merge multiple pattern libraries
- Validation on load

## License

MIT
