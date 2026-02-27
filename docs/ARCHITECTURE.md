# Architecture

ZkPatternMatcher is designed as a modular workspace with independently extractable crates.

## Workspace Structure

```
ZkPatternMatcher/
├── crates/
│   ├── pattern-types/      # Core types (zero dependencies)
│   ├── pattern-loader/     # YAML loading
│   └── pattern-matcher/    # Matching engine
├── src/                    # Root crate (re-exports)
├── tests/                  # Integration tests
└── patterns/               # Pattern library
```

## Crate Dependency Graph

```
pattern-types (no deps)
    ↑
    ├── pattern-loader (+ serde_yaml)
    └── pattern-matcher (+ regex)
         ↑
         └── zk-pattern-matcher (root)
```

## Extractable Components

Each crate can be used independently:

### 1. pattern-types

```toml
[dependencies]
pattern-types = { git = "https://github.com/Teycir/ZkPatternMatcher", package = "pattern-types" }
```

**Use case:** Define custom pattern types without loading/matching logic.

### 2. pattern-loader

```toml
[dependencies]
pattern-loader = { git = "https://github.com/Teycir/ZkPatternMatcher", package = "pattern-loader" }
```

**Use case:** Load YAML patterns into your own tool.

### 3. pattern-matcher

```toml
[dependencies]
pattern-matcher = { git = "https://github.com/Teycir/ZkPatternMatcher", package = "pattern-matcher" }
```

**Use case:** Use matching engine with custom pattern sources.

## Design Principles

1. **Minimal dependencies** - Each crate has only essential deps
2. **Clear boundaries** - Types → Loader → Matcher
3. **Independent publishing** - Each crate can be published separately
4. **Zero coupling** - No circular dependencies

## Extension Points

- **Custom pattern kinds**: Extend `PatternKind` enum
- **Custom loaders**: Implement alternative to YAML
- **Custom matchers**: Implement AST-based matching
- **Custom reporters**: Process `PatternMatch` results

## Future Modularization

Potential additional crates:
- `pattern-reporter` - Formatting and output
- `pattern-ast` - AST-based matching
- `pattern-cli` - CLI framework
