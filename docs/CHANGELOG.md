# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-02-27

### Added
- Initial release of ZkPatternMatcher
- YAML-based pattern matching for ZK circuit vulnerability detection
- Three independent crates: `pattern-types`, `pattern-loader`, `pattern-matcher`
- CLI tool (`zkpm`) with `scan`, `validate`, and `list` commands
- JSON and text output formats
- Security hardening: file size limits (10MB), pattern limits (1000), match limits (10K)
- Regex complexity protection (200 char limit)
- YAML bomb prevention (10K line limit)
- 20 comprehensive tests (8 unit, 7 CLI integration, 5 realistic workflow)
- 100% detection on 3 real vulnerability test cases
- Zero unsafe code, zero dependencies with known vulnerabilities

### Security
- Resource limits prevent DoS attacks
- Regex ReDoS protection via complexity limits
- YAML bomb protection via line count limits
- All error paths use proper Result types (no panics)

[Unreleased]: https://github.com/Teycir/ZkPatternMatcher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Teycir/ZkPatternMatcher/releases/tag/v0.1.0
