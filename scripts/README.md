# Scripts

Utility scripts for testing and validation.

## Validation Scripts

- **`validate.sh`** - Run baseline pattern validation tests
- **`validate_all.sh`** - Run full validation suite (core + extended patterns)

## Testing Scripts

- **`test_real_vulnerabilities.sh`** - Test real vulnerability fixtures
- **`test_extended_patterns.sh`** - Test extended pattern library
- **`test_integration.sh`** - Run integration tests

## Publishing

- **`publish.sh`** - Publish package to crates.io

## Usage

```bash
# From project root
./scripts/validate_all.sh

# Or make executable and run directly
chmod +x scripts/*.sh
./scripts/validate.sh
```
