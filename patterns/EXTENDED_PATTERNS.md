# Extended Pattern Packs

This directory includes pattern packs beyond the baseline `real_vulnerabilities.yaml` library.

## Current Status

- Scanner/CLI is stable.
- Extended packs are **targeted matrix-validated** in `tests/real_world_validation_matrix_tests.rs`.
- Current matrix scope: **16 vulnerable fixtures + 10 safe controls**.

## Included Packs

1. `production.yaml`: Curated production-focused checks.
2. `signal_aliasing.yaml`: Signal aliasing and unconstrained intermediates.
3. `missing_iszero.yaml`: IsZero/binary-constraint related checks.
4. `unchecked_division.yaml`: Division-by-zero risk indicators.
5. `array_bounds.yaml`: Signal-indexed access and loop-bound risk checks.
6. `equality_check.yaml`: `==`/`=` misuse vs Circom constraints.
7. `merkle_path.yaml`: Merkle root/path integrity checks.
8. `commitment_soundness.yaml`: Commitment/nullifier soundness checks.
9. `public_input_validation.yaml`: Public input declaration/usage checks.

## Validation Coverage

| Pattern Pack | Vulnerable Fixture(s) in Matrix | Safe Control in Matrix | Status |
|--------------|----------------------------------|-------------------------|--------|
| `signal_aliasing.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `missing_iszero.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `unchecked_division.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `array_bounds.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `equality_check.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `merkle_path.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `commitment_soundness.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `public_input_validation.yaml` | ✅ | ✅ | Targeted matrix-validated |
| `production.yaml` | ✅ | ✅ | Targeted matrix-validated |

## Usage

```bash
# Scan a circuit with a specific extended pack
zkpm patterns/merkle_path.yaml circuit.circom

# Run semantic-assisted scan for cross-line checks
zkpm --semantic patterns/equality_check.yaml circuit.circom
```

## Practical Limits

- Default matching is syntax-first and line-based.
- Regex/literal rules can still match comments or string content in non-semantic mode.
- Matrix validation is fixture-targeted, not full ecosystem benchmarking.
- `invariants` blocks are parsed and warned on, but not solver-enforced.

See `docs/reference/LIMITATIONS.md` for full limitations and roadmap.

