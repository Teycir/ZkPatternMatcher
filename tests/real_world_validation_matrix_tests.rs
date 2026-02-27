use std::collections::HashSet;
use std::path::Path;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, Severity};

struct RealWorldCase {
    name: &'static str,
    pattern_file: &'static str,
    circuit_file: &'static str,
    expected_pattern_ids: &'static [&'static str],
}

struct SafeControlCase {
    name: &'static str,
    pattern_file: &'static str,
    circuit_file: &'static str,
}

fn scan_case(
    pattern_file: &str,
    circuit_file: &str,
) -> anyhow::Result<Vec<zk_pattern_matcher::PatternMatch>> {
    let library = load_pattern_library(Path::new(pattern_file))?;
    let matcher = PatternMatcher::new(library)?;
    matcher.scan_file(Path::new(circuit_file))
}

#[test]
fn real_world_vulnerability_matrix_hits_expected_patterns() -> anyhow::Result<()> {
    let cases = [
        RealWorldCase {
            name: "underconstrained-multiplier-core",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/real_vulnerabilities/underconstrained_multiplier.circom",
            expected_pattern_ids: &["underconstrained_assignment"],
        },
        RealWorldCase {
            name: "weak-nullifier-core",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/real_vulnerabilities/weak_nullifier.circom",
            expected_pattern_ids: &["weak_nullifier_pattern"],
        },
        RealWorldCase {
            name: "missing-range-check-core",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/real_vulnerabilities/missing_range_check.circom",
            expected_pattern_ids: &["no_range_check"],
        },
        RealWorldCase {
            name: "arithmetic-overflow-fixture",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/real_vulnerabilities/arithmetic_overflow_real.circom",
            expected_pattern_ids: &["underconstrained_assignment", "bug_marker"],
        },
        RealWorldCase {
            name: "signal-aliasing-pack",
            pattern_file: "patterns/signal_aliasing.yaml",
            circuit_file: "tests/real_vulnerabilities/signal_aliasing.circom",
            expected_pattern_ids: &["intermediate_array_unconstrained"],
        },
        RealWorldCase {
            name: "unchecked-division-pack",
            pattern_file: "patterns/unchecked_division.yaml",
            circuit_file: "tests/real_vulnerabilities/unchecked_division.circom",
            expected_pattern_ids: &["division_operator_detected"],
        },
        RealWorldCase {
            name: "nullifier-collision-production",
            pattern_file: "patterns/production.yaml",
            circuit_file: "tests/real_vulnerabilities/nullifier_collision_real.circom",
            expected_pattern_ids: &["vulnerability_marker"],
        },
        RealWorldCase {
            name: "underconstrained-merkle-production",
            pattern_file: "patterns/production.yaml",
            circuit_file: "tests/real_vulnerabilities/underconstrained_merkle_real.circom",
            expected_pattern_ids: &["vulnerability_marker"],
        },
    ];

    for case in &cases {
        let matches = scan_case(case.pattern_file, case.circuit_file)?;
        let found_ids: HashSet<&str> = matches.iter().map(|m| m.pattern_id.as_str()).collect();

        let hit_expected = case
            .expected_pattern_ids
            .iter()
            .any(|expected| found_ids.contains(expected));

        assert!(
            hit_expected,
            "Case '{}' did not hit expected patterns {:?}. Found IDs: {:?}",
            case.name, case.expected_pattern_ids, found_ids
        );
    }

    Ok(())
}

#[test]
fn safe_controls_have_no_high_or_critical_findings() -> anyhow::Result<()> {
    let safe_cases = [
        SafeControlCase {
            name: "safe-multiplier-core-pack",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/safe_circuits/safe_multiplier.circom",
        },
        SafeControlCase {
            name: "safe-merkle-core-pack",
            pattern_file: "patterns/real_vulnerabilities.yaml",
            circuit_file: "tests/safe_circuits/safe_merkle.circom",
        },
        SafeControlCase {
            name: "safe-multiplier-production-pack",
            pattern_file: "patterns/production.yaml",
            circuit_file: "tests/safe_circuits/safe_multiplier.circom",
        },
        SafeControlCase {
            name: "safe-merkle-production-pack",
            pattern_file: "patterns/production.yaml",
            circuit_file: "tests/safe_circuits/safe_merkle.circom",
        },
    ];

    for case in &safe_cases {
        let matches = scan_case(case.pattern_file, case.circuit_file)?;
        let high_or_critical = matches
            .iter()
            .filter(|m| matches!(m.severity, Severity::Critical | Severity::High))
            .count();

        assert_eq!(
            high_or_critical, 0,
            "Safe control '{}' produced {} high/critical findings",
            case.name, high_or_critical
        );
    }

    Ok(())
}
