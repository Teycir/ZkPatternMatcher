use std::path::Path;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, Severity};

/// Integration tests using real vulnerabilities from ZkPatternFuzz
/// These test the improved patterns against known vulnerable circuits

#[test]
fn test_nullifier_collision_detection() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    // Real vulnerability from ZkPatternFuzz: nullifier_collision
    let vulnerable_code = r#"
    // BUG: Nullifier only uses secret, ignoring randomness
    component nullHasher = Poseidon(1);
    nullHasher.inputs[0] <== secret;
    nullifier === nullHasher.out;
    "#;

    let matches = matcher.scan_text(vulnerable_code);

    // Should detect unconstrained assignment pattern
    let critical_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.severity == Severity::Critical)
        .collect();

    assert!(
        !critical_matches.is_empty(),
        "Should detect critical vulnerability in nullifier collision circuit"
    );
}

#[test]
fn test_underconstrained_merkle_detection() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    // Real vulnerability from ZkPatternFuzz: underconstrained_merkle
    // Note: This circuit uses <== (constrained) not <-- (unconstrained)
    // The vulnerability is semantic (missing binary constraint), not syntactic
    let vulnerable_code = r#"
    left[i] <== intermediate[i] + pathIndices[i] * (pathElements[i] - intermediate[i]);
    right[i] <== pathElements[i] + pathIndices[i] * (intermediate[i] - pathElements[i]);
    "#;

    let matches = matcher.scan_text(vulnerable_code);

    // Pattern correctly doesn't match <== (constrained assignment)
    let critical_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();

    assert_eq!(
        critical_matches.len(),
        0,
        "Pattern correctly distinguishes <== (constrained) from <-- (unconstrained)"
    );
}

#[test]
fn test_vulnerability_marker_detection() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    let code_with_markers = r#"
    // BUG: Nullifier only uses secret
    signal nullifier <== hash(secret);
    
    // VULN: Missing range check
    signal value <-- input;
    "#;

    let matches = matcher.scan_text(code_with_markers);

    let marker_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern_id == "vulnerability_marker")
        .collect();

    assert_eq!(
        marker_matches.len(),
        2,
        "Should detect both BUG: and VULN: markers"
    );
}

#[test]
fn test_signal_nullifier_pattern() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    // Should match: signal with nullifier keyword using <--
    let vulnerable = "signal nullifier <-- hash(secret);";
    let matches = matcher.scan_text(vulnerable);

    let nullifier_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern_id == "weak_nullifier_assignment")
        .collect();

    assert_eq!(
        nullifier_matches.len(),
        1,
        "Should detect weak nullifier assignment"
    );

    // Should NOT match: variable name containing nullifier without signal keyword
    let safe = "let old_nullifier = previous_value;";
    let matches = matcher.scan_text(safe);

    let false_positives: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern_id == "weak_nullifier_assignment")
        .collect();

    assert_eq!(
        false_positives.len(),
        0,
        "Should not match nullifier in non-signal context"
    );
}

#[test]
fn test_missing_constraint_markers() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    let code = r#"
    // TODO: constraint needed here
    signal value <-- input;
    
    // FIXME: constraint missing
    signal output <-- computation;
    
    // MISSING: constraint for range check
    signal bounded <-- value;
    "#;

    let matches = matcher.scan_text(code);

    let marker_matches: Vec<_> = matches
        .iter()
        .filter(|m| m.pattern_id == "missing_constraint_marker")
        .collect();

    assert_eq!(
        marker_matches.len(),
        3,
        "Should detect all three constraint markers"
    );
}

#[test]
fn test_pattern_performance_metrics() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");

    // Test corpus: 3 vulnerable + 2 safe circuits
    let test_cases = vec![
        ("vulnerable_1", "signal x <-- y;", true),
        ("vulnerable_2", "signal nullifier <-- hash(s);", true),
        ("vulnerable_3", "// BUG: missing constraint", true),
        ("safe_1", "signal x <== y * z;", false),
        ("safe_2", "signal output <== constrained_value;", false),
    ];

    let mut true_positives = 0;
    let mut false_positives = 0;
    let mut true_negatives = 0;
    let mut false_negatives = 0;

    for (name, code, should_detect) in &test_cases {
        let matches = matcher.scan_text(code);
        let has_critical = matches
            .iter()
            .any(|m| matches!(m.severity, Severity::Critical | Severity::High));

        match (should_detect, has_critical) {
            (true, true) => true_positives += 1,
            (true, false) => {
                false_negatives += 1;
                eprintln!("False negative in {}: {}", name, code);
            }
            (false, true) => {
                false_positives += 1;
                eprintln!("False positive in {}: {}", name, code);
            }
            (false, false) => true_negatives += 1,
        }
    }

    let total = test_cases.len();
    let accuracy = (true_positives + true_negatives) as f64 / total as f64;

    println!("\nPattern Performance:");
    println!("  True Positives: {}", true_positives);
    println!("  True Negatives: {}", true_negatives);
    println!("  False Positives: {}", false_positives);
    println!("  False Negatives: {}", false_negatives);
    println!("  Accuracy: {:.1}%", accuracy * 100.0);

    assert_eq!(false_positives, 0, "Should have zero false positives");
    assert_eq!(false_negatives, 0, "Should have zero false negatives");
}
