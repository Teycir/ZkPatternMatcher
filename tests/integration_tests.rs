use std::path::PathBuf;
use zk_pattern_matcher::*;

#[test]
fn test_load_pattern_library() {
    let path = PathBuf::from("patterns/underconstrained.yaml");
    let library = load_pattern_library(&path).expect("Failed to load pattern library");

    assert!(!library.patterns.is_empty());
    assert!(!library.invariants.is_empty());
}

#[test]
fn test_pattern_matching() {
    let library = PatternLibrary {
        patterns: vec![Pattern {
            id: "test_pattern".to_string(),
            kind: PatternKind::Regex,
            pattern: r"<--".to_string(),
            message: "Test message".to_string(),
            severity: Some(Severity::High),
        }],
        invariants: vec![],
    };

    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");
    let matches = matcher.scan_text("signal output c;\nc <-- a * b;");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].pattern_id, "test_pattern");
    assert_eq!(matches[0].severity, Severity::High);
}

#[test]
fn test_literal_pattern() {
    let library = PatternLibrary {
        patterns: vec![Pattern {
            id: "literal_test".to_string(),
            kind: PatternKind::Literal,
            pattern: "nullifier".to_string(),
            message: "Nullifier found".to_string(),
            severity: Some(Severity::Medium),
        }],
        invariants: vec![],
    };

    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");
    let matches = matcher.scan_text("signal input nullifier;");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].location.matched_text, "nullifier");
}
