use std::path::Path;
use zk_pattern_matcher::{
    load_pattern_library, Pattern, PatternKind, PatternLibrary, PatternMatcher, Severity,
};

#[test]
fn semantic_mode_keeps_unconstrained_assignment_critical_without_hard_guard() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");

    let source = r#"
    pragma circom 2.0.0;
    template T() {
        signal x;
        x <-- 1;
        x * (1 - x) === 0;
    }
    component main = T();
    "#;

    let matcher = PatternMatcher::new(library)
        .expect("Failed to create matcher")
        .with_semantic(true);

    let strict_match = matcher
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "unconstrained_assignment")
        .expect("expected unconstrained_assignment match");

    assert_eq!(strict_match.severity, Severity::Critical);
    assert!(strict_match.message.contains("semantic context shows 'x'"));
}

#[test]
fn semantic_mode_keeps_signal_without_constraint_medium_without_hard_guard() {
    let library = PatternLibrary {
        patterns: vec![Pattern {
            id: "signal_without_constraint".to_string(),
            kind: PatternKind::Regex,
            pattern: r"^\s*signal\s+[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*<--\s*[^;]+;\s*$".to_string(),
            message: "Signal assigned without immediate constraint".to_string(),
            severity: Some(Severity::Medium),
        }],
        invariants: vec![],
    };

    let source = r#"
    pragma circom 2.0.0;
    template T() {
        signal x <-- 1;
        x === 1;
    }
    component main = T();
    "#;

    let matcher = PatternMatcher::new(library)
        .expect("Failed to create matcher")
        .with_semantic(true);

    let strict_match = matcher
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "signal_without_constraint")
        .expect("expected signal_without_constraint match");

    assert_eq!(strict_match.severity, Severity::Medium);
    assert!(strict_match.message.contains("semantic context shows 'x'"));
}
