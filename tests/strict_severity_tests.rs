use std::path::Path;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, Severity};

#[test]
fn strict_severity_keeps_unconstrained_assignment_critical() {
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

    let relaxed = PatternMatcher::new(library.clone())
        .expect("Failed to create matcher")
        .with_semantic(true);
    let strict = PatternMatcher::new(library)
        .expect("Failed to create matcher")
        .with_semantic(true)
        .with_strict_severity(true);

    let relaxed_match = relaxed
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "unconstrained_assignment")
        .expect("expected unconstrained_assignment match");
    let strict_match = strict
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "unconstrained_assignment")
        .expect("expected unconstrained_assignment match");

    assert_eq!(relaxed_match.severity, Severity::Medium);
    assert_eq!(strict_match.severity, Severity::Critical);
    assert!(strict_match
        .message
        .contains("semantic context shows 'x' participates in constraints"));
}

#[test]
fn strict_severity_keeps_signal_without_constraint_medium() {
    let library = load_pattern_library(Path::new("patterns/production.yaml"))
        .expect("Failed to load patterns");

    let source = r#"
    pragma circom 2.0.0;
    template T() {
        signal x <-- 1;
        x === 1;
    }
    component main = T();
    "#;

    let relaxed = PatternMatcher::new(library.clone())
        .expect("Failed to create matcher")
        .with_semantic(true);
    let strict = PatternMatcher::new(library)
        .expect("Failed to create matcher")
        .with_semantic(true)
        .with_strict_severity(true);

    let relaxed_match = relaxed
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "signal_without_constraint")
        .expect("expected signal_without_constraint match");
    let strict_match = strict
        .scan_text(source)
        .into_iter()
        .find(|m| m.pattern_id == "signal_without_constraint")
        .expect("expected signal_without_constraint match");

    assert_eq!(relaxed_match.severity, Severity::Low);
    assert_eq!(strict_match.severity, Severity::Medium);
    assert!(strict_match
        .message
        .contains("semantic context shows 'x' participates in constraints"));
}
