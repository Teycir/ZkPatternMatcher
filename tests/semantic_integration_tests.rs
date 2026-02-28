use zk_pattern_matcher::{Pattern, PatternKind, PatternLibrary, PatternMatcher, Severity};

fn semantic_finding_matches(source: &str) -> Vec<zk_pattern_matcher::PatternMatch> {
    PatternMatcher::new(PatternLibrary {
        patterns: vec![],
        invariants: vec![],
    })
    .expect("matcher")
    .with_semantic(true)
    .scan_text(source)
}

fn unconstrained_library(pattern: &str) -> PatternLibrary {
    PatternLibrary {
        patterns: vec![Pattern {
            id: "unconstrained_assignment".to_string(),
            kind: PatternKind::Regex,
            pattern: pattern.to_string(),
            message: "Unconstrained assignment operator (<--) detected".to_string(),
            severity: Some(Severity::Critical),
        }],
        invariants: vec![],
    }
}

#[test]
fn does_not_flag_orphaned_when_signal_is_constrained_on_rhs() {
    let source = r#"
    template T() {
        signal one_hot[4];
        signal input idx;
        for (var i = 0; i < 4; i++) {
            one_hot[i] <-- (idx == i ? 1 : 0);
            one_hot[i] * (1 - one_hot[i]) === 0;
        }
    }
    "#;

    let findings = semantic_finding_matches(source);
    assert!(findings
        .iter()
        .all(|f| f.pattern_id != "orphaned_unconstrained_assignment"));
}

#[test]
fn still_flags_orphaned_when_signal_is_never_constrained() {
    let source = r#"
    template T() {
        signal x;
        x <-- 7;
        signal y;
        y <== 1;
    }
    "#;

    let findings = semantic_finding_matches(source);
    assert!(findings
        .iter()
        .any(|f| f.pattern_id == "orphaned_unconstrained_assignment"));
}

#[test]
fn self_equality_does_not_hide_orphaned_unconstrained_signal() {
    let source = r#"
    template T() {
        signal x;
        x <-- 1;
        x === x;
    }
    "#;

    let findings = semantic_finding_matches(source);
    assert!(findings
        .iter()
        .any(|f| f.pattern_id == "orphaned_unconstrained_assignment"));
    assert!(findings
        .iter()
        .any(|f| f.pattern_id == "self_equality_constraint"));
}

#[test]
fn component_aliasing_on_input_is_medium_review_signal() {
    let source = r#"
    template T() {
        signal input a;
        c1.in <== a;
        c2.in <== a;
    }
    "#;

    let findings = semantic_finding_matches(source);
    let alias = findings
        .iter()
        .find(|f| f.pattern_id == "component_input_aliasing")
        .expect("expected aliasing finding");
    assert_eq!(alias.severity, Severity::Medium);
}

#[test]
fn component_aliasing_of_unconstrained_signal_is_medium() {
    let source = r#"
    template T() {
        signal x;
        x <-- 1;
        c1.in <== x;
        c2.in <== x;
    }
    "#;

    let findings = semantic_finding_matches(source);
    let alias = findings
        .iter()
        .find(|f| f.pattern_id == "component_input_aliasing")
        .expect("expected aliasing finding");
    assert_eq!(alias.severity, Severity::Medium);
}

#[test]
fn component_aliasing_of_constrained_unconstrained_signal_is_medium() {
    let source = r#"
    template T() {
        signal x;
        x <-- 1;
        c1.in <== x;
        c2.in <== x;
        x === 1;
    }
    "#;

    let findings = semantic_finding_matches(source);
    let alias = findings
        .iter()
        .find(|f| f.pattern_id == "component_input_aliasing")
        .expect("expected aliasing finding");
    assert_eq!(alias.severity, Severity::Medium);
}

#[test]
fn single_local_constraint_does_not_trigger_hard_guard_for_unconstrained_assignment() {
    let source = r#"
    template T() {
        signal x;
        x <-- 1;
        x * (1 - x) === 0;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);
}

#[test]
fn semantic_calibration_preserves_critical_without_constraints() {
    let source = r#"
    template T() {
        signal x;
        x <-- 1;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);
}

#[test]
fn single_local_constraint_does_not_trigger_hard_guard_for_signal_without_constraint() {
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
    template T() {
        signal x <-- y;
        x === y;
    }
    "#;

    let matcher = PatternMatcher::new(library)
        .expect("matcher")
        .with_semantic(true);
    let heuristic: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "signal_without_constraint")
        .collect();
    assert_eq!(heuristic.len(), 1);
    assert_eq!(heuristic[0].severity, Severity::Medium);
}

#[test]
fn indexed_signal_with_only_local_binary_check_remains_reported() {
    let source = r#"
    template T() {
        signal output out[4];
        out[0] <-- 1;
        out[0] * (1 - out[0]) === 0;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);
}

#[test]
fn dotted_signal_with_single_recomposition_line_remains_reported() {
    let source = r#"
    template T() {
        signal input in;
        k_bits.in <-- in \ 7;
        k_bits.in * 7 === in;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);
}

#[test]
fn dedup_removes_signal_without_constraint_when_unconstrained_exists_same_line() {
    let library = PatternLibrary {
        patterns: vec![
            Pattern {
                id: "unconstrained_assignment".to_string(),
                kind: PatternKind::Regex,
                pattern: r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$".to_string(),
                message: "Unconstrained assignment operator (<--) detected".to_string(),
                severity: Some(Severity::Critical),
            },
            Pattern {
                id: "signal_without_constraint".to_string(),
                kind: PatternKind::Regex,
                pattern: r"^\s*signal\s+[A-Za-z_]\w*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$"
                    .to_string(),
                message: "Signal assigned without immediate constraint".to_string(),
                severity: Some(Severity::Medium),
            },
        ],
        invariants: vec![],
    };

    let source = r#"
    template T() {
        signal x <-- 1;
        x === 1;
    }
    "#;

    let matcher = PatternMatcher::new(library)
        .expect("matcher")
        .with_semantic(true);
    let matches = matcher.scan_text(source);

    let unconstrained_count = matches
        .iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .count();
    let heuristic_count = matches
        .iter()
        .filter(|m| m.pattern_id == "signal_without_constraint")
        .count();

    assert_eq!(unconstrained_count, 1);
    assert_eq!(heuristic_count, 0);
}

#[test]
fn hard_guard_suppresses_bitness_plus_var_recomposition_pattern() {
    let source = r#"
    template T() {
        signal input in;
        signal out[2];
        var lc = 0;

        out[0] <-- 0;
        out[1] <-- 0;
        out[0] * (out[0] - 1) === 0;
        out[1] * (out[1] - 1) === 0;

        lc += out[0];
        lc += out[1] * 2;
        lc === in;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert!(unconstrained.is_empty());
}

#[test]
fn hard_guard_suppresses_bits_component_wiring_plus_recomposition() {
    let source = r#"
    template T() {
        signal input in;
        signal q;
        component to_bits;

        q <-- in \ 7;
        to_bits.in <== q;
        q * 7 === in;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert!(unconstrained.is_empty());
}

#[test]
fn hard_guard_keeps_single_equation_unchecked_division_flagged() {
    let source = r#"
    template T() {
        signal input numerator;
        signal input denominator;
        signal quotient;

        quotient <-- numerator / denominator;
        quotient * denominator === numerator;
    }
    "#;

    let matcher = PatternMatcher::new(unconstrained_library(
        r"^\s*(?:signal\s+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\[[^\]]+\])*\s*<--\s*[^;]+;\s*$",
    ))
    .expect("matcher")
    .with_semantic(true);

    let unconstrained: Vec<_> = matcher
        .scan_text(source)
        .into_iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .collect();
    assert_eq!(unconstrained.len(), 1);
    assert_eq!(unconstrained[0].severity, Severity::Critical);
}
