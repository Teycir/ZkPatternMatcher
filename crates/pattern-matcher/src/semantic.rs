use pattern_types::PatternMatch;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AssignKind {
    Unconstrained, // <--
    Constrained,   // <==
    Equality,      // ===
}

#[derive(Debug, Clone)]
pub struct SignalAssignment {
    pub line_no: usize,
    pub signal: String,
    pub kind: AssignKind,
    pub tautological_equality: bool,
}

#[derive(Debug, Clone)]
pub struct SemanticFinding {
    pub line_no: usize,
    pub signal: String,
    pub finding_id: String,
    pub message: String,
    pub severity: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Lazy-compiled regex patterns
// ─────────────────────────────────────────────────────────────────────────────

static RE_UNCONSTRAINED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(\w[\w\[\]]*)\s*<--").expect("valid regex"));
static RE_CONSTRAINED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(\w[\w\[\]]*)\s*<==").expect("valid regex"));
static RE_EQUALITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(\w[\w\[\]]*)\s*===").expect("valid regex"));
static RE_PORT_WIRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\w+)\.(\w+)\s*<==\s*(\w+)").expect("valid regex"));
static RE_TEMPLATE_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*template\s+(\w+)\s*\(").expect("valid regex"));
static RE_VAR_DECL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*var\s+(\w+)").expect("valid regex"));
static RE_SELF_EQ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(\w+)\s*===\s*(\w+)\s*;").expect("valid regex"));
static RE_IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\b").expect("valid regex"));
static RE_UNCONSTRAINED_CAPTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:signal\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\s*\[[^\]]+\])*)\s*<--")
        .expect("valid regex")
});
static RE_NUMERIC_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d+\b").expect("valid regex"));
static RE_VAR_MUTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*([A-Za-z_]\w*)\s*(?:\+?=|-?=|\*?=|/?=)\s*.+;\s*$").expect("valid regex")
});

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full two-pass semantic scan on a single `.circom` source file.
/// Returns a list of `SemanticFinding`s, one per detected issue.
pub fn two_pass_scan(source: &str) -> Vec<SemanticFinding> {
    let stripped_source = strip_comments_preserve_lines(source);
    let templates = split_into_templates(&stripped_source);
    let mut findings = Vec::new();

    for tmpl in &templates {
        findings.extend(scan_template(tmpl));
    }

    findings
}

/// Enrich syntax-level findings with semantic context without changing
/// severities.
pub fn calibrate_pattern_matches(source: &str, matches: &mut [PatternMatch]) {
    if matches.is_empty() {
        return;
    }

    let contexts = collect_template_constraint_context(source);
    if contexts.is_empty() {
        return;
    }

    for m in matches.iter_mut() {
        if m.pattern_id != "unconstrained_assignment" && m.pattern_id != "signal_without_constraint"
        {
            continue;
        }

        let Some(signal) = extract_unconstrained_signal(&m.location.matched_text) else {
            continue;
        };

        let Some(ctx) = contexts
            .iter()
            .find(|ctx| m.location.line >= ctx.start_line && m.location.line <= ctx.end_line)
        else {
            continue;
        };

        if !ctx.constrained_signals.contains(&signal) {
            continue;
        }

        match m.pattern_id.as_str() {
            "unconstrained_assignment" => {
                let is_locally_constrained = ctx.locally_constrained_signals.contains(&signal);

                m.message = if is_locally_constrained {
                    format!(
                        "Unconstrained assignment operator (<--) detected; semantic context shows '{}' is constrained shortly after assignment in the same template (likely witness-hint pattern). Keep under manual review.",
                        signal
                    )
                } else {
                    format!(
                        "Unconstrained assignment operator (<--) detected; semantic context shows '{}' participates in constraints in the same template. Manual review required.",
                        signal
                    )
                };
            }
            "signal_without_constraint" => {
                let is_locally_constrained = ctx.locally_constrained_signals.contains(&signal);

                m.message = if is_locally_constrained {
                    format!(
                        "Signal assigned without immediate constraint; semantic context shows '{}' is constrained shortly after assignment in the same template (likely witness-hint pattern).",
                        signal
                    )
                } else {
                    format!(
                        "Signal assigned without immediate constraint; semantic context shows '{}' participates in constraints in the same template. Manual review required.",
                        signal
                    )
                };
            }
            _ => {}
        }
    }
}

fn find_template_context(
    contexts: &[TemplateConstraintContext],
    line_no: usize,
) -> Option<&TemplateConstraintContext> {
    contexts
        .iter()
        .find(|ctx| line_no >= ctx.start_line && line_no <= ctx.end_line)
}

fn is_hard_mitigated_pattern_match(
    m: &PatternMatch,
    contexts: &[TemplateConstraintContext],
) -> bool {
    if m.pattern_id != "unconstrained_assignment" && m.pattern_id != "signal_without_constraint" {
        return false;
    }

    let Some(signal) = extract_unconstrained_signal(&m.location.matched_text) else {
        return false;
    };

    let Some(ctx) = find_template_context(contexts, m.location.line) else {
        return false;
    };

    ctx.hard_mitigated_signals.contains(&signal)
}

/// Deduplicate overlapping findings and drop matches that satisfy hard
/// mitigation guards derived from validated false-positive rationales.
pub fn dedup_and_filter_pattern_matches(source: &str, matches: &mut Vec<PatternMatch>) {
    if matches.is_empty() {
        return;
    }

    let contexts = collect_template_constraint_context(source);
    let unconstrained_by_line_signal: HashSet<(usize, String)> = matches
        .iter()
        .filter(|m| m.pattern_id == "unconstrained_assignment")
        .filter_map(|m| {
            extract_unconstrained_signal(&m.location.matched_text)
                .map(|signal| (m.location.line, signal))
        })
        .collect();

    let mut seen_exact: HashSet<(String, usize, usize, String)> = HashSet::new();

    matches.retain(|m| {
        let exact_key = (
            m.pattern_id.clone(),
            m.location.line,
            m.location.column,
            m.location.matched_text.clone(),
        );
        if !seen_exact.insert(exact_key) {
            return false;
        }

        if m.pattern_id == "signal_without_constraint" {
            if let Some(signal) = extract_unconstrained_signal(&m.location.matched_text) {
                if unconstrained_by_line_signal.contains(&(m.location.line, signal)) {
                    return false;
                }
            }
        }

        if is_hard_mitigated_pattern_match(m, &contexts) {
            return false;
        }

        true
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Template splitting
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TemplateBlock {
    lines: Vec<(usize, String)>, // (1-based global line number, line content)
}

#[derive(Debug)]
struct TemplateConstraintContext {
    start_line: usize,
    end_line: usize,
    constrained_signals: HashSet<String>,
    locally_constrained_signals: HashSet<String>,
    hard_mitigated_signals: HashSet<String>,
}

#[derive(Debug)]
struct ConstraintLine {
    line_no: usize,
    text: String,
    tokens: HashSet<String>,
    has_numeric_literal: bool,
    has_multiplication: bool,
    has_add_or_sub: bool,
}

/// Split source into per-template blocks so that signal names don't bleed
/// across template boundaries. Uses a brace-depth counter to find boundaries.
fn split_into_templates(source: &str) -> Vec<TemplateBlock> {
    let mut templates: Vec<TemplateBlock> = Vec::new();
    let mut current: Option<TemplateBlock> = None;
    let mut depth: i32 = 0;

    for (i, line) in source.lines().enumerate() {
        let line_no = i + 1;

        // Detect template header
        if RE_TEMPLATE_START.is_match(line) {
            if let Some(prev) = current.take() {
                templates.push(prev);
            }
            current = Some(TemplateBlock { lines: Vec::new() });
            depth = 0;
        }

        // Accumulate lines into current template
        if let Some(ref mut tmpl) = current {
            tmpl.lines.push((line_no, line.to_string()));
        }

        // Track brace depth to detect template end
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth <= 0 {
                        if let Some(finished) = current.take() {
                            templates.push(finished);
                        }
                        depth = 0;
                    }
                }
                _ => {}
            }
        }
    }

    // Push any unclosed template
    if let Some(remaining) = current {
        templates.push(remaining);
    }

    templates
}

fn collect_template_constraint_context(source: &str) -> Vec<TemplateConstraintContext> {
    let stripped_source = strip_comments_preserve_lines(source);
    let templates = split_into_templates(&stripped_source);
    let mut contexts = Vec::new();

    for tmpl in templates {
        let Some((start_line, _)) = tmpl.lines.first() else {
            continue;
        };
        let Some((end_line, _)) = tmpl.lines.last() else {
            continue;
        };

        let assignments = collect_assignments(&tmpl);
        let mut constrained_signals: HashSet<String> = assignments
            .iter()
            .filter(|a| {
                matches!(a.kind, AssignKind::Constrained)
                    || (matches!(a.kind, AssignKind::Equality) && !a.tautological_equality)
            })
            .map(|a| a.signal.clone())
            .collect();
        constrained_signals.extend(collect_constraint_signal_usage(&tmpl.lines));
        let locally_constrained_signals = collect_locally_constrained_signals(&tmpl.lines);
        let constraint_lines = collect_non_taut_constraint_lines(&tmpl.lines);
        let hard_mitigated_signals =
            collect_hard_mitigated_signals(&tmpl.lines, &assignments, &constraint_lines);

        contexts.push(TemplateConstraintContext {
            start_line: *start_line,
            end_line: *end_line,
            constrained_signals,
            locally_constrained_signals,
            hard_mitigated_signals,
        });
    }

    contexts
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-template analysis
// ─────────────────────────────────────────────────────────────────────────────

fn scan_template(tmpl: &TemplateBlock) -> Vec<SemanticFinding> {
    let mut findings = Vec::new();

    let assignments = collect_assignments(tmpl);
    let constrained_usage = collect_constraint_signal_usage(&tmpl.lines);
    let port_wirings = collect_port_wirings(tmpl);

    findings.extend(check_orphaned_unconstrained(
        &assignments,
        &constrained_usage,
    ));
    findings.extend(check_signal_aliasing(&port_wirings));
    findings.extend(check_var_equality_constraint(&tmpl.lines));

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 1 — Collectors
// ─────────────────────────────────────────────────────────────────────────────

fn collect_assignments(tmpl: &TemplateBlock) -> Vec<SignalAssignment> {
    let mut out = Vec::new();

    for (line_no, line) in &tmpl.lines {
        let stripped = strip_comment(line);

        if let Some(caps) = RE_UNCONSTRAINED.captures(&stripped) {
            out.push(SignalAssignment {
                line_no: *line_no,
                signal: normalize_signal(&caps[1]),
                kind: AssignKind::Unconstrained,
                tautological_equality: false,
            });
        } else if let Some(caps) = RE_CONSTRAINED.captures(&stripped) {
            out.push(SignalAssignment {
                line_no: *line_no,
                signal: normalize_signal(&caps[1]),
                kind: AssignKind::Constrained,
                tautological_equality: false,
            });
        }

        if let Some(caps) = RE_EQUALITY.captures(&stripped) {
            let tautological_equality = RE_SELF_EQ
                .captures(&stripped)
                .map(|eq_caps| normalize_signal(&eq_caps[1]) == normalize_signal(&eq_caps[2]))
                .unwrap_or(false);
            out.push(SignalAssignment {
                line_no: *line_no,
                signal: normalize_signal(&caps[1]),
                kind: AssignKind::Equality,
                tautological_equality,
            });
        }
    }

    out
}

fn is_keyword(token: &str) -> bool {
    matches!(
        token,
        "template"
            | "signal"
            | "input"
            | "output"
            | "component"
            | "var"
            | "for"
            | "if"
            | "else"
            | "while"
            | "return"
            | "function"
            | "pragma"
            | "include"
    )
}

fn collect_constraint_signal_usage(lines: &[(usize, String)]) -> HashSet<String> {
    let mut usage = HashSet::new();

    for (_, line) in lines {
        let stripped = strip_comment(line);
        if !stripped.contains("<==") && !stripped.contains("===") {
            continue;
        }

        // `x === x` is tautological and should not count as evidence that `x`
        // is actually constrained.
        if let Some(caps) = RE_SELF_EQ.captures(&stripped) {
            let lhs = normalize_signal(&caps[1]);
            let rhs = normalize_signal(&caps[2]);
            if lhs == rhs {
                continue;
            }
        }

        for caps in RE_IDENT.captures_iter(&stripped) {
            let token = &caps[1];
            if is_keyword(token) {
                continue;
            }
            usage.insert(token.to_string());
        }
    }

    usage
}

fn line_mentions_signal(line: &str, signal: &str) -> bool {
    let signal_pattern = format!(r"\b{}\b", regex::escape(signal));
    Regex::new(&signal_pattern)
        .map(|re| re.is_match(line))
        .unwrap_or(false)
}

fn collect_locally_constrained_signals(lines: &[(usize, String)]) -> HashSet<String> {
    const LOCAL_WINDOW_LINES: usize = 12;
    let mut out = HashSet::new();

    for (assignment_line, assignment_text) in lines {
        let assignment_stripped = strip_comment(assignment_text);
        let Some(caps) = RE_UNCONSTRAINED_CAPTURE.captures(&assignment_stripped) else {
            continue;
        };
        let signal = normalize_signal(&caps[1]);

        let is_locally_constrained = lines.iter().any(|(line_no, line)| {
            if *line_no <= *assignment_line || *line_no > *assignment_line + LOCAL_WINDOW_LINES {
                return false;
            }

            let stripped = strip_comment(line);
            if !stripped.contains("<==") && !stripped.contains("===") {
                return false;
            }

            if let Some(caps) = RE_SELF_EQ.captures(&stripped) {
                let lhs = normalize_signal(&caps[1]);
                let rhs = normalize_signal(&caps[2]);
                if lhs == rhs {
                    return false;
                }
            }

            line_mentions_signal(&stripped, &signal)
        });

        if is_locally_constrained {
            out.insert(signal);
        }
    }

    out
}

fn collect_non_taut_constraint_lines(lines: &[(usize, String)]) -> Vec<ConstraintLine> {
    let mut out = Vec::new();

    for (line_no, line) in lines {
        let stripped = strip_comment(line);
        if !stripped.contains("<==") && !stripped.contains("===") {
            continue;
        }

        if let Some(caps) = RE_SELF_EQ.captures(&stripped) {
            let lhs = normalize_signal(&caps[1]);
            let rhs = normalize_signal(&caps[2]);
            if lhs == rhs {
                continue;
            }
        }

        let tokens: HashSet<String> = RE_IDENT
            .captures_iter(&stripped)
            .filter_map(|caps| {
                let token = &caps[1];
                if is_keyword(token) {
                    return None;
                }
                Some(normalize_signal(token))
            })
            .collect();

        out.push(ConstraintLine {
            line_no: *line_no,
            text: stripped.clone(),
            tokens,
            has_numeric_literal: RE_NUMERIC_LITERAL.is_match(&stripped),
            has_multiplication: stripped.contains('*'),
            has_add_or_sub: stripped.contains('+') || stripped.contains('-'),
        });
    }

    out
}

fn constraint_has_anchor_for_signal(
    line: &ConstraintLine,
    signal: &str,
    unconstrained_signals: &HashSet<String>,
) -> bool {
    if line.has_numeric_literal {
        return true;
    }

    line.tokens
        .iter()
        .any(|token| token != signal && !unconstrained_signals.contains(token))
}

fn strip_indices(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    let mut depth = 0usize;

    for c in expr.chars() {
        if c == '[' {
            depth += 1;
            continue;
        }
        if c == ']' && depth > 0 {
            depth -= 1;
            continue;
        }
        if depth == 0 {
            out.push(c);
        }
    }

    out
}

fn is_binary_constraint_for_signal(line: &str, signal: &str) -> bool {
    let normalized = strip_indices(line);
    let compact: String = normalized.chars().filter(|c| !c.is_whitespace()).collect();
    let sig = regex::escape(signal);
    let variants = [
        format!("{sig}*(1-{sig})===0"),
        format!("(1-{sig})*{sig}===0"),
        format!("{sig}*({sig}-1)===0"),
        format!("({sig}-1)*{sig}===0"),
    ];

    variants.iter().any(|v| compact.contains(v))
}

fn has_bit_component_input_wiring(
    lines: &[(usize, String)],
    signal: &str,
    assignment_line: usize,
) -> bool {
    lines.iter().any(|(line_no, line)| {
        if *line_no <= assignment_line {
            return false;
        }
        let stripped = strip_comment(line);
        if !stripped.contains("<==") || !line_mentions_signal(&stripped, signal) {
            return false;
        }
        let lower = stripped.to_ascii_lowercase();
        lower.contains(".in") && lower.contains("bit")
    })
}

fn has_var_recomposition_proof(
    lines: &[(usize, String)],
    signal: &str,
    assignment_line: usize,
    constraint_lines: &[ConstraintLine],
    unconstrained_signals: &HashSet<String>,
) -> bool {
    let supporting_vars: HashSet<String> = lines
        .iter()
        .filter(|(line_no, _)| *line_no > assignment_line)
        .filter_map(|(_, line)| {
            let stripped = strip_comment(line);
            if stripped.contains("<==") || stripped.contains("===") {
                return None;
            }
            let caps = RE_VAR_MUTATION.captures(&stripped)?;
            if !line_mentions_signal(&stripped, signal) {
                return None;
            }
            Some(caps[1].to_string())
        })
        .collect();

    if supporting_vars.is_empty() {
        return false;
    }

    constraint_lines.iter().any(|line| {
        if line.line_no <= assignment_line {
            return false;
        }

        supporting_vars.iter().any(|var| {
            line.tokens.contains(var)
                && constraint_has_anchor_for_signal(line, var, unconstrained_signals)
        })
    })
}

fn collect_hard_mitigated_signals(
    lines: &[(usize, String)],
    assignments: &[SignalAssignment],
    constraint_lines: &[ConstraintLine],
) -> HashSet<String> {
    let unconstrained_signals: HashSet<String> = assignments
        .iter()
        .filter(|a| matches!(a.kind, AssignKind::Unconstrained))
        .map(|a| a.signal.clone())
        .collect();

    let mut mitigated = HashSet::new();

    for assignment in assignments
        .iter()
        .filter(|a| matches!(a.kind, AssignKind::Unconstrained))
    {
        let signal_constraints: Vec<&ConstraintLine> = constraint_lines
            .iter()
            .filter(|line| {
                line.line_no > assignment.line_no && line.tokens.contains(&assignment.signal)
            })
            .collect();

        if signal_constraints.is_empty() {
            continue;
        }

        let anchored_constraints: Vec<&ConstraintLine> = signal_constraints
            .iter()
            .copied()
            .filter(|line| {
                constraint_has_anchor_for_signal(line, &assignment.signal, &unconstrained_signals)
            })
            .collect();

        if anchored_constraints.is_empty() {
            continue;
        }

        let has_two_anchored_constraints = anchored_constraints.len() >= 2;
        let has_binary_constraint = signal_constraints
            .iter()
            .any(|line| is_binary_constraint_for_signal(&line.text, &assignment.signal));
        let has_structural_constraint = anchored_constraints
            .iter()
            .any(|line| line.has_multiplication || line.has_add_or_sub);
        let has_bit_component_wiring =
            has_bit_component_input_wiring(lines, &assignment.signal, assignment.line_no);
        let has_var_recomposition = has_var_recomposition_proof(
            lines,
            &assignment.signal,
            assignment.line_no,
            constraint_lines,
            &unconstrained_signals,
        );

        if has_two_anchored_constraints
            || (has_binary_constraint && has_var_recomposition)
            || (has_bit_component_wiring && has_structural_constraint)
        {
            mitigated.insert(assignment.signal.clone());
        }
    }

    mitigated
}

fn extract_unconstrained_signal(matched_text: &str) -> Option<String> {
    let stripped = strip_comment(matched_text);
    RE_UNCONSTRAINED_CAPTURE
        .captures(&stripped)
        .map(|caps| normalize_signal(&caps[1]))
}

fn normalize_signal(raw: &str) -> String {
    raw.split('[').next().unwrap_or(raw).to_string()
}

fn strip_comment(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut result = String::with_capacity(line.len());
    let mut i = 0;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        if let Some(quote) = in_string {
            result.push(c);

            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                in_string = None;
            }

            i += 1;
            continue;
        }

        if c == '"' || c == '\'' {
            in_string = Some(c);
            result.push(c);
            i += 1;
            continue;
        }

        if c == '/' && next == Some('/') {
            break;
        }

        result.push(c);
        i += 1;
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PortWiring {
    line_no: usize,
    component: String,
    port: String,
    signal: String,
}

fn collect_port_wirings(tmpl: &TemplateBlock) -> Vec<PortWiring> {
    let mut out = Vec::new();

    for (line_no, line) in &tmpl.lines {
        let stripped = strip_comment(line);
        for caps in RE_PORT_WIRING.captures_iter(&stripped) {
            out.push(PortWiring {
                line_no: *line_no,
                component: caps[1].to_string(),
                port: caps[2].to_string(),
                signal: caps[3].to_string(),
            });
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Pass 2 — Checks
// ─────────────────────────────────────────────────────────────────────────────

fn check_orphaned_unconstrained(
    assignments: &[SignalAssignment],
    constrained_usage: &HashSet<String>,
) -> Vec<SemanticFinding> {
    let constrained: HashSet<&str> = assignments
        .iter()
        .filter(|a| {
            matches!(a.kind, AssignKind::Constrained)
                || (matches!(a.kind, AssignKind::Equality) && !a.tautological_equality)
        })
        .map(|a| a.signal.as_str())
        .collect();

    assignments
        .iter()
        .filter(|a| {
            a.kind == AssignKind::Unconstrained
                && !constrained.contains(a.signal.as_str())
                && !constrained_usage.contains(a.signal.as_str())
        })
        .map(|a| SemanticFinding {
            line_no: a.line_no,
            signal: a.signal.clone(),
            finding_id: "orphaned_unconstrained_assignment".into(),
            message: format!(
                "CRITICAL: signal '{}' assigned with <-- (unconstrained witness hint) on line {} \
                 but no corresponding <== or === found in this template. \
                 The prover can set this to any value without the verifier detecting it.",
                a.signal, a.line_no
            ),
            severity: "critical".into(),
        })
        .collect()
}

fn check_signal_aliasing(wirings: &[PortWiring]) -> Vec<SemanticFinding> {
    let mut signal_to_ports: HashMap<&str, Vec<(usize, String)>> = HashMap::new();

    for w in wirings {
        signal_to_ports
            .entry(w.signal.as_str())
            .or_default()
            .push((w.line_no, format!("{}.{}", w.component, w.port)));
    }

    let mut findings = Vec::new();
    for (signal, ports) in &signal_to_ports {
        if ports.len() < 2 {
            continue;
        }

        let unique_ports: HashSet<&str> = ports.iter().map(|(_, p)| p.as_str()).collect();
        if unique_ports.len() < 2 {
            continue;
        }

        let port_list: Vec<String> = ports
            .iter()
            .map(|(ln, p)| format!("{} (line {})", p, ln))
            .collect();

        findings.push(SemanticFinding {
            line_no: ports[0].0,
            signal: signal.to_string(),
            finding_id: "component_input_aliasing".into(),
            message: format!(
                "MEDIUM: signal '{}' wired to multiple component ports: {}. \
                 Shared signals can reduce circuit degrees of freedom — \
                 verify this aliasing is intentional and constraints still bind all paths.",
                signal,
                port_list.join(", ")
            ),
            severity: "medium".into(),
        });
    }

    findings
}

fn check_var_equality_constraint(lines: &[(usize, String)]) -> Vec<SemanticFinding> {
    let mut var_names: HashSet<String> = HashSet::new();
    let mut findings = Vec::new();

    for (_, line) in lines {
        let s = strip_comment(line);
        if let Some(caps) = RE_VAR_DECL.captures(&s) {
            var_names.insert(caps[1].to_string());
        }
    }

    for (line_no, line) in lines {
        let s = strip_comment(line);
        if let Some(caps) = RE_SELF_EQ.captures(&s) {
            let lhs = &caps[1];
            let rhs = &caps[2];

            if lhs == rhs {
                findings.push(SemanticFinding {
                    line_no: *line_no,
                    signal: lhs.to_string(),
                    finding_id: "self_equality_constraint".into(),
                    message: format!(
                        "MEDIUM: tautological constraint '{} === {}' on line {} — \
                         this constraint is always satisfied and does nothing. \
                         Likely a copy-paste error; verify the RHS is the intended \
                         expected value or witness signal.",
                        lhs, rhs, line_no
                    ),
                    severity: "medium".into(),
                });
            }

            if var_names.contains(lhs) {
                findings.push(SemanticFinding {
                    line_no: *line_no,
                    signal: lhs.to_string(),
                    finding_id: "constraint_on_var".into(),
                    message: format!(
                        "MEDIUM: '{}' on line {} is declared as `var` (compile-time value), \
                         not a `signal`. Applying === to a var produces a trivially satisfied \
                         constraint that the verifier cannot meaningfully enforce at runtime.",
                        lhs, line_no
                    ),
                    severity: "medium".into(),
                });
            }
        }
    }

    findings
}

fn strip_comments_preserve_lines(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    let mut in_block = false;
    let mut in_line = false;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        if in_block {
            if c == '*' && next == Some('/') {
                in_block = false;
                i += 2;
                continue;
            }

            if c == '\n' {
                result.push('\n');
            }
            i += 1;
            continue;
        }

        if let Some(quote) = in_string {
            result.push(c);

            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                in_string = None;
            }

            i += 1;
            continue;
        }

        if in_line {
            if c == '\n' {
                in_line = false;
                result.push('\n');
            }
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' {
            in_string = Some(c);
            result.push(c);
            i += 1;
            continue;
        }

        if c == '/' && next == Some('*') {
            in_block = true;
            i += 2;
            continue;
        }

        if c == '/' && next == Some('/') {
            in_line = true;
            i += 2;
            continue;
        }

        result.push(c);
        i += 1;
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn format_findings(findings: &[SemanticFinding]) -> String {
    if findings.is_empty() {
        return "[semantic] No issues found.\n".to_string();
    }

    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "[semantic][{}][line {}] {}\n  → {}\n",
            f.severity.to_uppercase(),
            f.line_no,
            f.finding_id,
            f.message,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_unconstrained_marker_inside_block_comments() {
        let source = r#"
        template T() {
            /*
                fake <-- assignment
            */
            signal x;
            x <== 1;
        }
        "#;

        let findings = two_pass_scan(source);
        assert!(findings
            .iter()
            .all(|f| f.finding_id != "orphaned_unconstrained_assignment"));
    }
}
