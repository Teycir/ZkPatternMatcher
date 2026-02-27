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

// ─────────────────────────────────────────────────────────────────────────────
// Template splitting
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TemplateBlock {
    lines: Vec<(usize, String)>, // (1-based global line number, line content)
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

// ─────────────────────────────────────────────────────────────────────────────
// Per-template analysis
// ─────────────────────────────────────────────────────────────────────────────

fn scan_template(tmpl: &TemplateBlock) -> Vec<SemanticFinding> {
    let mut findings = Vec::new();

    let assignments = collect_assignments(tmpl);
    let port_wirings = collect_port_wirings(tmpl);

    findings.extend(check_orphaned_unconstrained(&assignments));
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
            });
        } else if let Some(caps) = RE_CONSTRAINED.captures(&stripped) {
            out.push(SignalAssignment {
                line_no: *line_no,
                signal: normalize_signal(&caps[1]),
                kind: AssignKind::Constrained,
            });
        }

        if let Some(caps) = RE_EQUALITY.captures(&stripped) {
            out.push(SignalAssignment {
                line_no: *line_no,
                signal: normalize_signal(&caps[1]),
                kind: AssignKind::Equality,
            });
        }
    }

    out
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

fn check_orphaned_unconstrained(assignments: &[SignalAssignment]) -> Vec<SemanticFinding> {
    let constrained: HashSet<&str> = assignments
        .iter()
        .filter(|a| matches!(a.kind, AssignKind::Constrained | AssignKind::Equality))
        .map(|a| a.signal.as_str())
        .collect();

    assignments
        .iter()
        .filter(|a| a.kind == AssignKind::Unconstrained && !constrained.contains(a.signal.as_str()))
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
                "HIGH: signal '{}' wired to multiple component ports: {}. \
                 Shared signals reduce circuit degrees of freedom — \
                 verify this aliasing is intentional and does not allow \
                 a malicious prover to satisfy constraints with forged inputs.",
                signal,
                port_list.join(", ")
            ),
            severity: "high".into(),
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
