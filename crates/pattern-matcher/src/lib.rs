//! Pattern matching engine for ZK circuit vulnerability detection.

use anyhow::{Context, Result};
use fancy_regex::Regex as FancyRegex;
use pattern_types::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

pub mod semantic;

static INVARIANT_WARNING_EMITTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
pub struct MatcherLimits {
    pub max_patterns: usize,
    pub max_regex_length: usize,
    pub max_matches: usize,
    pub max_file_size: u64,
}

impl Default for MatcherLimits {
    fn default() -> Self {
        Self {
            max_patterns: 1000,
            max_regex_length: 200,
            max_matches: 10_000,
            max_file_size: 10 * 1024 * 1024,
        }
    }
}

/// Pattern matcher with compiled regex cache.
pub struct PatternMatcher {
    patterns: Vec<Pattern>,
    compiled_regex: HashMap<String, Regex>,
    compiled_fancy_regex: HashMap<String, FancyRegex>,
    limits: MatcherLimits,
    semantic_enabled: bool,
}

impl PatternMatcher {
    /// Creates a new pattern matcher from a pattern library.
    ///
    /// # Limits
    /// - Max patterns: 1,000
    /// - Max regex length: 200 chars
    ///
    /// # Errors
    /// Returns an error if:
    /// - Pattern limit exceeded
    /// - Regex compilation fails
    /// - Regex too complex (>200 chars)
    ///
    /// # Example
    /// ```no_run
    /// use pattern_matcher::PatternMatcher;
    /// use pattern_types::*;
    ///
    /// let library = PatternLibrary { patterns: vec![], invariants: vec![] };
    /// let matcher = PatternMatcher::new(library)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new(library: PatternLibrary) -> Result<Self> {
        Self::new_with_limits(library, MatcherLimits::default())
    }

    pub fn new_with_limits(library: PatternLibrary, limits: MatcherLimits) -> Result<Self> {
        if library.patterns.len() > limits.max_patterns {
            anyhow::bail!(
                "Too many patterns: {} (max {})",
                library.patterns.len(),
                limits.max_patterns
            );
        }

        if !library.invariants.is_empty()
            && !INVARIANT_WARNING_EMITTED.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "Warning: {} invariants loaded but invariant enforcement is not implemented yet.",
                library.invariants.len()
            );
        }

        let mut seen_ids = HashSet::new();
        let mut compiled_regex = HashMap::new();
        let mut compiled_fancy_regex = HashMap::new();

        for pattern in &library.patterns {
            if !seen_ids.insert(pattern.id.as_str()) {
                anyhow::bail!("Duplicate pattern id detected: {}", pattern.id);
            }

            if pattern.kind == PatternKind::Ast {
                anyhow::bail!(
                    "Pattern '{}' uses kind=ast, which is not implemented yet",
                    pattern.id
                );
            }

            match pattern.kind {
                PatternKind::Regex => {
                    if pattern.pattern.len() > limits.max_regex_length {
                        anyhow::bail!(
                            "Regex pattern too complex in {}: {} chars (max {})",
                            pattern.id,
                            pattern.pattern.len(),
                            limits.max_regex_length
                        );
                    }

                    let re = Regex::new(&pattern.pattern)
                        .with_context(|| format!("Invalid regex in pattern {}", pattern.id))?;

                    compiled_regex.insert(pattern.id.clone(), re);
                }
                PatternKind::FancyRegex => {
                    if pattern.pattern.len() > limits.max_regex_length {
                        anyhow::bail!(
                            "Fancy-regex pattern too complex in {}: {} chars (max {})",
                            pattern.id,
                            pattern.pattern.len(),
                            limits.max_regex_length
                        );
                    }

                    let re = FancyRegex::new(&pattern.pattern).with_context(|| {
                        format!("Invalid fancy-regex in pattern {}", pattern.id)
                    })?;

                    compiled_fancy_regex.insert(pattern.id.clone(), re);
                }
                _ => {}
            }
        }

        Ok(Self {
            patterns: library.patterns,
            compiled_regex,
            compiled_fancy_regex,
            limits,
            semantic_enabled: false,
        })
    }

    pub fn with_semantic(mut self, enabled: bool) -> Self {
        self.semantic_enabled = enabled;
        self
    }

    /// Scans text content for pattern matches.
    ///
    /// # Limits
    /// - Max matches: 10,000 (stops early if exceeded)
    ///
    /// # Returns
    /// Vector of pattern matches with locations.
    pub fn scan_text(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in text.lines().enumerate() {
            if matches.len() >= self.limits.max_matches {
                break;
            }

            for pattern in &self.patterns {
                if matches.len() >= self.limits.max_matches {
                    break;
                }

                match pattern.kind {
                    PatternKind::Regex => {
                        if let Some(re) = self.compiled_regex.get(&pattern.id) {
                            for m in re.find_iter(line) {
                                if matches.len() >= self.limits.max_matches {
                                    break;
                                }
                                matches.push(PatternMatch {
                                    pattern_id: pattern.id.clone(),
                                    message: pattern.message.clone(),
                                    severity: pattern.severity.clone().unwrap_or(Severity::Info),
                                    location: MatchLocation {
                                        line: line_num + 1,
                                        column: m.start() + 1,
                                        matched_text: m.as_str().to_string(),
                                    },
                                });
                            }
                        }
                    }
                    PatternKind::FancyRegex => {
                        if let Some(re) = self.compiled_fancy_regex.get(&pattern.id) {
                            for maybe_match in re.find_iter(line) {
                                if matches.len() >= self.limits.max_matches {
                                    break;
                                }

                                if let Ok(m) = maybe_match {
                                    matches.push(PatternMatch {
                                        pattern_id: pattern.id.clone(),
                                        message: pattern.message.clone(),
                                        severity: pattern
                                            .severity
                                            .clone()
                                            .unwrap_or(Severity::Info),
                                        location: MatchLocation {
                                            line: line_num + 1,
                                            column: m.start() + 1,
                                            matched_text: m.as_str().to_string(),
                                        },
                                    });
                                }
                            }
                        }
                    }
                    PatternKind::Literal => {
                        if pattern.pattern.is_empty() {
                            continue;
                        }

                        let mut cursor = 0;
                        while cursor < line.len() {
                            if matches.len() >= self.limits.max_matches {
                                break;
                            }

                            if let Some(pos) = line[cursor..].find(&pattern.pattern) {
                                let abs_pos = cursor + pos;
                                matches.push(PatternMatch {
                                    pattern_id: pattern.id.clone(),
                                    message: pattern.message.clone(),
                                    severity: pattern.severity.clone().unwrap_or(Severity::Info),
                                    location: MatchLocation {
                                        line: line_num + 1,
                                        column: abs_pos + 1,
                                        matched_text: pattern.pattern.clone(),
                                    },
                                });
                                cursor = abs_pos + pattern.pattern.len();
                            } else {
                                break;
                            }
                        }
                    }
                    PatternKind::Ast => {
                        // AST matching not implemented - patterns with kind=ast are skipped
                    }
                }
            }
        }

        if self.semantic_enabled {
            for finding in semantic::two_pass_scan(text) {
                if matches.len() >= self.limits.max_matches {
                    break;
                }

                matches.push(PatternMatch {
                    pattern_id: finding.finding_id,
                    message: finding.message,
                    severity: semantic_severity(&finding.severity),
                    location: MatchLocation {
                        line: finding.line_no,
                        column: 1,
                        matched_text: finding.signal,
                    },
                });
            }
        }

        matches
    }

    /// Scans a file for pattern matches.
    ///
    /// # Limits
    /// - Max file size: 10MB
    ///
    /// # Errors
    /// Returns an error if:
    /// - File exceeds size limit
    /// - File cannot be read
    ///
    /// # Example
    /// ```no_run
    /// # use pattern_matcher::PatternMatcher;
    /// # use pattern_types::*;
    /// # use std::path::Path;
    /// # let library = PatternLibrary { patterns: vec![], invariants: vec![] };
    /// # let matcher = PatternMatcher::new(library)?;
    /// let matches = matcher.scan_file(Path::new("circuit.circom"))?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn scan_file(&self, path: &std::path::Path) -> Result<Vec<PatternMatch>> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata: {}", path.display()))?;

        if metadata.len() > self.limits.max_file_size {
            anyhow::bail!(
                "File too large: {} bytes (max {})",
                metadata.len(),
                self.limits.max_file_size
            );
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        Ok(self.scan_text(&content))
    }
}

fn semantic_severity(severity: &str) -> Severity {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_regex_matches_on_a_line() -> Result<()> {
        let library = PatternLibrary {
            patterns: vec![Pattern {
                id: "arrow".to_string(),
                kind: PatternKind::Regex,
                pattern: "<--".to_string(),
                message: "match".to_string(),
                severity: Some(Severity::High),
            }],
            invariants: vec![],
        };

        let matcher = PatternMatcher::new(library)?;
        let matches = matcher.scan_text("a <-- b; c <-- d;");
        assert_eq!(matches.len(), 2);
        Ok(())
    }

    #[test]
    fn reports_all_literal_matches_on_a_line() -> Result<()> {
        let library = PatternLibrary {
            patterns: vec![Pattern {
                id: "lit".to_string(),
                kind: PatternKind::Literal,
                pattern: "foo".to_string(),
                message: "match".to_string(),
                severity: Some(Severity::Low),
            }],
            invariants: vec![],
        };

        let matcher = PatternMatcher::new(library)?;
        let matches = matcher.scan_text("foo bar foo baz");
        assert_eq!(matches.len(), 2);
        Ok(())
    }

    #[test]
    fn reports_all_fancy_regex_matches_on_a_line() -> Result<()> {
        let library = PatternLibrary {
            patterns: vec![Pattern {
                id: "dup".to_string(),
                kind: PatternKind::FancyRegex,
                pattern: r"(\w)\1".to_string(),
                message: "match".to_string(),
                severity: Some(Severity::Low),
            }],
            invariants: vec![],
        };

        let matcher = PatternMatcher::new(library)?;
        let matches = matcher.scan_text("aa bb cc");
        assert_eq!(matches.len(), 3);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_pattern_ids() {
        let library = PatternLibrary {
            patterns: vec![
                Pattern {
                    id: "dup".to_string(),
                    kind: PatternKind::Literal,
                    pattern: "a".to_string(),
                    message: "one".to_string(),
                    severity: None,
                },
                Pattern {
                    id: "dup".to_string(),
                    kind: PatternKind::Literal,
                    pattern: "b".to_string(),
                    message: "two".to_string(),
                    severity: None,
                },
            ],
            invariants: vec![],
        };

        let err = PatternMatcher::new(library)
            .err()
            .expect("expected duplicate id validation error");
        assert!(err.to_string().contains("Duplicate pattern id"));
    }

    #[test]
    fn validates_length_before_compiling_regex() {
        let library = PatternLibrary {
            patterns: vec![Pattern {
                id: "long_invalid".to_string(),
                kind: PatternKind::Regex,
                pattern: "[".repeat(201),
                message: "bad".to_string(),
                severity: None,
            }],
            invariants: vec![],
        };

        let err = PatternMatcher::new(library)
            .err()
            .expect("expected regex length validation error");
        assert!(err.to_string().contains("too complex"));
    }

    #[test]
    fn semantic_findings_are_added_when_enabled() -> Result<()> {
        let library = PatternLibrary {
            patterns: vec![],
            invariants: vec![],
        };

        let source = r#"
        template T() {
            signal a;
            a <-- 1;
        }
        "#;

        let plain = PatternMatcher::new(library.clone())?;
        let semantic = PatternMatcher::new(library)?.with_semantic(true);

        let plain_matches = plain.scan_text(source);
        let semantic_matches = semantic.scan_text(source);

        assert!(plain_matches.is_empty());
        assert!(semantic_matches
            .iter()
            .any(|m| m.pattern_id == "orphaned_unconstrained_assignment"));
        Ok(())
    }

    #[test]
    fn rejects_ast_patterns_until_implemented() {
        let library = PatternLibrary {
            patterns: vec![Pattern {
                id: "ast_check".to_string(),
                kind: PatternKind::Ast,
                pattern: "unused".to_string(),
                message: "unused".to_string(),
                severity: None,
            }],
            invariants: vec![],
        };

        let err = PatternMatcher::new(library)
            .err()
            .expect("expected AST kind validation error");
        assert!(err.to_string().contains("kind=ast"));
    }
}
