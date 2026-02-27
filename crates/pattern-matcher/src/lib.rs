//! Pattern matching engine for ZK circuit vulnerability detection.

use anyhow::{Context, Result};
use pattern_types::*;
use regex::Regex;
use fancy_regex::Regex as FancyRegex;
use std::collections::HashMap;

pub mod semantic;

/// Pattern matcher with compiled regex cache.
pub struct PatternMatcher {
    patterns: Vec<Pattern>,
    compiled_regex: HashMap<String, Regex>,
    compiled_fancy_regex: HashMap<String, FancyRegex>,
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
        const MAX_PATTERNS: usize = 1000;

        if library.patterns.len() > MAX_PATTERNS {
            anyhow::bail!(
                "Too many patterns: {} (max {})",
                library.patterns.len(),
                MAX_PATTERNS
            );
        }

        let mut compiled_regex = HashMap::new();
        let mut compiled_fancy_regex = HashMap::new();

        for pattern in &library.patterns {
            match pattern.kind {
                PatternKind::Regex => {
                    let re = Regex::new(&pattern.pattern)
                        .with_context(|| format!("Invalid regex in pattern {}", pattern.id))?;

                    if pattern.pattern.len() > 200 {
                        anyhow::bail!(
                            "Regex pattern too complex in {}: {} chars (max 200)",
                            pattern.id,
                            pattern.pattern.len()
                        );
                    }

                    compiled_regex.insert(pattern.id.clone(), re);
                }
                PatternKind::FancyRegex => {
                    let re = FancyRegex::new(&pattern.pattern)
                        .with_context(|| format!("Invalid fancy-regex in pattern {}", pattern.id))?;

                    if pattern.pattern.len() > 200 {
                        anyhow::bail!(
                            "Fancy-regex pattern too complex in {}: {} chars (max 200)",
                            pattern.id,
                            pattern.pattern.len()
                        );
                    }

                    compiled_fancy_regex.insert(pattern.id.clone(), re);
                }
                _ => {}
            }
        }

        Ok(Self {
            patterns: library.patterns,
            compiled_regex,
            compiled_fancy_regex,
        })
    }

    /// Scans text content for pattern matches.
    ///
    /// # Limits
    /// - Max matches: 10,000 (stops early if exceeded)
    ///
    /// # Returns
    /// Vector of pattern matches with locations.
    pub fn scan_text(&self, text: &str) -> Vec<PatternMatch> {
        const MAX_MATCHES: usize = 10000;
        let mut matches = Vec::new();

        for (line_num, line) in text.lines().enumerate() {
            if matches.len() >= MAX_MATCHES {
                break;
            }

            for pattern in &self.patterns {
                if matches.len() >= MAX_MATCHES {
                    break;
                }

                match pattern.kind {
                    PatternKind::Regex => {
                        if let Some(re) = self.compiled_regex.get(&pattern.id) {
                            if let Some(m) = re.find(line) {
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
                            if let Ok(Some(m)) = re.find(line) {
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
                    PatternKind::Literal => {
                        if let Some(pos) = line.find(&pattern.pattern) {
                            matches.push(PatternMatch {
                                pattern_id: pattern.id.clone(),
                                message: pattern.message.clone(),
                                severity: pattern.severity.clone().unwrap_or(Severity::Info),
                                location: MatchLocation {
                                    line: line_num + 1,
                                    column: pos + 1,
                                    matched_text: pattern.pattern.clone(),
                                },
                            });
                        }
                    }
                    PatternKind::Ast => {
                        // AST matching not implemented - patterns with kind=ast are skipped
                    }
                }
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
        const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB limit

        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata: {}", path.display()))?;

        if metadata.len() > MAX_FILE_SIZE {
            anyhow::bail!(
                "File too large: {} bytes (max {})",
                metadata.len(),
                MAX_FILE_SIZE
            );
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        Ok(self.scan_text(&content))
    }
}
