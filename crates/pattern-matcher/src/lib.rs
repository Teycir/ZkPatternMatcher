use pattern_types::*;
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;

pub struct PatternMatcher {
    patterns: Vec<Pattern>,
    compiled_regex: HashMap<String, Regex>,
}

impl PatternMatcher {
    pub fn new(library: PatternLibrary) -> Result<Self> {
        let mut compiled_regex = HashMap::new();
        
        for pattern in &library.patterns {
            if pattern.kind == PatternKind::Regex {
                let re = Regex::new(&pattern.pattern)
                    .with_context(|| format!("Invalid regex in pattern {}", pattern.id))?;
                compiled_regex.insert(pattern.id.clone(), re);
            }
        }
        
        Ok(Self {
            patterns: library.patterns,
            compiled_regex,
        })
    }
    
    pub fn scan_text(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for (line_num, line) in text.lines().enumerate() {
            for pattern in &self.patterns {
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
                        // AST matching not implemented in minimal version
                    }
                }
            }
        }
        
        matches
    }
    
    pub fn scan_file(&self, path: &std::path::Path) -> Result<Vec<PatternMatch>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        Ok(self.scan_text(&content))
    }
}
