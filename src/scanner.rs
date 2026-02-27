use crate::{PatternMatch, PatternMatcher};
use anyhow::Result;
use regex::Regex;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub struct Scanner {
    matcher: PatternMatcher,
    ignore_rules: Vec<IgnoreRule>,
}

enum IgnoreRule {
    Directory(String),
    Glob {
        regex: Regex,
        match_components: bool,
    },
    Literal {
        value: String,
        match_components: bool,
    },
}

impl Scanner {
    pub fn new(matcher: PatternMatcher, ignore_patterns: Vec<String>) -> Self {
        let ignore_rules = ignore_patterns
            .iter()
            .filter_map(|pattern| IgnoreRule::from_pattern(pattern))
            .collect();

        Self {
            matcher,
            ignore_rules,
        }
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<PatternMatch>> {
        self.matcher.scan_file(path)
    }

    pub fn scan_recursive(&self, path: &Path) -> Result<Vec<(PathBuf, Vec<PatternMatch>)>> {
        let mut results = Vec::new();
        self.scan_recursive_impl(path, &mut results)?;
        Ok(results)
    }

    fn scan_recursive_impl(
        &self,
        path: &Path,
        results: &mut Vec<(PathBuf, Vec<PatternMatch>)>,
    ) -> Result<()> {
        if self.should_ignore(path) {
            return Ok(());
        }

        if path.is_file() {
            match self.matcher.scan_file(path) {
                Ok(matches) => {
                    if !matches.is_empty() {
                        results.push((path.to_path_buf(), matches));
                    }
                }
                Err(err) => {
                    // Skip binary/non-UTF8 files so recursive scans can continue.
                    if is_skippable_file_error(&err) {
                        return Ok(());
                    }
                    return Err(err);
                }
            }
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                self.scan_recursive_impl(&entry.path(), results)?;
            }
        }

        Ok(())
    }

    fn should_ignore(&self, path: &Path) -> bool {
        self.ignore_rules.iter().any(|rule| rule.matches(path))
    }
}

impl IgnoreRule {
    fn from_pattern(pattern: &str) -> Option<Self> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return None;
        }

        if pattern.ends_with('/') {
            let dir = pattern.trim_end_matches('/').trim();
            if dir.is_empty() {
                return None;
            }
            return Some(IgnoreRule::Directory(dir.to_string()));
        }

        if pattern.contains('*') || pattern.contains('?') {
            let regex = glob_to_regex(pattern).ok()?;
            return Some(IgnoreRule::Glob {
                regex,
                match_components: !pattern.contains('/'),
            });
        }

        Some(IgnoreRule::Literal {
            value: pattern.to_string(),
            match_components: !pattern.contains('/'),
        })
    }

    fn matches(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        match self {
            IgnoreRule::Directory(dir) => path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().as_ref() == dir),
            IgnoreRule::Glob {
                regex,
                match_components,
            } => {
                if *match_components {
                    path.components().any(|component| {
                        regex.is_match(component.as_os_str().to_string_lossy().as_ref())
                    })
                } else {
                    regex.is_match(path_str.as_ref())
                }
            }
            IgnoreRule::Literal {
                value,
                match_components,
            } => {
                if *match_components {
                    path.components()
                        .any(|component| component.as_os_str().to_string_lossy().as_ref() == value)
                } else {
                    path_str.contains(value)
                }
            }
        }
    }
}

fn glob_to_regex(glob: &str) -> std::result::Result<Regex, regex::Error> {
    let mut regex = String::from("^");

    for ch in glob.chars() {
        match ch {
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }

    regex.push('$');
    Regex::new(&regex)
}

fn is_skippable_file_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == ErrorKind::InvalidData)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pattern_types::{Pattern, PatternKind, PatternLibrary, Severity};

    #[test]
    fn glob_extension_patterns_do_not_overmatch_directory_names() {
        let matcher = PatternMatcher::new(PatternLibrary {
            patterns: vec![],
            invariants: vec![],
        })
        .unwrap();

        let scanner = Scanner::new(matcher, vec!["*.a".to_string(), "*.o".to_string()]);

        assert!(!scanner.should_ignore(Path::new("/tmp/aaa")));
        assert!(scanner.should_ignore(Path::new("/tmp/liba.a")));
        assert!(scanner.should_ignore(Path::new("/tmp/obj.o")));
    }

    #[test]
    fn recursive_scan_skips_invalid_utf8_files() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let circuit_path = temp.path().join("vuln.circom");
        let binary_path = temp.path().join("blob.bin");

        std::fs::write(
            &circuit_path,
            "pragma circom 2.0.0;\ntemplate T(){ signal input a; signal output b; b <-- a; }\ncomponent main = T();",
        )?;
        std::fs::write(&binary_path, [0xff, 0xfe, 0xfd, 0x00])?;

        let matcher = PatternMatcher::new(PatternLibrary {
            patterns: vec![Pattern {
                id: "unconstrained".to_string(),
                kind: PatternKind::Regex,
                pattern: "<--".to_string(),
                message: "Unconstrained".to_string(),
                severity: Some(Severity::High),
            }],
            invariants: vec![],
        })?;

        let scanner = Scanner::new(matcher, vec![]);
        let results = scanner.scan_recursive(temp.path())?;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, circuit_path);
        assert_eq!(results[0].1.len(), 1);
        Ok(())
    }
}
