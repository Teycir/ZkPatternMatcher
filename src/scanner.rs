use crate::{PatternMatch, PatternMatcher};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub struct Scanner {
    matcher: PatternMatcher,
    ignore_patterns: Vec<String>,
}

impl Scanner {
    pub fn new(matcher: PatternMatcher, ignore_patterns: Vec<String>) -> Self {
        Self {
            matcher,
            ignore_patterns,
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
            let matches = self.matcher.scan_file(path)?;
            if !matches.is_empty() {
                results.push((path.to_path_buf(), matches));
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
        let path_str = path.to_string_lossy();
        self.ignore_patterns.iter().any(|pattern| {
            if pattern.ends_with('/') {
                path_str.contains(pattern)
            } else if pattern.contains('*') {
                let re = pattern.replace("*", ".*");
                regex::Regex::new(&re)
                    .map(|r| r.is_match(&path_str))
                    .unwrap_or(false)
            } else {
                path_str.contains(pattern)
            }
        })
    }
}
