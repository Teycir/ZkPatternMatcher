//! YAML pattern library loader with security limits.

use anyhow::{Context, Result};
use pattern_types::PatternLibrary;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct LoaderLimits {
    pub max_file_size: u64,
    pub max_lines: usize,
    pub max_libraries: usize,
}

impl Default for LoaderLimits {
    fn default() -> Self {
        Self {
            max_file_size: 1024 * 1024,
            max_lines: 10_000,
            max_libraries: 100,
        }
    }
}

/// Loads a pattern library from a YAML file.
///
/// # Security Limits
/// - Max file size: 1MB
/// - Max lines: 10,000
///
/// # Errors
/// Returns an error if:
/// - File exceeds size/complexity limits
/// - File cannot be read
/// - YAML is malformed
///
/// # Example
/// ```no_run
/// use pattern_loader::load_pattern_library;
/// use std::path::Path;
///
/// let lib = load_pattern_library(Path::new("patterns/test.yaml"))?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn load_pattern_library(path: &Path) -> Result<PatternLibrary> {
    load_pattern_library_with_limits(path, LoaderLimits::default())
}

pub fn load_pattern_library_with_limits(
    path: &Path,
    limits: LoaderLimits,
) -> Result<PatternLibrary> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata: {}", path.display()))?;

    if metadata.len() > limits.max_file_size {
        anyhow::bail!(
            "Pattern file too large: {} bytes (max {})",
            metadata.len(),
            limits.max_file_size
        );
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern file: {}", path.display()))?;

    // Limit YAML depth to prevent YAML bombs
    let line_count = content.lines().count();
    if line_count > limits.max_lines {
        anyhow::bail!(
            "Pattern file too complex: {} lines (max {})",
            line_count,
            limits.max_lines
        );
    }

    let library: PatternLibrary = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;

    Ok(library)
}

/// Loads and merges multiple pattern libraries.
///
/// # Limits
/// - Max libraries: 100
///
/// # Errors
/// Returns an error if any library fails to load or limit is exceeded.
pub fn load_pattern_libraries(paths: &[&Path]) -> Result<PatternLibrary> {
    load_pattern_libraries_with_limits(paths, LoaderLimits::default())
}

pub fn load_pattern_libraries_with_limits(
    paths: &[&Path],
    limits: LoaderLimits,
) -> Result<PatternLibrary> {
    if paths.len() > limits.max_libraries {
        anyhow::bail!(
            "Too many pattern libraries: {} (max {})",
            paths.len(),
            limits.max_libraries
        );
    }

    let mut all_patterns = Vec::new();
    let mut all_invariants = Vec::new();
    let mut seen_pattern_ids = HashSet::new();

    for path in paths {
        let lib = load_pattern_library_with_limits(path, limits)?;
        for pattern in &lib.patterns {
            if !seen_pattern_ids.insert(pattern.id.clone()) {
                anyhow::bail!(
                    "Duplicate pattern id '{}' found while merging libraries",
                    pattern.id
                );
            }
        }
        all_patterns.extend(lib.patterns);
        all_invariants.extend(lib.invariants);
    }

    Ok(PatternLibrary {
        patterns: all_patterns,
        invariants: all_invariants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_pattern_ids_across_libraries_are_rejected() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let first = temp.path().join("a.yaml");
        let second = temp.path().join("b.yaml");

        std::fs::write(
            &first,
            "patterns:\n  - id: dup\n    kind: literal\n    pattern: foo\n    message: one\ninvariants: []\n",
        )
        .expect("write first");
        std::fs::write(
            &second,
            "patterns:\n  - id: dup\n    kind: literal\n    pattern: bar\n    message: two\ninvariants: []\n",
        )
        .expect("write second");

        let err = load_pattern_libraries_with_limits(&[&first, &second], LoaderLimits::default())
            .err()
            .expect("expected duplicate ID error");

        assert!(err.to_string().contains("Duplicate pattern id"));
    }
}
