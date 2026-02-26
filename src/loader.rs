use crate::types::PatternLibrary;
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_pattern_library(path: &Path) -> Result<PatternLibrary> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern file: {}", path.display()))?;
    
    let library: PatternLibrary = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;
    
    Ok(library)
}

pub fn load_pattern_libraries(paths: &[&Path]) -> Result<PatternLibrary> {
    let mut all_patterns = Vec::new();
    let mut all_invariants = Vec::new();
    
    for path in paths {
        let lib = load_pattern_library(path)?;
        all_patterns.extend(lib.patterns);
        all_invariants.extend(lib.invariants);
    }
    
    Ok(PatternLibrary {
        patterns: all_patterns,
        invariants: all_invariants,
    })
}
