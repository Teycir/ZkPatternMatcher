use pattern_types::PatternLibrary;
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_pattern_library(path: &Path) -> Result<PatternLibrary> {
    const MAX_FILE_SIZE: u64 = 1024 * 1024; // 1MB limit for YAML
    
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata: {}", path.display()))?;
    
    if metadata.len() > MAX_FILE_SIZE {
        anyhow::bail!("Pattern file too large: {} bytes (max {})", metadata.len(), MAX_FILE_SIZE);
    }
    
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern file: {}", path.display()))?;
    
    // Limit YAML depth to prevent YAML bombs
    if content.matches('\n').count() > 10000 {
        anyhow::bail!("Pattern file too complex: {} lines (max 10000)", content.matches('\n').count());
    }
    
    let library: PatternLibrary = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;
    
    Ok(library)
}

pub fn load_pattern_libraries(paths: &[&Path]) -> Result<PatternLibrary> {
    const MAX_LIBRARIES: usize = 100;
    
    if paths.len() > MAX_LIBRARIES {
        anyhow::bail!("Too many pattern libraries: {} (max {})", paths.len(), MAX_LIBRARIES);
    }
    
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
