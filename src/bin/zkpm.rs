use anyhow::Result;
use std::path::PathBuf;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, Severity};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        eprintln!("Usage: zkpm <pattern.yaml> <target_file>");
        eprintln!("       zkpm validate <pattern.yaml>");
        std::process::exit(1);
    }
    
    let command = &args[1];
    
    match command.as_str() {
        "validate" => {
            let pattern_path = PathBuf::from(&args[2]);
            let library = load_pattern_library(&pattern_path)?;
            println!("✓ Valid pattern library with {} patterns", library.patterns.len());
            if !library.invariants.is_empty() {
                println!("  {} invariants defined", library.invariants.len());
            }
            Ok(())
        }
        _ => {
            let pattern_path = PathBuf::from(&args[1]);
            let target_path = PathBuf::from(&args[2]);
            
            let library = load_pattern_library(&pattern_path)?;
            let matcher = PatternMatcher::new(library)?;
            let matches = matcher.scan_file(&target_path)?;
            
            if matches.is_empty() {
                println!("No patterns matched.");
                return Ok(());
            }
            
            println!("Found {} matches:\n", matches.len());
            
            for m in &matches {
                let severity_icon = match m.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🔵",
                    Severity::Info => "ℹ️",
                };
                
                println!("{} [{:?}] {}", severity_icon, m.severity, m.message);
                println!("   Pattern: {}", m.pattern_id);
                println!("   Location: {}:{}", m.location.line, m.location.column);
                println!("   Matched: {}", m.location.matched_text);
                println!();
            }
            
            let has_critical = matches.iter().any(|m| matches!(m.severity, Severity::Critical | Severity::High));
            if has_critical {
                std::process::exit(1);
            }
            
            Ok(())
        }
    }
}
