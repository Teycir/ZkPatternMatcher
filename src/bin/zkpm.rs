use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, PatternMatch, Severity};

#[derive(Serialize)]
struct JsonOutput {
    matches: Vec<PatternMatch>,
    summary: Summary,
}

#[derive(Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        eprintln!("Usage: zkpm [--format json|text] <pattern.yaml> <target_file>");
        eprintln!("       zkpm validate <pattern.yaml>");
        std::process::exit(1);
    }
    
    let mut format = "text";
    let mut arg_offset = 1;
    
    if args[1] == "--format" && args.len() > 3 {
        format = &args[2];
        arg_offset = 3;
    }
    
    let command = &args[arg_offset];
    
    match command.as_str() {
        "validate" => {
            let pattern_path = PathBuf::from(&args[arg_offset + 1]);
            let library = load_pattern_library(&pattern_path)?;
            println!("✓ Valid pattern library with {} patterns", library.patterns.len());
            if !library.invariants.is_empty() {
                println!("  {} invariants defined", library.invariants.len());
            }
            Ok(())
        }
        _ => {
            let pattern_path = PathBuf::from(&args[arg_offset]);
            let target_path = PathBuf::from(&args[arg_offset + 1]);
            
            let library = load_pattern_library(&pattern_path)?;
            let matcher = PatternMatcher::new(library)?;
            let matches = matcher.scan_file(&target_path)?;
            
            if format == "json" {
                output_json(&matches)?;
            } else {
                output_text(&matches)?;
            }
            
            let has_critical = matches.iter().any(|m| matches!(m.severity, Severity::Critical | Severity::High));
            if has_critical {
                std::process::exit(1);
            }
            
            Ok(())
        }
    }
}

fn output_json(matches: &[PatternMatch]) -> Result<()> {
    let summary = Summary {
        total: matches.len(),
        critical: matches.iter().filter(|m| m.severity == Severity::Critical).count(),
        high: matches.iter().filter(|m| m.severity == Severity::High).count(),
        medium: matches.iter().filter(|m| m.severity == Severity::Medium).count(),
        low: matches.iter().filter(|m| m.severity == Severity::Low).count(),
        info: matches.iter().filter(|m| m.severity == Severity::Info).count(),
    };
    
    let output = JsonOutput {
        matches: matches.to_vec(),
        summary,
    };
    
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn output_text(matches: &[PatternMatch]) -> Result<()> {
    if matches.is_empty() {
        println!("No patterns matched.");
        return Ok(());
    }
    
    println!("Found {} matches:\n", matches.len());
    
    for m in matches {
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
    
    Ok(())
}
