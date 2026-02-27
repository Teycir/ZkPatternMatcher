use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use zk_pattern_matcher::{load_pattern_library, PatternMatcher, PatternMatch, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

impl Summary {
    fn from_matches(matches: &[PatternMatch]) -> Self {
        Self {
            total: matches.len(),
            critical: matches.iter().filter(|m| m.severity == Severity::Critical).count(),
            high: matches.iter().filter(|m| m.severity == Severity::High).count(),
            medium: matches.iter().filter(|m| m.severity == Severity::Medium).count(),
            low: matches.iter().filter(|m| m.severity == Severity::Low).count(),
            info: matches.iter().filter(|m| m.severity == Severity::Info).count(),
        }
    }
}

fn severity_icon(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "ℹ️",
    }
}

fn print_usage() {
    eprintln!("zkpm {} - ZK Pattern Matcher", VERSION);
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    zkpm [OPTIONS] <pattern.yaml> <target_file>");
    eprintln!("    zkpm validate <pattern.yaml>");
    eprintln!("    zkpm list <pattern.yaml>");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --format <json|text>    Output format (default: text)");
    eprintln!("    -h, --help              Print help information");
    eprintln!("    -V, --version           Print version information");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    
    // Handle --help and --version
    if args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return Ok(());
    }
    
    if args[1] == "--version" || args[1] == "-V" {
        println!("zkpm {}", VERSION);
        return Ok(());
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
        "list" => {
            let pattern_path = PathBuf::from(&args[arg_offset + 1]);
            let library = load_pattern_library(&pattern_path)?;
            
            for pattern in &library.patterns {
                let severity = pattern.severity.as_ref().unwrap_or(&Severity::Info);
                println!("{} {} [{:?}] - {}", 
                    severity_icon(severity),
                    pattern.id, 
                    severity,
                    pattern.message
                );
            }
            
            println!("\nTotal: {} patterns", library.patterns.len());
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
    let output = JsonOutput {
        matches: matches.to_vec(),
        summary: Summary::from_matches(matches),
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
        println!("{} [{:?}] {}", severity_icon(&m.severity), m.severity, m.message);
        println!("   Pattern: {}", m.pattern_id);
        println!("   Location: {}:{}", m.location.line, m.location.column);
        println!("   Matched: {}", m.location.matched_text);
        println!();
    }
    
    Ok(())
}
