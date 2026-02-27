use anyhow::Result;
use std::path::PathBuf;
use zk_pattern_matcher::{
    load_pattern_library, load_config, load_ignore_patterns,
    Scanner, OutputFormatter, OutputFormat, Severity
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("zkpm {} - ZK Pattern Matcher", VERSION);
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    zkpm [OPTIONS] <pattern.yaml> <target>");
    eprintln!("    zkpm validate <pattern.yaml>");
    eprintln!("    zkpm list <pattern.yaml>");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --format <json|text|sarif>  Output format (default: text)");
    eprintln!("    -r, --recursive             Scan directories recursively");
    eprintln!("    --ignore <pattern>          Ignore files matching pattern");
    eprintln!("    -h, --help                  Print help information");
    eprintln!("    -V, --version               Print version information");
}

fn severity_icon(severity: &Severity, show_icons: bool) -> String {
    if !show_icons {
        return String::new();
    }
    match severity {
        Severity::Critical => "🔴 ",
        Severity::High => "🟠 ",
        Severity::Medium => "🟡 ",
        Severity::Low => "🔵 ",
        Severity::Info => "ℹ️  ",
    }.to_string()
}

fn main() -> Result<()> {
    let config = load_config();
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    
    if args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return Ok(());
    }
    
    if args[1] == "--version" || args[1] == "-V" {
        println!("zkpm {}", VERSION);
        return Ok(());
    }
    
    let mut format = config.output.default_format.as_str();
    let mut recursive = false;
    let mut custom_ignore: Vec<String> = Vec::new();
    let mut arg_offset = 1;
    
    while arg_offset < args.len() {
        match args[arg_offset].as_str() {
            "--format" if arg_offset + 1 < args.len() => {
                format = &args[arg_offset + 1];
                arg_offset += 2;
            }
            "-r" | "--recursive" => {
                recursive = true;
                arg_offset += 1;
            }
            "--ignore" if arg_offset + 1 < args.len() => {
                custom_ignore.push(args[arg_offset + 1].clone());
                arg_offset += 2;
            }
            _ => break,
        }
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
                println!("{}{} [{:?}] - {}", 
                    severity_icon(severity, config.output.show_icons),
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
            let matcher = zk_pattern_matcher::PatternMatcher::new(library)?;
            
            let mut ignore_patterns = load_ignore_patterns();
            ignore_patterns.extend(custom_ignore);
            
            let scanner = Scanner::new(matcher, ignore_patterns);
            
            let output_format = match format {
                "json" => OutputFormat::Json,
                "sarif" => OutputFormat::Sarif,
                _ => OutputFormat::Text,
            };
            let formatter = OutputFormatter::new(output_format, config.output.show_icons);
            
            if recursive {
                let results = scanner.scan_recursive(&target_path)?;
                formatter.output_recursive(&results)?;
                
                let has_critical = results.iter().any(|(_, matches)| {
                    matches.iter().any(|m| matches!(m.severity, Severity::Critical | Severity::High))
                });
                if has_critical && config.output.fail_on_critical {
                    std::process::exit(1);
                }
            } else {
                let matches = scanner.scan_file(&target_path)?;
                formatter.output_single(&matches, target_path.to_str().unwrap_or("unknown"))?;
                
                let has_critical = matches.iter().any(|m| matches!(m.severity, Severity::Critical | Severity::High));
                if has_critical && config.output.fail_on_critical {
                    std::process::exit(1);
                }
            }
            
            Ok(())
        }
    }
}
