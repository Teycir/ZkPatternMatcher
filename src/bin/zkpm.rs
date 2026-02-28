use anyhow::Result;
use std::path::PathBuf;
use zk_pattern_matcher::{
    load_config, load_ignore_patterns, load_pattern_library_with_limits, severity_icon,
    LoaderLimits, MatcherLimits, OutputFormat, OutputFormatter, Scanner, Severity,
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
    eprintln!("    --semantic                  Enable two-pass semantic checks (cross-line)");
    eprintln!("    --strict-severity           Keep original severities in semantic mode");
    eprintln!("    -h, --help                  Print help information");
    eprintln!("    -V, --version               Print version information");
}

fn usage_error(message: &str) -> ! {
    eprintln!("Error: {message}\n");
    print_usage();
    std::process::exit(2);
}

fn main() -> Result<()> {
    let config = load_config();
    let loader_limits = LoaderLimits {
        max_file_size: config.limits.max_pattern_file_size as u64,
        ..LoaderLimits::default()
    };
    let matcher_limits = MatcherLimits {
        max_patterns: config.limits.max_patterns,
        max_matches: config.limits.max_matches,
        max_file_size: config.limits.max_file_size as u64,
        ..MatcherLimits::default()
    };

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
    let mut semantic = false;
    let mut strict_severity = false;
    let mut custom_ignore: Vec<String> = Vec::new();
    let mut arg_offset = 1;

    while arg_offset < args.len() {
        match args[arg_offset].as_str() {
            "--format" if arg_offset + 1 < args.len() => {
                format = &args[arg_offset + 1];
                arg_offset += 2;
            }
            arg if arg.starts_with("--format=") => {
                let value = arg.trim_start_matches("--format=");
                if value.is_empty() {
                    usage_error("missing value for --format");
                }
                format = value;
                arg_offset += 1;
            }
            "--format" => usage_error("missing value for --format"),
            "-r" | "--recursive" => {
                recursive = true;
                arg_offset += 1;
            }
            "--semantic" => {
                semantic = true;
                arg_offset += 1;
            }
            "--strict-severity" => {
                strict_severity = true;
                arg_offset += 1;
            }
            "--ignore" if arg_offset + 1 < args.len() => {
                custom_ignore.push(args[arg_offset + 1].clone());
                arg_offset += 2;
            }
            arg if arg.starts_with("--ignore=") => {
                let value = arg.trim_start_matches("--ignore=");
                if value.is_empty() {
                    usage_error("missing value for --ignore");
                }
                custom_ignore.push(value.to_string());
                arg_offset += 1;
            }
            "--ignore" => usage_error("missing value for --ignore"),
            arg if arg.starts_with('-') => usage_error(&format!("unknown option: {arg}")),
            _ => break,
        }
    }

    if arg_offset >= args.len() {
        usage_error("missing command or <pattern.yaml> argument");
    }

    let command = &args[arg_offset];

    match command.as_str() {
        "validate" => {
            if arg_offset + 1 >= args.len() {
                usage_error("validate requires <pattern.yaml>");
            }
            let pattern_path = PathBuf::from(&args[arg_offset + 1]);
            let library = load_pattern_library_with_limits(&pattern_path, loader_limits)?;
            println!(
                "✓ Valid pattern library with {} patterns",
                library.patterns.len()
            );
            if !library.invariants.is_empty() {
                println!("  {} invariants defined", library.invariants.len());
            }
            Ok(())
        }
        "list" => {
            if arg_offset + 1 >= args.len() {
                usage_error("list requires <pattern.yaml>");
            }
            let pattern_path = PathBuf::from(&args[arg_offset + 1]);
            let library = load_pattern_library_with_limits(&pattern_path, loader_limits)?;

            for pattern in &library.patterns {
                let severity = pattern.severity.as_ref().unwrap_or(&Severity::Info);
                println!(
                    "{}{} [{:?}] - {}",
                    severity_icon(config.output.show_icons, severity),
                    pattern.id,
                    severity,
                    pattern.message
                );
            }

            println!("\nTotal: {} patterns", library.patterns.len());
            Ok(())
        }
        _ => {
            if arg_offset + 1 >= args.len() {
                usage_error("scan requires <pattern.yaml> <target>");
            }
            let pattern_path = PathBuf::from(&args[arg_offset]);
            let target_path = PathBuf::from(&args[arg_offset + 1]);

            let library = load_pattern_library_with_limits(&pattern_path, loader_limits)?;
            if !library.invariants.is_empty() {
                eprintln!(
                    "Warning: {} invariants loaded but invariant enforcement is not implemented yet.",
                    library.invariants.len()
                );
            }
            if !semantic {
                eprintln!(
                    "Note: regex-only mode may produce false positives from comments/strings. Use --semantic for higher-confidence findings."
                );
            }
            let matcher =
                zk_pattern_matcher::PatternMatcher::new_with_limits(library, matcher_limits)?
                    .with_semantic(semantic)
                    .with_strict_severity(strict_severity);

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
                    matches
                        .iter()
                        .any(|m| matches!(m.severity, Severity::Critical | Severity::High))
                });
                if has_critical && config.output.fail_on_critical {
                    std::process::exit(1);
                }
            } else {
                let matches = scanner.scan_file(&target_path)?;
                formatter.output_single(&matches, target_path.to_str().unwrap_or("unknown"))?;

                let has_critical = matches
                    .iter()
                    .any(|m| matches!(m.severity, Severity::Critical | Severity::High));
                if has_critical && config.output.fail_on_critical {
                    std::process::exit(1);
                }
            }

            Ok(())
        }
    }
}
