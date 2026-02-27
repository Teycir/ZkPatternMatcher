use zk_pattern_matcher::{load_pattern_library, PatternMatcher, Severity};
use std::path::Path;

#[test]
fn test_no_false_positives_on_safe_multiplier() {
    let library = load_pattern_library(Path::new("patterns/real_vulnerabilities.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");
    
    let matches = matcher.scan_file(Path::new("tests/safe_circuits/safe_multiplier.circom"))
        .expect("Failed to scan file");
    
    let critical_or_high = matches.iter()
        .filter(|m| matches!(m.severity, Severity::Critical | Severity::High))
        .count();
    
    assert_eq!(critical_or_high, 0, 
        "Safe circuit should not trigger critical/high severity findings");
}

#[test]
fn test_no_false_positives_on_safe_merkle() {
    let library = load_pattern_library(Path::new("patterns/real_vulnerabilities.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");
    
    let matches = matcher.scan_file(Path::new("tests/safe_circuits/safe_merkle.circom"))
        .expect("Failed to scan file");
    
    let critical_or_high = matches.iter()
        .filter(|m| matches!(m.severity, Severity::Critical | Severity::High))
        .count();
    
    assert_eq!(critical_or_high, 0, 
        "Safe circuit should not trigger critical/high severity findings");
}

#[test]
fn test_safe_circuits_batch() {
    let library = load_pattern_library(Path::new("patterns/real_vulnerabilities.yaml"))
        .expect("Failed to load patterns");
    let matcher = PatternMatcher::new(library).expect("Failed to create matcher");
    
    let safe_circuits = vec![
        "tests/safe_circuits/safe_multiplier.circom",
        "tests/safe_circuits/safe_merkle.circom",
    ];
    
    for circuit in safe_circuits {
        let matches = matcher.scan_file(Path::new(circuit))
            .expect(&format!("Failed to scan {}", circuit));
        
        let critical_or_high = matches.iter()
            .filter(|m| matches!(m.severity, Severity::Critical | Severity::High))
            .count();
        
        assert_eq!(critical_or_high, 0, 
            "Safe circuit {} should not trigger critical/high findings", circuit);
    }
}
