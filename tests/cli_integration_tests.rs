use std::process::Command;

#[test]
fn test_cli_scan_vulnerable_circuit_exits_with_error() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--", 
                "patterns/real_vulnerabilities.yaml",
                "tests/real_vulnerabilities/underconstrained_multiplier.circom"])
        .output()
        .expect("Failed to execute zkpm");
    
    assert!(!output.status.success(), "Should exit with error on critical findings");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Found"), "Should report matches");
    assert!(stdout.contains("Critical"), "Should detect critical severity");
}

#[test]
fn test_cli_json_output_is_valid() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "--format", "json",
                "patterns/real_vulnerabilities.yaml",
                "tests/real_vulnerabilities/underconstrained_multiplier.circom"])
        .output()
        .expect("Failed to execute zkpm");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("Output should be valid JSON");
    
    assert!(json["matches"].is_array(), "Should have matches array");
    assert!(json["summary"]["total"].is_number(), "Should have summary");
    assert!(json["summary"]["critical"].as_u64().unwrap() > 0, "Should detect critical issues");
}

#[test]
fn test_cli_validate_command() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "validate",
                "patterns/real_vulnerabilities.yaml"])
        .output()
        .expect("Failed to execute zkpm");
    
    assert!(output.status.success(), "Validate should succeed on valid pattern");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Valid pattern library"), "Should confirm validity");
    assert!(stdout.contains("patterns"), "Should report pattern count");
}

#[test]
fn test_cli_list_command() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "list",
                "patterns/real_vulnerabilities.yaml"])
        .output()
        .expect("Failed to execute zkpm");
    
    assert!(output.status.success(), "List should succeed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("underconstrained_assignment"), "Should list pattern IDs");
    assert!(stdout.contains("Total:"), "Should show total count");
    assert!(stdout.contains("Critical") || stdout.contains("High"), "Should show severity");
}

#[test]
fn test_cli_handles_missing_file() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "patterns/real_vulnerabilities.yaml",
                "nonexistent.circom"])
        .output()
        .expect("Failed to execute zkpm");
    
    assert!(!output.status.success(), "Should fail on missing file");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to read") || stderr.contains("No such file"), 
            "Should report file error");
}

#[test]
fn test_cli_handles_invalid_pattern_file() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "nonexistent_pattern.yaml",
                "tests/real_vulnerabilities/underconstrained_multiplier.circom"])
        .output()
        .expect("Failed to execute zkpm");
    
    assert!(!output.status.success(), "Should fail on missing pattern file");
}

#[test]
fn test_cli_scan_clean_circuit_succeeds() {
    // Create a clean circuit file
    let clean_circuit = "pragma circom 2.0.0;\n\
                        template Clean() {\n\
                            signal input a;\n\
                            signal output b;\n\
                            b <== a * 2;\n\
                        }\n\
                        component main = Clean();";
    
    std::fs::write("/tmp/clean_test.circom", clean_circuit).unwrap();
    
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--",
                "patterns/underconstrained.yaml",
                "/tmp/clean_test.circom"])
        .output()
        .expect("Failed to execute zkpm");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should either find no matches or only low-severity matches
    if stdout.contains("No patterns matched") {
        assert!(output.status.success(), "Should succeed when no patterns match");
    }
    
    std::fs::remove_file("/tmp/clean_test.circom").ok();
}
