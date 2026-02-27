use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_batch_scan_multiple_files() {
    // Real-world: scanning multiple circuits in a project
    let output = Command::new("sh")
        .arg("-c")
        .arg(
            "find tests/real_vulnerabilities -name '*.circom' | \
              xargs -I {} cargo run --quiet --bin zkpm -- \
              patterns/real_vulnerabilities.yaml {} 2>&1 | \
              grep -c 'Found'",
        )
        .output()
        .expect("Failed to execute batch scan");

    let count = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(0);
    assert!(count >= 3, "Should scan all 3 vulnerable circuits");
}

#[test]
fn test_ci_pipeline_simulation() {
    // Real-world: CI/CD pipeline checking for vulnerabilities
    let temp_dir = TempDir::new().unwrap();
    let circuit_path = temp_dir.path().join("circuit.circom");

    // Vulnerable circuit
    fs::write(
        &circuit_path,
        "pragma circom 2.0.0;\n\
         template Test() {\n\
             signal input a;\n\
             signal output b;\n\
             b <-- a * 2;  // Vulnerable\n\
         }\n\
         component main = Test();",
    )
    .unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--bin",
            "zkpm",
            "--",
            "patterns/real_vulnerabilities.yaml",
            circuit_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    // CI should fail on critical findings
    assert!(
        !output.status.success(),
        "CI should fail on vulnerabilities"
    );
    assert_eq!(output.status.code(), Some(1), "Should exit with code 1");
}

#[test]
fn test_json_parsing_for_automation() {
    // Real-world: parsing JSON in scripts/tools
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--bin",
            "zkpm",
            "--",
            "--format",
            "json",
            "patterns/real_vulnerabilities.yaml",
            "tests/real_vulnerabilities/weak_nullifier.circom",
        ])
        .output()
        .expect("Failed to execute");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Should produce valid JSON");

    // Automation needs these fields
    assert!(json.get("matches").is_some());
    assert!(json.get("summary").is_some());
    assert!(json["summary"].get("critical").is_some());

    // Extract specific data like automation would
    let critical_count = json["summary"]["critical"].as_u64().unwrap();
    assert!(critical_count > 0, "Should detect critical issues");
}

#[test]
fn test_pattern_library_discovery() {
    // Real-world: discovering what patterns are available
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--bin",
            "zkpm",
            "--",
            "list",
            "patterns/real_vulnerabilities.yaml",
        ])
        .output()
        .expect("Failed to execute");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    // Should list multiple patterns
    assert!(lines.len() > 3, "Should list multiple patterns");

    // Each pattern should have ID and severity
    let pattern_lines: Vec<&str> = lines
        .iter()
        .filter(|l| l.contains("[Critical]") || l.contains("[High]"))
        .copied()
        .collect();

    assert!(
        pattern_lines.len() >= 3,
        "Should have multiple high-severity patterns"
    );
}

#[test]
fn test_large_file_handling() {
    // Real-world: scanning large circuit files
    let temp_dir = TempDir::new().unwrap();
    let large_circuit = temp_dir.path().join("large.circom");

    // Create a large circuit (but under 10MB limit)
    let mut content = String::from("pragma circom 2.0.0;\ntemplate Large() {\n");
    for i in 0..1000 {
        content.push_str(&format!("    signal input a{};\n", i));
    }
    content.push_str("    signal output b;\n    b <-- a0;\n}\ncomponent main = Large();");

    fs::write(&large_circuit, content).unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--bin",
            "zkpm",
            "--",
            "patterns/real_vulnerabilities.yaml",
            large_circuit.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute");

    // Should handle large files without crashing
    assert!(
        output.status.code().is_some(),
        "Should complete without crash"
    );
}
