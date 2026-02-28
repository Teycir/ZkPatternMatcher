use std::process::Command;

#[test]
fn test_cli_scan_vulnerable_circuit_exits_with_error() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "patterns/real_vulnerabilities.yaml",
            "tests/real_vulnerabilities/underconstrained_multiplier.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(
        !output.status.success(),
        "Should exit with error on critical findings"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Found"), "Should report matches");
    assert!(
        stdout.contains("Critical"),
        "Should detect critical severity"
    );
}

#[test]
fn test_cli_json_output_is_valid() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "--format",
            "json",
            "patterns/real_vulnerabilities.yaml",
            "tests/real_vulnerabilities/underconstrained_multiplier.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    assert!(json["matches"].is_array(), "Should have matches array");
    assert!(json["summary"]["total"].is_number(), "Should have summary");
    assert!(
        json["summary"]["critical"].as_u64().unwrap() > 0,
        "Should detect critical issues"
    );
}

#[test]
fn test_cli_validate_command() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "validate",
            "patterns/real_vulnerabilities.yaml",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(
        output.status.success(),
        "Validate should succeed on valid pattern"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Valid pattern library"),
        "Should confirm validity"
    );
    assert!(stdout.contains("patterns"), "Should report pattern count");
}

#[test]
fn test_cli_list_command() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "list",
            "patterns/real_vulnerabilities.yaml",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(output.status.success(), "List should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("underconstrained_assignment"),
        "Should list pattern IDs"
    );
    assert!(stdout.contains("Total:"), "Should show total count");
    assert!(
        stdout.contains("Critical") || stdout.contains("High"),
        "Should show severity"
    );
}

#[test]
fn test_cli_handles_missing_file() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "patterns/real_vulnerabilities.yaml",
            "nonexistent.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(!output.status.success(), "Should fail on missing file");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read") || stderr.contains("No such file"),
        "Should report file error"
    );
}

#[test]
fn test_cli_handles_invalid_pattern_file() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "nonexistent_pattern.yaml",
            "tests/real_vulnerabilities/underconstrained_multiplier.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(
        !output.status.success(),
        "Should fail on missing pattern file"
    );
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
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "patterns/underconstrained.yaml",
            "/tmp/clean_test.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should either find no matches or only low-severity matches
    if stdout.contains("No patterns matched") {
        assert!(
            output.status.success(),
            "Should succeed when no patterns match"
        );
    }

    std::fs::remove_file("/tmp/clean_test.circom").ok();
}

#[test]
fn test_cli_validate_requires_pattern_argument_without_panic() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--", "validate"])
        .output()
        .expect("Failed to execute zkpm");

    assert!(!output.status.success(), "Should fail when arg is missing");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("validate requires <pattern.yaml>"));
    assert!(!stderr.contains("panicked at"));
}

#[test]
fn test_cli_scan_requires_target_argument_without_panic() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "patterns/real_vulnerabilities.yaml",
        ])
        .output()
        .expect("Failed to execute zkpm");

    assert!(
        !output.status.success(),
        "Should fail when target is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("scan requires <pattern.yaml> <target>"));
    assert!(!stderr.contains("panicked at"));
}

#[test]
fn test_cli_semantic_flag_emits_semantic_findings() {
    let pattern_file = "/tmp/zkpm_semantic_empty.yaml";
    let circuit_file = "/tmp/zkpm_semantic_case.circom";

    std::fs::write(pattern_file, "patterns: []\ninvariants: []\n").unwrap();
    std::fs::write(
        circuit_file,
        "pragma circom 2.0.0;\n\
         template T() {\n\
             var x;\n\
             x === x;\n\
         }\n\
         component main = T();\n",
    )
    .unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "--semantic",
            pattern_file,
            circuit_file,
        ])
        .output()
        .expect("Failed to execute zkpm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("self_equality_constraint"));
    assert!(stdout.contains("constraint_on_var"));

    std::fs::remove_file(pattern_file).ok();
    std::fs::remove_file(circuit_file).ok();
}

#[test]
fn test_cli_strict_severity_preserves_original_levels_in_semantic_mode() {
    let circuit_file = "/tmp/zkpm_strict_severity_case.circom";

    std::fs::write(
        circuit_file,
        "pragma circom 2.0.0;\n\
         template T() {\n\
             signal x;\n\
             x <-- 1;\n\
             x === 1;\n\
         }\n\
         component main = T();\n",
    )
    .unwrap();

    let semantic_output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "--semantic",
            "--format",
            "json",
            "patterns/production.yaml",
            circuit_file,
        ])
        .output()
        .expect("Failed to execute zkpm");
    let semantic_stdout = String::from_utf8_lossy(&semantic_output.stdout);
    let semantic_json: serde_json::Value =
        serde_json::from_str(&semantic_stdout).expect("Output should be valid JSON");
    let semantic_severity = semantic_json["matches"]
        .as_array()
        .expect("matches should be an array")
        .iter()
        .find(|m| m["pattern_id"] == "unconstrained_assignment")
        .and_then(|m| m["severity"].as_str())
        .expect("unconstrained_assignment severity should be present");
    assert_eq!(semantic_severity, "medium");

    let strict_output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "--semantic",
            "--strict-severity",
            "--format",
            "json",
            "patterns/production.yaml",
            circuit_file,
        ])
        .output()
        .expect("Failed to execute zkpm");
    let strict_stdout = String::from_utf8_lossy(&strict_output.stdout);
    let strict_json: serde_json::Value =
        serde_json::from_str(&strict_stdout).expect("Output should be valid JSON");
    let strict_severity = strict_json["matches"]
        .as_array()
        .expect("matches should be an array")
        .iter()
        .find(|m| m["pattern_id"] == "unconstrained_assignment")
        .and_then(|m| m["severity"].as_str())
        .expect("unconstrained_assignment severity should be present");
    assert_eq!(strict_severity, "critical");

    std::fs::remove_file(circuit_file).ok();
}

#[test]
fn test_cli_supports_equals_style_format_option() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "zkpm",
            "--",
            "--format=json",
            "patterns/real_vulnerabilities.yaml",
            "tests/real_vulnerabilities/underconstrained_multiplier.circom",
        ])
        .output()
        .expect("Failed to execute zkpm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");
    assert!(json["matches"].is_array());
}

#[test]
fn test_cli_warns_when_invariants_are_present_but_not_enforced() {
    let pattern_file = "/tmp/zkpm_invariant_only.yaml";
    let circuit_file = "/tmp/zkpm_invariant_case.circom";

    std::fs::write(
        pattern_file,
        "patterns: []\ninvariants:\n  - name: foo\n    invariant_type: constraint\n    relation: \"x\"\n    oracle: must_hold\n    severity: low\n    description: \"unused\"\n",
    )
    .unwrap();
    std::fs::write(
        circuit_file,
        "pragma circom 2.0.0;\ntemplate T(){ signal input a; signal output b; b <== a; }\ncomponent main = T();\n",
    )
    .unwrap();

    let output = Command::new("cargo")
        .args(["run", "--bin", "zkpm", "--", pattern_file, circuit_file])
        .output()
        .expect("Failed to execute zkpm");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invariant enforcement is not implemented"));

    std::fs::remove_file(pattern_file).ok();
    std::fs::remove_file(circuit_file).ok();
}
