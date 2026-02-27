use crate::{PatternMatch, Severity};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct SarifReport {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn build_result(pattern_match: &PatternMatch, file_path: &str) -> SarifResult {
    SarifResult {
        rule_id: pattern_match.pattern_id.clone(),
        level: severity_to_sarif_level(&pattern_match.severity).to_string(),
        message: SarifMessage {
            text: pattern_match.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: file_path.to_string(),
                },
                region: SarifRegion {
                    start_line: pattern_match.location.line,
                    start_column: pattern_match.location.column,
                },
            },
        }],
    }
}

fn build_report(results: Vec<SarifResult>) -> SarifReport {
    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "zkpm".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/teycir/ZkPatternMatcher".to_string(),
                },
            },
            results,
        }],
    }
}

pub fn to_sarif(matches: &[PatternMatch], file_path: &str) -> SarifReport {
    let results: Vec<SarifResult> = matches.iter().map(|m| build_result(m, file_path)).collect();

    build_report(results)
}

pub fn to_sarif_recursive(results_by_file: &[(PathBuf, Vec<PatternMatch>)]) -> SarifReport {
    let results = results_by_file
        .iter()
        .flat_map(|(path, matches)| {
            let file_path = path.to_string_lossy().to_string();
            matches.iter().map(move |m| build_result(m, &file_path))
        })
        .collect();

    build_report(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchLocation;

    #[test]
    fn recursive_sarif_preserves_each_file_uri() {
        let matches_by_file = vec![
            (
                PathBuf::from("/tmp/a.circom"),
                vec![PatternMatch {
                    pattern_id: "rule_a".to_string(),
                    message: "A".to_string(),
                    severity: Severity::High,
                    location: MatchLocation {
                        line: 1,
                        column: 1,
                        matched_text: "<--".to_string(),
                    },
                }],
            ),
            (
                PathBuf::from("/tmp/b.circom"),
                vec![PatternMatch {
                    pattern_id: "rule_b".to_string(),
                    message: "B".to_string(),
                    severity: Severity::Medium,
                    location: MatchLocation {
                        line: 2,
                        column: 3,
                        matched_text: "==".to_string(),
                    },
                }],
            ),
        ];

        let report = to_sarif_recursive(&matches_by_file);
        let json = serde_json::to_value(report).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();

        let uris: Vec<&str> = results
            .iter()
            .map(|result| {
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
            })
            .collect();

        assert!(uris.contains(&"/tmp/a.circom"));
        assert!(uris.contains(&"/tmp/b.circom"));
    }
}
