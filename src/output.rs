use crate::{sarif, PatternMatch, Severity};
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct JsonOutput {
    pub matches: Vec<PatternMatch>,
    pub summary: Summary,
}

#[derive(Serialize)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Summary {
    pub fn from_matches(matches: &[PatternMatch]) -> Self {
        Self {
            total: matches.len(),
            critical: matches
                .iter()
                .filter(|m| m.severity == Severity::Critical)
                .count(),
            high: matches
                .iter()
                .filter(|m| m.severity == Severity::High)
                .count(),
            medium: matches
                .iter()
                .filter(|m| m.severity == Severity::Medium)
                .count(),
            low: matches
                .iter()
                .filter(|m| m.severity == Severity::Low)
                .count(),
            info: matches
                .iter()
                .filter(|m| m.severity == Severity::Info)
                .count(),
        }
    }
}

pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

pub struct OutputFormatter {
    format: OutputFormat,
    show_icons: bool,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat, show_icons: bool) -> Self {
        Self { format, show_icons }
    }

    pub fn output_single(&self, matches: &[PatternMatch], file_path: &str) -> Result<()> {
        match self.format {
            OutputFormat::Text => self.output_text(matches),
            OutputFormat::Json => self.output_json(matches),
            OutputFormat::Sarif => self.output_sarif(matches, file_path),
        }
    }

    pub fn output_recursive(&self, results: &[(PathBuf, Vec<PatternMatch>)]) -> Result<()> {
        match self.format {
            OutputFormat::Text => self.output_text_recursive(results),
            OutputFormat::Json => self.output_json_recursive(results),
            OutputFormat::Sarif => self.output_sarif_recursive(results),
        }
    }

    fn severity_icon(&self, severity: &Severity) -> String {
        if !self.show_icons {
            return String::new();
        }
        match severity {
            Severity::Critical => "🔴 ",
            Severity::High => "🟠 ",
            Severity::Medium => "🟡 ",
            Severity::Low => "🔵 ",
            Severity::Info => "ℹ️  ",
        }
        .to_string()
    }

    fn output_text(&self, matches: &[PatternMatch]) -> Result<()> {
        if matches.is_empty() {
            println!("No patterns matched.");
            return Ok(());
        }

        println!("Found {} matches:\n", matches.len());

        for m in matches {
            println!(
                "{}[{:?}] {}",
                self.severity_icon(&m.severity),
                m.severity,
                m.message
            );
            println!("   Pattern: {}", m.pattern_id);
            println!("   Location: {}:{}", m.location.line, m.location.column);
            println!("   Matched: {}", m.location.matched_text);
            println!();
        }

        Ok(())
    }

    fn output_text_recursive(&self, results: &[(PathBuf, Vec<PatternMatch>)]) -> Result<()> {
        if results.is_empty() {
            println!("No patterns matched.");
            return Ok(());
        }

        let total: usize = results.iter().map(|(_, m)| m.len()).sum();
        println!("Found {} matches in {} files:\n", total, results.len());

        for (path, matches) in results {
            println!("{}:", path.display());
            for m in matches {
                println!(
                    "  {}[{:?}] {}",
                    self.severity_icon(&m.severity),
                    m.severity,
                    m.message
                );
                println!("     Pattern: {}", m.pattern_id);
                println!("     Location: {}:{}", m.location.line, m.location.column);
                println!();
            }
        }

        Ok(())
    }

    fn output_json(&self, matches: &[PatternMatch]) -> Result<()> {
        let output = JsonOutput {
            matches: matches.to_vec(),
            summary: Summary::from_matches(matches),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }

    fn output_json_recursive(&self, results: &[(PathBuf, Vec<PatternMatch>)]) -> Result<()> {
        let all_matches: Vec<PatternMatch> = results
            .iter()
            .flat_map(|(_, matches)| matches.clone())
            .collect();
        self.output_json(&all_matches)
    }

    fn output_sarif(&self, matches: &[PatternMatch], file_path: &str) -> Result<()> {
        let report = sarif::to_sarif(matches, file_path);
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    fn output_sarif_recursive(&self, results: &[(PathBuf, Vec<PatternMatch>)]) -> Result<()> {
        let all_matches: Vec<PatternMatch> = results
            .iter()
            .flat_map(|(_, matches)| matches.clone())
            .collect();
        let file_path = results
            .first()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .unwrap_or_default();
        self.output_sarif(&all_matches, &file_path)
    }
}
