//! Core types for ZK pattern matching.
//!
//! This crate provides the fundamental types used across the pattern matching system:
//! - Pattern definitions and libraries
//! - Match results and locations
//! - Severity levels and invariants
//!
//! # Example
//!
//! ```
//! use pattern_types::*;
//!
//! let pattern = Pattern {
//!     id: "test".to_string(),
//!     kind: PatternKind::Regex,
//!     pattern: r"<--".to_string(),
//!     message: "Unconstrained assignment".to_string(),
//!     severity: Some(Severity::Critical),
//! };
//! ```

use serde::{Deserialize, Serialize};

/// Severity level for vulnerability findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A collection of patterns and invariants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternLibrary {
    pub patterns: Vec<Pattern>,
    #[serde(default)]
    pub invariants: Vec<Invariant>,
}

/// A single pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub id: String,
    pub kind: PatternKind,
    pub pattern: String,
    pub message: String,
    #[serde(default)]
    pub severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    Regex,
    Literal,
    Ast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub invariant_type: InvariantType,
    pub relation: String,
    pub oracle: Oracle,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InvariantType {
    Constraint,
    Metamorphic,
    Differential,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Oracle {
    MustHold,
    MustFail,
    ShouldHold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub message: String,
    pub severity: Severity,
    pub location: MatchLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchLocation {
    pub line: usize,
    pub column: usize,
    pub matched_text: String,
}
