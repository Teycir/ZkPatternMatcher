use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub output: Output,
}

#[derive(Debug, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    #[serde(default = "default_max_pattern_file_size")]
    pub max_pattern_file_size: usize,
    #[serde(default = "default_max_patterns")]
    pub max_patterns: usize,
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
}

#[derive(Debug, Deserialize)]
pub struct Output {
    #[serde(default = "default_format")]
    pub default_format: String,
    #[serde(default = "default_show_icons")]
    pub show_icons: bool,
    #[serde(default = "default_fail_on_critical")]
    pub fail_on_critical: bool,
}

fn default_max_file_size() -> usize {
    10485760
}
fn default_max_pattern_file_size() -> usize {
    1048576
}
fn default_max_patterns() -> usize {
    1000
}
fn default_max_matches() -> usize {
    10000
}
fn default_format() -> String {
    "text".to_string()
}
fn default_show_icons() -> bool {
    true
}
fn default_fail_on_critical() -> bool {
    true
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: default_max_file_size(),
            max_pattern_file_size: default_max_pattern_file_size(),
            max_patterns: default_max_patterns(),
            max_matches: default_max_matches(),
        }
    }
}

impl Default for Output {
    fn default() -> Self {
        Self {
            default_format: default_format(),
            show_icons: default_show_icons(),
            fail_on_critical: default_fail_on_critical(),
        }
    }
}

pub fn load_config() -> Config {
    let paths = [
        PathBuf::from(".zkpm.toml"),
        dirs::home_dir()
            .map(|h| h.join(".zkpm/config.toml"))
            .unwrap_or_default(),
    ];

    for path in &paths {
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => return config,
                Err(err) => eprintln!(
                    "Warning: Failed to parse config at {}: {}. Using defaults.",
                    path.display(),
                    err
                ),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => eprintln!(
                "Warning: Failed to read config at {}: {}. Using defaults.",
                path.display(),
                err
            ),
        }
    }

    Config::default()
}

pub fn load_ignore_patterns() -> Vec<String> {
    let paths = [
        PathBuf::from(".zkpmignore"),
        dirs::home_dir()
            .map(|h| h.join(".zkpm/ignore"))
            .unwrap_or_default(),
    ];

    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect();
        }
    }

    vec![]
}
