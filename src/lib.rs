pub mod config;
pub mod output;
pub mod sarif;
pub mod scanner;

pub use config::{load_config, load_ignore_patterns, Config};
pub use output::{severity_icon, OutputFormat, OutputFormatter};
pub use pattern_loader::{
    load_pattern_libraries, load_pattern_libraries_with_limits, load_pattern_library,
    load_pattern_library_with_limits, LoaderLimits,
};
pub use pattern_matcher::{MatcherLimits, PatternMatcher};
pub use pattern_types::*;
pub use scanner::Scanner;
