//! Error types for sentinel-modsec.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using the crate's Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for sentinel-modsec operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Error parsing a SecRule directive.
    #[error("parse error at {location}: {message}")]
    Parse {
        /// Human-readable error message.
        message: String,
        /// Location in the source (file:line:col or line:col).
        location: String,
        /// The source text that caused the error (if available).
        source_text: Option<String>,
    },

    /// Error loading a rule file.
    #[error("failed to load rule file {path}: {source}")]
    RuleFileLoad {
        /// Path to the file that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Error compiling a regex pattern.
    #[error("invalid regex pattern '{pattern}': {source}")]
    RegexCompile {
        /// The pattern that failed to compile.
        pattern: String,
        /// Underlying regex error.
        #[source]
        source: regex::Error,
    },

    /// Error compiling an Aho-Corasick pattern set.
    #[error("invalid pattern set: {message}")]
    PatternSet {
        /// Error message.
        message: String,
    },

    /// Error parsing an IP address or network.
    #[error("invalid IP address or network '{value}': {message}")]
    InvalidIp {
        /// The value that failed to parse.
        value: String,
        /// Error message.
        message: String,
    },

    /// Unknown variable name.
    #[error("unknown variable: {name}")]
    UnknownVariable {
        /// The unknown variable name.
        name: String,
    },

    /// Unknown operator name.
    #[error("unknown operator: @{name}")]
    UnknownOperator {
        /// The unknown operator name.
        name: String,
    },

    /// Unknown transformation name.
    #[error("unknown transformation: t:{name}")]
    UnknownTransformation {
        /// The unknown transformation name.
        name: String,
    },

    /// Unknown action name.
    #[error("unknown action: {name}")]
    UnknownAction {
        /// The unknown action name.
        name: String,
    },

    /// Invalid action argument.
    #[error("invalid argument for action '{action}': {message}")]
    InvalidActionArgument {
        /// The action name.
        action: String,
        /// Error message.
        message: String,
    },

    /// Rule is missing required 'id' action.
    #[error("rule is missing required 'id' action")]
    MissingRuleId,

    /// Duplicate rule ID.
    #[error("duplicate rule id: {id}")]
    DuplicateRuleId {
        /// The duplicate ID.
        id: u64,
    },

    /// Rule chain is incomplete.
    #[error("incomplete rule chain: chain action without following rule")]
    IncompleteChain,

    /// Error processing URI.
    #[error("failed to process URI: {message}")]
    ProcessUri {
        /// Error message.
        message: String,
    },

    /// Error processing request headers.
    #[error("failed to process request headers: {message}")]
    ProcessRequestHeaders {
        /// Error message.
        message: String,
    },

    /// Error processing request body.
    #[error("failed to process request body: {message}")]
    ProcessRequestBody {
        /// Error message.
        message: String,
    },

    /// Error processing response headers.
    #[error("failed to process response headers: {message}")]
    ProcessResponseHeaders {
        /// Error message.
        message: String,
    },

    /// Error processing response body.
    #[error("failed to process response body: {message}")]
    ProcessResponseBody {
        /// Error message.
        message: String,
    },

    /// Configuration error.
    #[error("configuration error: {message}")]
    Config {
        /// Error message.
        message: String,
    },

    /// Internal error (should not happen in normal operation).
    #[error("internal error: {message}")]
    Internal {
        /// Error message.
        message: String,
    },
}

impl Error {
    /// Create a parse error with location information.
    pub fn parse(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self::Parse {
            message: message.into(),
            location: location.into(),
            source_text: None,
        }
    }

    /// Create a parse error with location and source text.
    pub fn parse_with_source(
        message: impl Into<String>,
        location: impl Into<String>,
        source_text: impl Into<String>,
    ) -> Self {
        Self::Parse {
            message: message.into(),
            location: location.into(),
            source_text: Some(source_text.into()),
        }
    }
}

/// Source location for error reporting.
#[derive(Debug, Clone, Default)]
pub struct SourceLocation {
    /// File path (if known).
    pub file: Option<PathBuf>,
    /// Line number (1-indexed).
    pub line: usize,
    /// Column number (1-indexed).
    pub column: usize,
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref file) = self.file {
            write!(f, "{}:{}:{}", file.display(), self.line, self.column)
        } else {
            write!(f, "{}:{}", self.line, self.column)
        }
    }
}
