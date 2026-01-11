//! Operator trait definition.

/// Result of operator execution.
#[derive(Debug, Clone, Default)]
pub struct OperatorResult {
    /// Whether the operator matched.
    pub matched: bool,
    /// Captured groups from regex.
    pub captures: Vec<String>,
    /// The matched value.
    pub matched_value: Option<String>,
}

impl OperatorResult {
    /// Create a result indicating no match.
    pub fn no_match() -> Self {
        Self {
            matched: false,
            captures: Vec::new(),
            matched_value: None,
        }
    }

    /// Create a result indicating a match.
    pub fn matched(value: String) -> Self {
        Self {
            matched: true,
            captures: Vec::new(),
            matched_value: Some(value),
        }
    }

    /// Create a result with captures.
    pub fn matched_with_captures(value: String, captures: Vec<String>) -> Self {
        Self {
            matched: true,
            captures,
            matched_value: Some(value),
        }
    }
}

/// Trait for all operators.
pub trait Operator: Send + Sync {
    /// Execute the operator against a value.
    fn execute(&self, value: &str) -> OperatorResult;

    /// Get the operator name.
    fn name(&self) -> &'static str;

    /// Whether this operator supports capture groups.
    fn supports_capture(&self) -> bool {
        false
    }
}
