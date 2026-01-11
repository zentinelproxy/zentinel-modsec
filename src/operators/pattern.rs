//! Pattern matching operators (@rx, @pm).

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};
use aho_corasick::AhoCorasick;
use regex::Regex;

/// Regex operator (@rx).
pub struct RxOperator {
    pattern: Regex,
}

impl RxOperator {
    /// Create a new regex operator.
    pub fn new(pattern: &str) -> Result<Self> {
        let regex = Regex::new(pattern).map_err(|e| Error::RegexCompile {
            pattern: pattern.to_string(),
            source: e,
        })?;
        Ok(Self { pattern: regex })
    }
}

impl Operator for RxOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Some(captures) = self.pattern.captures(value) {
            let matched_value = captures.get(0).map(|m| m.as_str().to_string());
            let capture_groups: Vec<String> = captures
                .iter()
                .skip(1) // Skip the full match
                .filter_map(|c| c.map(|m| m.as_str().to_string()))
                .collect();

            OperatorResult {
                matched: true,
                captures: capture_groups,
                matched_value,
            }
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "rx"
    }

    fn supports_capture(&self) -> bool {
        true
    }
}

/// Phrase match operator (@pm).
pub struct PmOperator {
    automaton: AhoCorasick,
    patterns: Vec<String>,
}

impl PmOperator {
    /// Create a new phrase match operator from space-separated patterns.
    pub fn new(patterns_str: &str) -> Result<Self> {
        let patterns: Vec<String> = patterns_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern list".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self { automaton, patterns })
    }

    /// Create a phrase match operator from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::RuleFileLoad {
            path: path.into(),
            source: e,
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern file".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self { automaton, patterns })
    }
}

impl Operator for PmOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Some(mat) = self.automaton.find(value) {
            let matched = &self.patterns[mat.pattern().as_usize()];
            OperatorResult::matched(matched.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "pm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx_simple() {
        let op = RxOperator::new("^admin").unwrap();
        assert!(op.execute("admin").matched);
        assert!(!op.execute("user").matched);
    }

    #[test]
    fn test_rx_captures() {
        let op = RxOperator::new(r"user=(\w+)").unwrap();
        let result = op.execute("user=john");
        assert!(result.matched);
        assert_eq!(result.captures, vec!["john"]);
    }

    #[test]
    fn test_pm_simple() {
        let op = PmOperator::new("admin root user").unwrap();
        assert!(op.execute("the admin user").matched);
        assert!(!op.execute("guest").matched);
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = PmOperator::new("ADMIN").unwrap();
        assert!(op.execute("admin").matched);
        assert!(op.execute("Admin").matched);
    }
}
