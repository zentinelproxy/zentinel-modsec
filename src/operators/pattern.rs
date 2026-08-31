//! Pattern matching operators (@rx, @pm).
//!
//! Optimized with lazy regex compilation for fast rule parsing.

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};
use aho_corasick::AhoCorasick;
use once_cell::sync::OnceCell;
use regex::Regex;

/// Regex operator (@rx) with lazy compilation.
///
/// The pattern's *syntax* is validated when the rule is loaded, but the
/// automaton is only built on first use — CRS defines hundreds of regex rules
/// and most requests exercise few of them.
///
/// The distinction matters: an invalid pattern must be a load error. If it
/// were discovered at match time there would be nothing useful to do about it,
/// and the rule would silently never match — a dead rule that looks alive.
pub struct RxOperator {
    pattern_str: String,
    /// `None` once compilation has been attempted and failed, so a pattern
    /// that passes syntax validation but cannot be built (an oversized
    /// program, say) is reported once rather than retried per request.
    compiled: OnceCell<Option<Regex>>,
}

impl RxOperator {
    /// Create a new regex operator, validating the pattern's syntax.
    ///
    /// Parsing with `regex-syntax` catches every syntax error the full
    /// compiler would, without building the automaton, so loading stays fast
    /// while a malformed pattern fails loudly at load instead of turning into
    /// a rule that can never match.
    #[inline]
    pub fn new(pattern: &str) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax("empty pattern".to_string()),
            });
        }

        if let Err(e) = regex_syntax::Parser::new().parse(pattern) {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax(e.to_string()),
            });
        }

        Ok(Self {
            pattern_str: pattern.to_string(),
            compiled: OnceCell::new(),
        })
    }

    /// Get or compile the regex pattern.
    ///
    /// Returns `None` if compilation failed. Syntax was already validated in
    /// [`RxOperator::new`], so reaching this is rare — a program too large to
    /// build, for instance. It is reported once, because a rule that cannot
    /// match must not do so silently.
    #[inline]
    fn get_regex(&self) -> Option<&Regex> {
        self.compiled
            .get_or_init(|| match Regex::new(&self.pattern_str) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    tracing::error!(
                        pattern = %self.pattern_str,
                        error = %e,
                        "regex could not be compiled at first use; this rule can never match"
                    );
                    None
                }
            })
            .as_ref()
    }
}

impl Operator for RxOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        let Some(regex) = self.get_regex() else {
            return OperatorResult::no_match();
        };

        if let Some(captures) = regex.captures(value) {
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

        Ok(Self {
            automaton,
            patterns,
        })
    }

    /// Create a phrase match operator from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        // Try the path as-is first, then common CRS locations
        let possible_paths = [
            path.to_string(),
            format!("test-rules/crs/rules/{}", path),
            format!("rules/{}", path),
        ];

        let mut content = None;
        let mut last_error = None;

        for p in &possible_paths {
            match std::fs::read_to_string(p) {
                Ok(c) => {
                    content = Some(c);
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        let content = content.ok_or_else(|| Error::RuleFileLoad {
            path: path.into(),
            source: last_error.unwrap(),
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

        Ok(Self {
            automaton,
            patterns,
        })
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
