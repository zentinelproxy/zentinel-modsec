//! Detection operators (@detectSQLi, @detectXSS).
//!
//! These use our pure Rust libinjection implementation.

use super::traits::{Operator, OperatorResult};
use crate::libinjection;

/// SQL injection detection operator (@detectSQLi).
pub struct DetectSqliOperator;

impl Operator for DetectSqliOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        let result = libinjection::sqli::detect_sqli(value);
        if result.is_injection {
            OperatorResult::matched(result.fingerprint.unwrap_or_default())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectSQLi"
    }
}

/// XSS detection operator (@detectXSS).
pub struct DetectXssOperator;

impl Operator for DetectXssOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        let result = libinjection::xss::detect_xss(value);
        if result.is_injection {
            OperatorResult::matched(result.fingerprint.unwrap_or_default())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectXSS"
    }
}
