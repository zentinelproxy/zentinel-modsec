//! Pure Rust implementation of libinjection for SQLi and XSS detection.
//!
//! This module provides SQL injection and XSS detection using fingerprint-based
//! analysis, similar to the original libinjection library.

pub mod sqli;
pub mod xss;

pub use sqli::{is_sqli, sqli_fingerprint};
pub use xss::is_xss;

/// Result of injection detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether injection was detected.
    pub is_injection: bool,
    /// Fingerprint that matched (if any).
    pub fingerprint: Option<String>,
}

impl DetectionResult {
    /// Create a positive detection result.
    pub fn detected(fingerprint: String) -> Self {
        Self {
            is_injection: true,
            fingerprint: Some(fingerprint),
        }
    }

    /// Create a negative detection result.
    pub fn safe() -> Self {
        Self {
            is_injection: false,
            fingerprint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("1; DROP TABLE users--"));
        assert!(is_sqli("admin'--"));
        assert!(is_sqli("1 UNION SELECT * FROM users"));
        assert!(!is_sqli("hello world"));
        assert!(!is_sqli("normal query string"));
    }

    #[test]
    fn test_xss_detection() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("javascript:alert(1)"));
        assert!(is_xss("<img src=x onerror=alert(1)>"));
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(!is_xss("hello world"));
        assert!(!is_xss("<p>Normal paragraph</p>"));
    }
}
