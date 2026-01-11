//! Operator parsing for SecRule.
//!
//! Optimized with perfect hash function for O(1) operator name lookup.

use crate::error::{Error, Result};
use phf::phf_map;

/// An operator specification in a SecRule.
#[derive(Debug, Clone)]
pub struct OperatorSpec {
    /// Whether the operator is negated (! prefix).
    pub negated: bool,
    /// The operator name.
    pub name: OperatorName,
    /// The operator argument.
    pub argument: String,
}

/// Operator names supported by ModSecurity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorName {
    // Pattern matching
    /// Regular expression match.
    Rx,
    /// Phrase match (Aho-Corasick).
    Pm,
    /// Phrase match from file.
    PmFromFile,
    /// Phrase match (alias).
    Pmf,

    // String comparison
    /// String equals.
    StreQ,
    /// Contains substring.
    Contains,
    /// Contains word.
    ContainsWord,
    /// Begins with.
    BeginsWith,
    /// Ends with.
    EndsWith,
    /// Within list.
    Within,
    /// String match (single pattern, case-insensitive).
    StrMatch,

    // Numeric comparison
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,

    // Detection
    /// Detect SQL injection.
    DetectSqli,
    /// Detect XSS.
    DetectXss,

    // Validation
    /// Validate URL encoding.
    ValidateUrlEncoding,
    /// Validate UTF-8 encoding.
    ValidateUtf8Encoding,
    /// Validate byte range.
    ValidateByteRange,
    /// Validate hash.
    ValidateHash,
    /// Validate DTD.
    ValidateDtd,
    /// Validate schema.
    ValidateSchema,

    // Verification
    /// Verify credit card.
    VerifyCc,
    /// Verify SSN.
    VerifySsn,
    /// Verify CPF (Brazilian ID).
    VerifyCpf,

    // Network
    /// IP address match.
    IpMatch,
    /// IP address match from file.
    IpMatchFromFile,
    /// IP address match (alias).
    IpMatchF,
    /// RBL lookup.
    Rbl,
    /// Geo lookup.
    GeoLookup,
    /// GSB lookup.
    GsbLookup,

    // File operations
    /// Inspect file.
    InspectFile,

    // Fuzzy matching
    /// Fuzzy hash.
    FuzzyHash,

    // Special
    /// No match (always false).
    NoMatch,
    /// Unconditional match (always true).
    UnconditionalMatch,
    /// Rsub (regex substitution).
    Rsub,
}

/// Perfect hash map for O(1) operator name lookup.
static OPERATOR_MAP: phf::Map<&'static str, OperatorName> = phf_map! {
    "rx" => OperatorName::Rx,
    "pm" => OperatorName::Pm,
    "pmfromfile" => OperatorName::PmFromFile,
    "pmf" => OperatorName::Pmf,
    "streq" => OperatorName::StreQ,
    "contains" => OperatorName::Contains,
    "containsword" => OperatorName::ContainsWord,
    "beginswith" => OperatorName::BeginsWith,
    "endswith" => OperatorName::EndsWith,
    "within" => OperatorName::Within,
    "strmatch" => OperatorName::StrMatch,
    "eq" => OperatorName::Eq,
    "ne" => OperatorName::Ne,
    "gt" => OperatorName::Gt,
    "ge" => OperatorName::Ge,
    "lt" => OperatorName::Lt,
    "le" => OperatorName::Le,
    "detectsqli" => OperatorName::DetectSqli,
    "detectxss" => OperatorName::DetectXss,
    "validateurlencoding" => OperatorName::ValidateUrlEncoding,
    "validateutf8encoding" => OperatorName::ValidateUtf8Encoding,
    "validatebyterange" => OperatorName::ValidateByteRange,
    "validatehash" => OperatorName::ValidateHash,
    "validatedtd" => OperatorName::ValidateDtd,
    "validateschema" => OperatorName::ValidateSchema,
    "verifycc" => OperatorName::VerifyCc,
    "verifyssn" => OperatorName::VerifySsn,
    "verifycpf" => OperatorName::VerifyCpf,
    "ipmatch" => OperatorName::IpMatch,
    "ipmatchfromfile" => OperatorName::IpMatchFromFile,
    "ipmatchf" => OperatorName::IpMatchF,
    "rbl" => OperatorName::Rbl,
    "geolookup" => OperatorName::GeoLookup,
    "gsblookup" => OperatorName::GsbLookup,
    "inspectfile" => OperatorName::InspectFile,
    "fuzzyhash" => OperatorName::FuzzyHash,
    "nomatch" => OperatorName::NoMatch,
    "unconditionalmatch" => OperatorName::UnconditionalMatch,
    "rsub" => OperatorName::Rsub,
};

impl OperatorName {
    /// Parse an operator name from a string (O(1) lookup).
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        // Fast path: check if already lowercase ASCII
        if s.bytes().all(|b| b.is_ascii_lowercase()) {
            return OPERATOR_MAP.get(s).copied();
        }
        // Slow path: need to lowercase
        let mut buf = [0u8; 32];
        let len = s.len().min(32);
        for (i, b) in s.bytes().take(len).enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        let lower = std::str::from_utf8(&buf[..len]).ok()?;
        OPERATOR_MAP.get(lower).copied()
    }

    /// Check if this operator requires an argument.
    #[inline]
    pub fn requires_argument(&self) -> bool {
        !matches!(
            self,
            Self::DetectSqli
                | Self::DetectXss
                | Self::ValidateUrlEncoding
                | Self::ValidateUtf8Encoding
                | Self::NoMatch
                | Self::UnconditionalMatch
                | Self::GeoLookup
        )
    }
}

/// Parse an operator specification from a string.
#[inline]
pub fn parse_operator(input: &str) -> Result<OperatorSpec> {
    let input = input.trim();
    let bytes = input.as_bytes();

    // Check for negation
    let (negated, input) = if bytes.first() == Some(&b'!') {
        (true, input[1..].trim_start())
    } else {
        (false, input)
    };

    // Check for @ prefix
    if input.starts_with('@') {
        // Find the operator name and argument
        let rest = &input[1..];

        // Find the end of the operator name (first space or end)
        let space_pos = rest.bytes().position(|b| b.is_ascii_whitespace());
        let (name_str, argument) = match space_pos {
            Some(pos) => (&rest[..pos], rest[pos..].trim_start().to_string()),
            None => (rest, String::new()),
        };

        let name = OperatorName::from_str(name_str).ok_or_else(|| Error::UnknownOperator {
            name: name_str.to_string(),
        })?;

        Ok(OperatorSpec {
            negated,
            name,
            argument,
        })
    } else {
        // Default to @rx (regex) operator
        Ok(OperatorSpec {
            negated,
            name: OperatorName::Rx,
            argument: input.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rx_operator() {
        let op = parse_operator("@rx ^admin").unwrap();
        assert_eq!(op.name, OperatorName::Rx);
        assert_eq!(op.argument, "^admin");
        assert!(!op.negated);
    }

    #[test]
    fn test_parse_implicit_rx() {
        let op = parse_operator("^admin").unwrap();
        assert_eq!(op.name, OperatorName::Rx);
        assert_eq!(op.argument, "^admin");
    }

    #[test]
    fn test_parse_negated_operator() {
        let op = parse_operator("!@rx ^admin").unwrap();
        assert_eq!(op.name, OperatorName::Rx);
        assert!(op.negated);
    }

    #[test]
    fn test_parse_contains() {
        let op = parse_operator("@contains /admin").unwrap();
        assert_eq!(op.name, OperatorName::Contains);
        assert_eq!(op.argument, "/admin");
    }

    #[test]
    fn test_parse_detectsqli() {
        let op = parse_operator("@detectSQLi").unwrap();
        assert_eq!(op.name, OperatorName::DetectSqli);
        assert!(op.argument.is_empty());
    }

    #[test]
    fn test_parse_pm() {
        let op = parse_operator("@pm admin root user").unwrap();
        assert_eq!(op.name, OperatorName::Pm);
        assert_eq!(op.argument, "admin root user");
    }

    #[test]
    fn test_operator_lookup_case_insensitive() {
        assert_eq!(OperatorName::from_str("rx"), Some(OperatorName::Rx));
        assert_eq!(OperatorName::from_str("RX"), Some(OperatorName::Rx));
        assert_eq!(OperatorName::from_str("Rx"), Some(OperatorName::Rx));
        assert_eq!(OperatorName::from_str("detectSQLi"), Some(OperatorName::DetectSqli));
        assert_eq!(OperatorName::from_str("DETECTSQLI"), Some(OperatorName::DetectSqli));
    }
}
