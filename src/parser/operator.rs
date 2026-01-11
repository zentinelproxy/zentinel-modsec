//! Operator parsing for SecRule.

use crate::error::{Error, Result};

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl OperatorName {
    /// Parse an operator name from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "rx" => Some(Self::Rx),
            "pm" => Some(Self::Pm),
            "pmfromfile" => Some(Self::PmFromFile),
            "pmf" => Some(Self::Pmf),
            "streq" => Some(Self::StreQ),
            "contains" => Some(Self::Contains),
            "containsword" => Some(Self::ContainsWord),
            "beginswith" => Some(Self::BeginsWith),
            "endswith" => Some(Self::EndsWith),
            "within" => Some(Self::Within),
            "strmatch" => Some(Self::StrMatch),
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "gt" => Some(Self::Gt),
            "ge" => Some(Self::Ge),
            "lt" => Some(Self::Lt),
            "le" => Some(Self::Le),
            "detectsqli" => Some(Self::DetectSqli),
            "detectxss" => Some(Self::DetectXss),
            "validateurlencoding" => Some(Self::ValidateUrlEncoding),
            "validateutf8encoding" => Some(Self::ValidateUtf8Encoding),
            "validatebyterange" => Some(Self::ValidateByteRange),
            "validatehash" => Some(Self::ValidateHash),
            "validatedtd" => Some(Self::ValidateDtd),
            "validateschema" => Some(Self::ValidateSchema),
            "verifycc" => Some(Self::VerifyCc),
            "verifyssn" => Some(Self::VerifySsn),
            "verifycpf" => Some(Self::VerifyCpf),
            "ipmatch" => Some(Self::IpMatch),
            "ipmatchfromfile" => Some(Self::IpMatchFromFile),
            "ipmatchf" => Some(Self::IpMatchF),
            "rbl" => Some(Self::Rbl),
            "geolookup" => Some(Self::GeoLookup),
            "gsblookup" => Some(Self::GsbLookup),
            "inspectfile" => Some(Self::InspectFile),
            "fuzzyhash" => Some(Self::FuzzyHash),
            "nomatch" => Some(Self::NoMatch),
            "unconditionalmatch" => Some(Self::UnconditionalMatch),
            "rsub" => Some(Self::Rsub),
            _ => None,
        }
    }

    /// Check if this operator requires an argument.
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
pub fn parse_operator(input: &str) -> Result<OperatorSpec> {
    let input = input.trim();

    // Check for negation
    let (negated, input) = if input.starts_with('!') {
        (true, input[1..].trim_start())
    } else {
        (false, input)
    };

    // Check for @ prefix
    if input.starts_with('@') {
        // Find the operator name and argument
        let rest = &input[1..];

        // Find the end of the operator name (first space or end)
        let (name_str, argument) = if let Some(pos) = rest.find(|c: char| c.is_whitespace()) {
            let name = &rest[..pos];
            let arg = rest[pos..].trim().to_string();
            (name, arg)
        } else {
            (rest, String::new())
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
}
