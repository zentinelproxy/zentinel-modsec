//! Operator implementations for ModSecurity.

mod traits;
mod pattern;
mod comparison;
mod detection;
mod validation;
mod network;

pub use traits::{Operator, OperatorResult};
pub use pattern::{RxOperator, PmOperator};
pub use comparison::{ContainsOperator, BeginsWithOperator, EndsWithOperator, StreqOperator};
pub use comparison::{EqOperator, GtOperator, LtOperator, GeOperator, LeOperator};
pub use detection::{DetectSqliOperator, DetectXssOperator};
pub use validation::{ValidateUrlEncodingOperator, ValidateUtf8EncodingOperator};
pub use network::IpMatchOperator;

use crate::parser::{OperatorName, OperatorSpec};
use crate::error::{Error, Result};
use std::sync::Arc;

/// Type alias for a compiled operator.
pub type CompiledOperator = dyn Operator;

/// Create an operator from a name and argument string.
/// This is a convenience function for testing and benchmarking.
pub fn create_operator(name: OperatorName, argument: &str) -> Result<Arc<dyn Operator>> {
    let spec = OperatorSpec {
        negated: false,
        name,
        argument: argument.to_string(),
    };
    compile_operator(&spec)
}

/// Create a compiled operator from a specification.
pub fn compile_operator(spec: &OperatorSpec) -> Result<Arc<dyn Operator>> {
    let name = &spec.name;
    let argument = &spec.argument;
    match name {
        OperatorName::Rx => Ok(Arc::new(RxOperator::new(argument)?)),
        OperatorName::Pm | OperatorName::Pmf => Ok(Arc::new(PmOperator::new(argument)?)),
        OperatorName::PmFromFile => Ok(Arc::new(PmOperator::from_file(argument)?)),
        OperatorName::Contains => Ok(Arc::new(ContainsOperator::new(argument))),
        OperatorName::BeginsWith => Ok(Arc::new(BeginsWithOperator::new(argument))),
        OperatorName::EndsWith => Ok(Arc::new(EndsWithOperator::new(argument))),
        OperatorName::StreQ => Ok(Arc::new(StreqOperator::new(argument))),
        OperatorName::Eq => Ok(Arc::new(EqOperator::new(argument))),
        OperatorName::Gt => Ok(Arc::new(GtOperator::new(argument))),
        OperatorName::Lt => Ok(Arc::new(LtOperator::new(argument))),
        OperatorName::Ge => Ok(Arc::new(GeOperator::new(argument))),
        OperatorName::Le => Ok(Arc::new(LeOperator::new(argument))),
        OperatorName::DetectSqli => Ok(Arc::new(DetectSqliOperator)),
        OperatorName::DetectXss => Ok(Arc::new(DetectXssOperator)),
        OperatorName::ValidateUrlEncoding => Ok(Arc::new(ValidateUrlEncodingOperator)),
        OperatorName::ValidateUtf8Encoding => Ok(Arc::new(ValidateUtf8EncodingOperator)),
        OperatorName::IpMatch | OperatorName::IpMatchF => Ok(Arc::new(IpMatchOperator::new(argument)?)),
        OperatorName::IpMatchFromFile => Ok(Arc::new(IpMatchOperator::from_file(argument)?)),
        OperatorName::NoMatch => Ok(Arc::new(NoMatchOperator)),
        OperatorName::UnconditionalMatch => Ok(Arc::new(UnconditionalMatchOperator)),
        OperatorName::ValidateByteRange => Ok(Arc::new(ValidateByteRangeOperator::new(argument))),
        // Placeholder operators - acknowledge but don't match
        OperatorName::VerifyCc | OperatorName::VerifySsn | OperatorName::VerifyCpf => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::ValidateHash | OperatorName::ValidateDtd | OperatorName::ValidateSchema => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::Rbl | OperatorName::GeoLookup | OperatorName::GsbLookup => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::InspectFile | OperatorName::FuzzyHash | OperatorName::Rsub => {
            Ok(Arc::new(NoMatchOperator))
        }
        OperatorName::ContainsWord => Ok(Arc::new(ContainsOperator::new(argument))),
        OperatorName::Within => Ok(Arc::new(WithinOperator::new(argument))),
        OperatorName::StrMatch => Ok(Arc::new(ContainsOperator::new(argument))),
        OperatorName::Ne => Ok(Arc::new(NeOperator::new(argument))),
        _ => Err(Error::UnknownOperator { name: format!("{:?}", name) }),
    }
}

/// Operator that never matches.
pub struct NoMatchOperator;

impl Operator for NoMatchOperator {
    fn execute(&self, _value: &str) -> OperatorResult {
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "noMatch"
    }
}

/// Operator that always matches.
pub struct UnconditionalMatchOperator;

impl Operator for UnconditionalMatchOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        OperatorResult::matched(value.to_string())
    }

    fn name(&self) -> &'static str {
        "unconditionalMatch"
    }
}

/// Validates that all bytes are within specified ranges.
pub struct ValidateByteRangeOperator {
    #[allow(dead_code)]
    ranges: Vec<(u8, u8)>,
}

impl ValidateByteRangeOperator {
    /// Create a new byte range validator.
    pub fn new(spec: &str) -> Self {
        // Parse ranges like "9,10,13,32-126"
        let mut ranges = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let parts: Vec<&str> = part.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse(), parts[1].parse()) {
                        ranges.push((start, end));
                    }
                }
            } else if let Ok(byte) = part.parse() {
                ranges.push((byte, byte));
            }
        }
        Self { ranges }
    }
}

impl Operator for ValidateByteRangeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        // Check if all bytes are within the allowed ranges
        for byte in value.bytes() {
            let valid = self.ranges.iter().any(|(start, end)| byte >= *start && byte <= *end);
            if !valid {
                // Invalid byte found - this is a match (rule should trigger)
                return OperatorResult::matched(format!("invalid byte: {}", byte));
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "validateByteRange"
    }
}

/// Within operator - checks if value is within a list of values.
pub struct WithinOperator {
    values: Vec<String>,
}

impl WithinOperator {
    /// Create a new within operator.
    pub fn new(values: &str) -> Self {
        Self {
            values: values.split_whitespace().map(|s| s.to_string()).collect(),
        }
    }
}

impl Operator for WithinOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if self.values.iter().any(|v| v == value) {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "within"
    }
}

/// Not equal operator.
pub struct NeOperator {
    expected: String,
}

impl NeOperator {
    /// Create a new not-equal operator.
    pub fn new(expected: &str) -> Self {
        Self {
            expected: expected.to_string(),
        }
    }
}

impl Operator for NeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        // Try numeric comparison first
        if let (Ok(a), Ok(b)) = (value.parse::<i64>(), self.expected.parse::<i64>()) {
            if a != b {
                return OperatorResult::matched(value.to_string());
            }
        } else if value != self.expected {
            // String comparison
            return OperatorResult::matched(value.to_string());
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "ne"
    }
}
