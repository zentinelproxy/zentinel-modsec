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
        OperatorName::Eq => Ok(Arc::new(EqOperator::new(argument)?)),
        OperatorName::Gt => Ok(Arc::new(GtOperator::new(argument)?)),
        OperatorName::Lt => Ok(Arc::new(LtOperator::new(argument)?)),
        OperatorName::Ge => Ok(Arc::new(GeOperator::new(argument)?)),
        OperatorName::Le => Ok(Arc::new(LeOperator::new(argument)?)),
        OperatorName::DetectSqli => Ok(Arc::new(DetectSqliOperator)),
        OperatorName::DetectXss => Ok(Arc::new(DetectXssOperator)),
        OperatorName::ValidateUrlEncoding => Ok(Arc::new(ValidateUrlEncodingOperator)),
        OperatorName::ValidateUtf8Encoding => Ok(Arc::new(ValidateUtf8EncodingOperator)),
        OperatorName::IpMatch | OperatorName::IpMatchF => Ok(Arc::new(IpMatchOperator::new(argument)?)),
        OperatorName::IpMatchFromFile => Ok(Arc::new(IpMatchOperator::from_file(argument)?)),
        OperatorName::NoMatch => Ok(Arc::new(NoMatchOperator)),
        OperatorName::UnconditionalMatch => Ok(Arc::new(UnconditionalMatchOperator)),
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
