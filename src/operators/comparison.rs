//! Comparison operators (@contains, @eq, @gt, etc.).

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};

/// Contains operator (@contains).
pub struct ContainsOperator {
    needle: String,
}

impl ContainsOperator {
    pub fn new(needle: &str) -> Self {
        Self {
            needle: needle.to_string(),
        }
    }
}

impl Operator for ContainsOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if value.contains(&self.needle) {
            OperatorResult::matched(self.needle.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "contains"
    }
}

/// BeginsWith operator (@beginsWith).
pub struct BeginsWithOperator {
    prefix: String,
}

impl BeginsWithOperator {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }
}

impl Operator for BeginsWithOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if value.starts_with(&self.prefix) {
            OperatorResult::matched(self.prefix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "beginsWith"
    }
}

/// EndsWith operator (@endsWith).
pub struct EndsWithOperator {
    suffix: String,
}

impl EndsWithOperator {
    pub fn new(suffix: &str) -> Self {
        Self {
            suffix: suffix.to_string(),
        }
    }
}

impl Operator for EndsWithOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if value.ends_with(&self.suffix) {
            OperatorResult::matched(self.suffix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "endsWith"
    }
}

/// String equals operator (@streq).
pub struct StreqOperator {
    expected: String,
}

impl StreqOperator {
    pub fn new(expected: &str) -> Self {
        Self {
            expected: expected.to_string(),
        }
    }
}

impl Operator for StreqOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if value == self.expected {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "streq"
    }
}

/// Numeric equals operator (@eq).
pub struct EqOperator {
    value: i64,
}

impl EqOperator {
    pub fn new(value: &str) -> Result<Self> {
        let v = value.parse().map_err(|_| Error::InvalidActionArgument {
            action: "eq".to_string(),
            message: format!("invalid number: {}", value),
        })?;
        Ok(Self { value: v })
    }
}

impl Operator for EqOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(n) = value.parse::<i64>() {
            if n == self.value {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "eq"
    }
}

/// Greater than operator (@gt).
pub struct GtOperator {
    value: i64,
}

impl GtOperator {
    pub fn new(value: &str) -> Result<Self> {
        let v = value.parse().map_err(|_| Error::InvalidActionArgument {
            action: "gt".to_string(),
            message: format!("invalid number: {}", value),
        })?;
        Ok(Self { value: v })
    }
}

impl Operator for GtOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(n) = value.parse::<i64>() {
            if n > self.value {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "gt"
    }
}

/// Less than operator (@lt).
pub struct LtOperator {
    value: i64,
}

impl LtOperator {
    pub fn new(value: &str) -> Result<Self> {
        let v = value.parse().map_err(|_| Error::InvalidActionArgument {
            action: "lt".to_string(),
            message: format!("invalid number: {}", value),
        })?;
        Ok(Self { value: v })
    }
}

impl Operator for LtOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(n) = value.parse::<i64>() {
            if n < self.value {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "lt"
    }
}

/// Greater than or equal operator (@ge).
pub struct GeOperator {
    value: i64,
}

impl GeOperator {
    pub fn new(value: &str) -> Result<Self> {
        let v = value.parse().map_err(|_| Error::InvalidActionArgument {
            action: "ge".to_string(),
            message: format!("invalid number: {}", value),
        })?;
        Ok(Self { value: v })
    }
}

impl Operator for GeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(n) = value.parse::<i64>() {
            if n >= self.value {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "ge"
    }
}

/// Less than or equal operator (@le).
pub struct LeOperator {
    value: i64,
}

impl LeOperator {
    pub fn new(value: &str) -> Result<Self> {
        let v = value.parse().map_err(|_| Error::InvalidActionArgument {
            action: "le".to_string(),
            message: format!("invalid number: {}", value),
        })?;
        Ok(Self { value: v })
    }
}

impl Operator for LeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(n) = value.parse::<i64>() {
            if n <= self.value {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "le"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let op = ContainsOperator::new("admin");
        assert!(op.execute("/admin/users").matched);
        assert!(!op.execute("/users").matched);
    }

    #[test]
    fn test_begins_with() {
        let op = BeginsWithOperator::new("/admin");
        assert!(op.execute("/admin/users").matched);
        assert!(!op.execute("/users/admin").matched);
    }

    #[test]
    fn test_ends_with() {
        let op = EndsWithOperator::new(".php");
        assert!(op.execute("index.php").matched);
        assert!(!op.execute("index.html").matched);
    }

    #[test]
    fn test_streq() {
        let op = StreqOperator::new("admin");
        assert!(op.execute("admin").matched);
        assert!(!op.execute("Admin").matched);
    }

    #[test]
    fn test_numeric_operators() {
        let eq = EqOperator::new("10").unwrap();
        assert!(eq.execute("10").matched);
        assert!(!eq.execute("11").matched);

        let gt = GtOperator::new("10").unwrap();
        assert!(gt.execute("11").matched);
        assert!(!gt.execute("10").matched);

        let lt = LtOperator::new("10").unwrap();
        assert!(lt.execute("9").matched);
        assert!(!lt.execute("10").matched);
    }
}
