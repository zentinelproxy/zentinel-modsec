//! Comparison operators (@contains, @eq, @gt, etc.).

use super::traits::{Operator, OperatorResult};

/// Contains operator (@contains).
pub struct ContainsOperator {
    needle: String,
}

impl ContainsOperator {
    /// Create the operator from its SecLang argument.
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
    /// Create the operator from its SecLang argument.
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
    /// Create the operator from its SecLang argument.
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
    /// Create the operator from its SecLang argument.
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

/// The integer a numeric operator reads from an operand.
///
/// libmodsecurity converts both the input and the operator argument with
/// `atoll` (`operators/gt.cc`, `lt.cc`, `ge.cc`, `le.cc`) or with `stoi`,
/// taking 0 if it throws (`operators/eq.cc`): leading whitespace is skipped,
/// a sign belongs to the number, and conversion stops at the first byte that
/// is not a digit. So an empty or non-numeric operand is 0 and `7abc` is 7,
/// and the comparison always takes place.
///
/// A value outside the 64-bit range saturates, as glibc's `atoll` does. (For
/// `@eq` this is wider than `stoi`, which is 32-bit and gives 0 beyond that.)
fn leading_integer(operand: &str) -> i64 {
    let bytes = operand.as_bytes();
    // C's `isspace`: space, and `\t` `\n` `\v` `\f` `\r`.
    let mut rest = &bytes[bytes
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t'..=b'\r'))
        .count()..];
    let negative = rest.first() == Some(&b'-');
    if negative || rest.first() == Some(&b'+') {
        rest = &rest[1..];
    }
    // Accumulated on the negative side, which holds one more value.
    let mut value: i64 = 0;
    for digit in rest.iter().take_while(|b| b.is_ascii_digit()) {
        value = value
            .saturating_mul(10)
            .saturating_sub(i64::from(digit - b'0'));
    }
    if negative {
        value
    } else {
        value.checked_neg().unwrap_or(i64::MAX)
    }
}

/// Numeric equals operator (@eq).
pub struct EqOperator {
    target: i64,
}

impl EqOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            target: leading_integer(value),
        }
    }
}

impl Operator for EqOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if leading_integer(value) == self.target {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "eq"
    }
}

/// Greater than operator (@gt).
pub struct GtOperator {
    target: i64,
}

impl GtOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            target: leading_integer(value),
        }
    }
}

impl Operator for GtOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if leading_integer(value) > self.target {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "gt"
    }
}

/// Less than operator (@lt).
pub struct LtOperator {
    target: i64,
}

impl LtOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            target: leading_integer(value),
        }
    }
}

impl Operator for LtOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if leading_integer(value) < self.target {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "lt"
    }
}

/// Greater than or equal operator (@ge).
pub struct GeOperator {
    target: i64,
}

impl GeOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            target: leading_integer(value),
        }
    }
}

impl Operator for GeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if leading_integer(value) >= self.target {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "ge"
    }
}

/// Less than or equal operator (@le).
pub struct LeOperator {
    target: i64,
}

impl LeOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(value: &str) -> Self {
        Self {
            target: leading_integer(value),
        }
    }
}

impl Operator for LeOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if leading_integer(value) <= self.target {
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
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
        let eq = EqOperator::new("10");
        assert!(eq.execute("10").matched);
        assert!(!eq.execute("11").matched);

        let gt = GtOperator::new("10");
        assert!(gt.execute("11").matched);
        assert!(!gt.execute("10").matched);

        let lt = LtOperator::new("10");
        assert!(lt.execute("9").matched);
        assert!(!lt.execute("10").matched);
    }
}
