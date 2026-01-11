//! Transaction engine for ModSecurity rule processing.

pub mod chain;
pub mod intervention;
pub mod phase;
pub mod ruleset;
pub mod scoring;
pub mod transaction;

pub use intervention::Intervention;
pub use ruleset::{CompiledRuleset, Rules};
pub use transaction::Transaction;

use crate::error::Result;
use std::sync::Arc;

/// Main ModSecurity engine.
pub struct ModSecurity {
    /// Compiled ruleset.
    ruleset: Arc<CompiledRuleset>,
    /// Default block status code.
    default_status: u16,
}

impl ModSecurity {
    /// Create a new ModSecurity instance with the given ruleset.
    pub fn new(ruleset: CompiledRuleset) -> Self {
        Self {
            ruleset: Arc::new(ruleset),
            default_status: 403,
        }
    }

    /// Load rules from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let ruleset = CompiledRuleset::from_file(path)?;
        Ok(Self::new(ruleset))
    }

    /// Load rules from a string.
    pub fn from_string(rules: &str) -> Result<Self> {
        let ruleset = CompiledRuleset::from_string(rules)?;
        Ok(Self::new(ruleset))
    }

    /// Set the default block status code.
    pub fn set_default_status(&mut self, status: u16) {
        self.default_status = status;
    }

    /// Create a new transaction for processing a request.
    pub fn new_transaction(&self) -> Transaction {
        Transaction::new(Arc::clone(&self.ruleset), self.default_status)
    }

    /// Get the ruleset.
    pub fn ruleset(&self) -> &CompiledRuleset {
        &self.ruleset
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_count()
    }
}

impl std::fmt::Debug for ModSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModSecurity")
            .field("rule_count", &self.ruleset.rule_count())
            .field("default_status", &self.default_status)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modsec_from_string() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let modsec = ModSecurity::from_string(rules).unwrap();
        assert_eq!(modsec.rule_count(), 1);
    }

    #[test]
    fn test_new_transaction() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let modsec = ModSecurity::from_string(rules).unwrap();
        let _tx = modsec.new_transaction();
    }
}
