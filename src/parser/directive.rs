//! Directive types for ModSecurity configuration.

use super::{Action, OperatorSpec, VariableSpec};
use crate::error::SourceLocation;
use std::path::PathBuf;

/// A parsed ModSecurity directive.
#[derive(Debug, Clone)]
pub enum Directive {
    /// SecRule directive - the main rule type.
    SecRule(SecRule),
    /// SecAction directive - actions without matching.
    SecAction(SecAction),
    /// SecMarker directive - named marker for skipAfter.
    SecMarker(SecMarker),
    /// SecRuleEngine directive - enable/disable rules.
    SecRuleEngine(RuleEngineMode),
    /// SecDefaultAction directive - default actions for rules.
    SecDefaultAction(Vec<Action>),
    /// SecRuleRemoveById directive - remove rules by ID.
    SecRuleRemoveById(Vec<u64>),
    /// SecRuleUpdateActionById directive - update rule actions.
    SecRuleUpdateActionById { id: u64, actions: Vec<Action> },
    /// SecRequestBodyAccess directive.
    SecRequestBodyAccess(bool),
    /// SecResponseBodyAccess directive.
    SecResponseBodyAccess(bool),
    /// SecRequestBodyLimit directive.
    SecRequestBodyLimit(usize),
    /// SecResponseBodyLimit directive.
    SecResponseBodyLimit(usize),
    /// Include directive - include another file.
    Include(PathBuf),
    /// Unknown directive (logged and skipped).
    Unknown(String),
}

/// A SecRule directive.
#[derive(Debug, Clone)]
pub struct SecRule {
    /// Variables to inspect.
    pub variables: Vec<VariableSpec>,
    /// Operator to apply.
    pub operator: OperatorSpec,
    /// Actions to execute on match.
    pub actions: Vec<Action>,
    /// Source location for error reporting.
    pub location: SourceLocation,
}

/// A SecAction directive.
#[derive(Debug, Clone)]
pub struct SecAction {
    /// Actions to execute.
    pub actions: Vec<Action>,
    /// Source location for error reporting.
    pub location: SourceLocation,
}

/// A SecMarker directive.
#[derive(Debug, Clone)]
pub struct SecMarker {
    /// Marker name.
    pub name: String,
}

/// Rule engine mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngineMode {
    /// Rules are enabled and will block.
    On,
    /// Rules are disabled.
    Off,
    /// Rules are enabled but will only log, not block.
    DetectionOnly,
}

impl Default for RuleEngineMode {
    fn default() -> Self {
        Self::Off
    }
}

impl SecRule {
    /// Check if this rule has the chain action.
    pub fn is_chained(&self) -> bool {
        self.actions.iter().any(|a| matches!(a, Action::Flow(super::FlowAction::Chain)))
    }

    /// Get the rule ID if present.
    pub fn id(&self) -> Option<u64> {
        for action in &self.actions {
            if let Action::Metadata(super::MetadataAction::Id(id)) = action {
                return Some(*id);
            }
        }
        None
    }

    /// Get the phase for this rule (defaults to 2).
    pub fn phase(&self) -> u8 {
        for action in &self.actions {
            if let Action::Metadata(super::MetadataAction::Phase(phase)) = action {
                return *phase;
            }
        }
        2 // Default phase is 2 (request body)
    }
}
