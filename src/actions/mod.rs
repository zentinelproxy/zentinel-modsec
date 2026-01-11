//! Action system for ModSecurity rule execution.

mod disruptive;
mod flow;
mod data;
mod metadata;

pub use disruptive::*;
pub use flow::*;
pub use data::*;
pub use metadata::*;

use crate::parser::{Action, DisruptiveAction, FlowAction, DataAction, MetadataAction, LoggingAction, SetVarValue};

/// Result of action execution.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Whether to stop processing (disruptive action taken).
    pub disruptive: Option<DisruptiveOutcome>,
    /// Flow control modifications.
    pub flow: FlowOutcome,
    /// Variables to set.
    pub setvar_ops: Vec<SetVarOp>,
    /// Captures from regex.
    pub captures: Vec<String>,
    /// Metadata collected.
    pub metadata: RuleMetadata,
}

impl Default for ActionResult {
    fn default() -> Self {
        Self {
            disruptive: None,
            flow: FlowOutcome::Continue,
            setvar_ops: Vec::new(),
            captures: Vec::new(),
            metadata: RuleMetadata::default(),
        }
    }
}

/// Outcome of a disruptive action.
#[derive(Debug, Clone)]
pub enum DisruptiveOutcome {
    /// Deny the request with status code.
    Deny(u16),
    /// Block (defer to SecRuleEngine).
    Block,
    /// Allow the request.
    Allow,
    /// Redirect to URL.
    Redirect(String),
    /// Pass (continue but mark as matched).
    Pass,
    /// Drop the connection.
    Drop,
}

/// Flow control outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowOutcome {
    /// Continue normal processing.
    Continue,
    /// Chain to next rule.
    Chain,
    /// Skip N rules.
    Skip(u32),
    /// Skip to marker.
    SkipAfter(String),
}

/// Variable set operation.
#[derive(Debug, Clone)]
pub struct SetVarOp {
    /// Collection name (usually "TX").
    pub collection: String,
    /// Variable name.
    pub name: String,
    /// Operation to perform.
    pub operation: SetVarOperation,
}

/// Type of setvar operation.
#[derive(Debug, Clone)]
pub enum SetVarOperation {
    /// Set to value.
    Set(String),
    /// Increment by value.
    Increment(i64),
    /// Decrement by value.
    Decrement(i64),
    /// Delete the variable.
    Delete,
}

/// Metadata from a rule.
#[derive(Debug, Clone, Default)]
pub struct RuleMetadata {
    /// Rule ID.
    pub id: Option<String>,
    /// Rule message.
    pub msg: Option<String>,
    /// Log message.
    pub logdata: Option<String>,
    /// Severity (0-7).
    pub severity: Option<u8>,
    /// Tags.
    pub tags: Vec<String>,
    /// Maturity level.
    pub maturity: Option<u8>,
    /// Accuracy level.
    pub accuracy: Option<u8>,
    /// Revision.
    pub rev: Option<String>,
    /// Version.
    pub ver: Option<String>,
}

/// Execute actions and collect results.
pub fn execute_actions(
    actions: &[Action],
    matched_value: Option<&str>,
    captures: &[String],
) -> ActionResult {
    let mut result = ActionResult::default();
    result.captures = captures.to_vec();

    for action in actions {
        match action {
            Action::Disruptive(d) => {
                result.disruptive = Some(execute_disruptive(d));
            }
            Action::Flow(f) => {
                result.flow = execute_flow(f);
            }
            Action::Data(d) => {
                execute_data(d, &mut result, matched_value);
            }
            Action::Metadata(m) => {
                execute_metadata(m, &mut result.metadata);
            }
            Action::Logging(l) => {
                execute_logging(l, &mut result.metadata);
            }
            Action::Control(_) => {
                // Control actions (ctl:) modify engine behavior, handled elsewhere
            }
            Action::Transformation(_) => {
                // Transformations are applied during variable resolution, not execution
            }
        }
    }

    result
}

/// Execute a disruptive action.
fn execute_disruptive(action: &DisruptiveAction) -> DisruptiveOutcome {
    match action {
        DisruptiveAction::Deny => DisruptiveOutcome::Deny(403),
        DisruptiveAction::Block => DisruptiveOutcome::Block,
        DisruptiveAction::Allow | DisruptiveAction::AllowPhase | DisruptiveAction::AllowRequest => {
            DisruptiveOutcome::Allow
        }
        DisruptiveAction::Pass => DisruptiveOutcome::Pass,
        DisruptiveAction::Drop => DisruptiveOutcome::Drop,
        DisruptiveAction::Redirect(url) => DisruptiveOutcome::Redirect(url.clone()),
    }
}

/// Execute a flow action.
fn execute_flow(action: &FlowAction) -> FlowOutcome {
    match action {
        FlowAction::Chain => FlowOutcome::Chain,
        FlowAction::Skip(n) => FlowOutcome::Skip(*n),
        FlowAction::SkipAfter(marker) => FlowOutcome::SkipAfter(marker.clone()),
    }
}

/// Execute a data action.
fn execute_data(action: &DataAction, result: &mut ActionResult, _matched_value: Option<&str>) {
    match action {
        DataAction::Capture => {
            // Captures are already populated from regex match
        }
        DataAction::SetVar(spec) => {
            let op = match &spec.value {
                SetVarValue::String(v) => SetVarOperation::Set(v.clone()),
                SetVarValue::Int(v) => SetVarOperation::Set(v.to_string()),
                SetVarValue::Increment(v) => SetVarOperation::Increment(*v),
                SetVarValue::Decrement(v) => SetVarOperation::Decrement(*v),
                SetVarValue::Delete => SetVarOperation::Delete,
            };
            result.setvar_ops.push(SetVarOp {
                collection: spec.collection.clone(),
                name: spec.key.clone(),
                operation: op,
            });
        }
        DataAction::InitCol { .. } => {
            // Collection initialization not implemented yet
        }
        DataAction::SetUid(_) => {
            // User ID setting not implemented yet
        }
        DataAction::SetSid(_) => {
            // Session ID setting not implemented yet
        }
        DataAction::ExpireVar { .. } => {
            // Variable expiration not implemented yet
        }
        DataAction::DeprecateVar(_) => {
            // Variable deprecation not implemented yet
        }
        DataAction::Exec(_) => {
            // Script execution not implemented
        }
        DataAction::Prepend(_) | DataAction::Append(_) => {
            // Response body modification not implemented
        }
    }
}

/// Execute a metadata action.
fn execute_metadata(action: &MetadataAction, metadata: &mut RuleMetadata) {
    match action {
        MetadataAction::Id(id) => {
            metadata.id = Some(id.to_string());
        }
        MetadataAction::Phase(_) => {
            // Phase is handled at rule level
        }
        MetadataAction::Msg(msg) => {
            metadata.msg = Some(msg.clone());
        }
        MetadataAction::Severity(sev) => {
            metadata.severity = Some(*sev);
        }
        MetadataAction::Tag(tag) => {
            metadata.tags.push(tag.clone());
        }
        MetadataAction::Maturity(m) => {
            metadata.maturity = Some(*m);
        }
        MetadataAction::Accuracy(a) => {
            metadata.accuracy = Some(*a);
        }
        MetadataAction::Rev(rev) => {
            metadata.rev = Some(rev.clone());
        }
        MetadataAction::Ver(ver) => {
            metadata.ver = Some(ver.clone());
        }
        MetadataAction::LogData(data) => {
            metadata.logdata = Some(data.clone());
        }
        MetadataAction::Status(_) => {
            // Status is handled at disruptive action level
        }
    }
}

/// Execute a logging action.
fn execute_logging(action: &LoggingAction, _metadata: &mut RuleMetadata) {
    match action {
        LoggingAction::Log | LoggingAction::NoLog | LoggingAction::AuditLog | LoggingAction::NoAuditLog => {
            // Logging flags handled elsewhere
        }
        LoggingAction::SanitiseMatched | LoggingAction::SanitizeMatched => {
            // Sanitization not implemented yet
        }
        LoggingAction::SanitiseArg(_)
        | LoggingAction::SanitiseRequestHeader(_)
        | LoggingAction::SanitiseResponseHeader(_) => {
            // Sanitization not implemented yet
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Action, DisruptiveAction, MetadataAction};

    #[test]
    fn test_execute_deny() {
        let actions = vec![Action::Disruptive(DisruptiveAction::Deny)];
        let result = execute_actions(&actions, None, &[]);
        assert!(matches!(result.disruptive, Some(DisruptiveOutcome::Deny(403))));
    }

    #[test]
    fn test_execute_metadata() {
        let actions = vec![
            Action::Metadata(MetadataAction::Id(12345)),
            Action::Metadata(MetadataAction::Msg("Test rule".to_string())),
            Action::Metadata(MetadataAction::Severity(2)),
            Action::Metadata(MetadataAction::Tag("attack-sqli".to_string())),
        ];
        let result = execute_actions(&actions, None, &[]);
        assert_eq!(result.metadata.id, Some("12345".to_string()));
        assert_eq!(result.metadata.msg, Some("Test rule".to_string()));
        assert_eq!(result.metadata.severity, Some(2));
        assert_eq!(result.metadata.tags, vec!["attack-sqli".to_string()]);
    }
}
