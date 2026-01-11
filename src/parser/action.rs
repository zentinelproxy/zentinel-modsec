//! Action parsing for SecRule.

use crate::error::{Error, Result};

/// An action in a SecRule.
#[derive(Debug, Clone)]
pub enum Action {
    /// Disruptive action (deny, block, pass, allow, redirect, drop).
    Disruptive(DisruptiveAction),
    /// Flow control action (chain, skip, skipAfter).
    Flow(FlowAction),
    /// Metadata action (id, phase, severity, msg, tag, etc.).
    Metadata(MetadataAction),
    /// Data action (setvar, capture, etc.).
    Data(DataAction),
    /// Logging action (log, nolog, auditlog, etc.).
    Logging(LoggingAction),
    /// Control action (ctl).
    Control(ControlAction),
    /// Transformation (t:xxx).
    Transformation(String),
}

/// Disruptive actions.
#[derive(Debug, Clone)]
pub enum DisruptiveAction {
    /// Deny the request (return status).
    Deny,
    /// Block the request.
    Block,
    /// Pass (continue processing).
    Pass,
    /// Allow (stop processing, allow request).
    Allow,
    /// Allow current phase.
    AllowPhase,
    /// Allow current request.
    AllowRequest,
    /// Redirect to URL.
    Redirect(String),
    /// Drop connection.
    Drop,
}

/// Flow control actions.
#[derive(Debug, Clone)]
pub enum FlowAction {
    /// Chain to next rule.
    Chain,
    /// Skip N rules.
    Skip(u32),
    /// Skip to marker.
    SkipAfter(String),
}

/// Metadata actions.
#[derive(Debug, Clone)]
pub enum MetadataAction {
    /// Rule ID.
    Id(u64),
    /// Processing phase.
    Phase(u8),
    /// Severity level.
    Severity(u8),
    /// Message.
    Msg(String),
    /// Tag.
    Tag(String),
    /// Revision.
    Rev(String),
    /// Version.
    Ver(String),
    /// Maturity level.
    Maturity(u8),
    /// Accuracy level.
    Accuracy(u8),
    /// Log data.
    LogData(String),
    /// HTTP status code.
    Status(u16),
}

/// Data actions.
#[derive(Debug, Clone)]
pub enum DataAction {
    /// Set variable.
    SetVar(SetVarSpec),
    /// Capture regex groups.
    Capture,
    /// Initialize collection.
    InitCol { collection: String, key: String },
    /// Set UID.
    SetUid(String),
    /// Set SID.
    SetSid(String),
    /// Expire variable.
    ExpireVar { var: String, seconds: u64 },
    /// Deprecate variable.
    DeprecateVar(String),
    /// Execute script.
    Exec(String),
    /// Prepend response body.
    Prepend(String),
    /// Append response body.
    Append(String),
}

/// SetVar specification.
#[derive(Debug, Clone)]
pub struct SetVarSpec {
    /// Collection name (e.g., "tx").
    pub collection: String,
    /// Variable key.
    pub key: String,
    /// Value to set.
    pub value: SetVarValue,
}

/// SetVar value types.
#[derive(Debug, Clone)]
pub enum SetVarValue {
    /// Set to string value.
    String(String),
    /// Set to integer value.
    Int(i64),
    /// Increment by amount.
    Increment(i64),
    /// Decrement by amount.
    Decrement(i64),
    /// Delete variable.
    Delete,
}

/// Logging actions.
#[derive(Debug, Clone)]
pub enum LoggingAction {
    /// Enable logging.
    Log,
    /// Disable logging.
    NoLog,
    /// Enable audit logging.
    AuditLog,
    /// Disable audit logging.
    NoAuditLog,
    /// Sanitize matched variables.
    SanitiseMatched,
    /// Sanitize matched variables (alias).
    SanitizeMatched,
    /// Sanitize argument.
    SanitiseArg(String),
    /// Sanitize request header.
    SanitiseRequestHeader(String),
    /// Sanitize response header.
    SanitiseResponseHeader(String),
}

/// Control actions.
#[derive(Debug, Clone)]
pub struct ControlAction {
    /// Control directive.
    pub directive: String,
    /// Control value.
    pub value: String,
}

/// Parse an action list from a string.
pub fn parse_actions(input: &str) -> Result<Vec<Action>> {
    let mut actions = Vec::new();
    let mut chars = input.chars().peekable();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '"';
    let mut paren_depth: u32 = 0;

    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = c;
                current.push(c);
            }
            c if in_quotes && c == quote_char => {
                in_quotes = false;
                current.push(c);
            }
            '(' if !in_quotes => {
                paren_depth += 1;
                current.push(c);
            }
            ')' if !in_quotes => {
                paren_depth = paren_depth.saturating_sub(1);
                current.push(c);
            }
            ',' if !in_quotes && paren_depth == 0 => {
                if !current.trim().is_empty() {
                    actions.push(parse_single_action(current.trim())?);
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    // Don't forget the last action
    if !current.trim().is_empty() {
        actions.push(parse_single_action(current.trim())?);
    }

    Ok(actions)
}

/// Parse a single action.
fn parse_single_action(input: &str) -> Result<Action> {
    let input = input.trim();

    // Check for transformation (t:xxx)
    if input.starts_with("t:") {
        return Ok(Action::Transformation(input[2..].to_string()));
    }

    // Split on : for actions with arguments
    let (name, argument) = if let Some(pos) = input.find(':') {
        let name = &input[..pos];
        let arg = &input[pos + 1..];
        (name.to_lowercase(), Some(arg.to_string()))
    } else {
        (input.to_lowercase(), None)
    };

    match name.as_str() {
        // Disruptive actions
        "deny" => Ok(Action::Disruptive(DisruptiveAction::Deny)),
        "block" => Ok(Action::Disruptive(DisruptiveAction::Block)),
        "pass" => Ok(Action::Disruptive(DisruptiveAction::Pass)),
        "allow" => Ok(Action::Disruptive(DisruptiveAction::Allow)),
        "drop" => Ok(Action::Disruptive(DisruptiveAction::Drop)),
        "redirect" => {
            let url = argument.ok_or_else(|| Error::InvalidActionArgument {
                action: "redirect".to_string(),
                message: "missing URL".to_string(),
            })?;
            Ok(Action::Disruptive(DisruptiveAction::Redirect(url)))
        }

        // Flow actions
        "chain" => Ok(Action::Flow(FlowAction::Chain)),
        "skip" => {
            let count: u32 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "skip".to_string(),
                    message: "invalid count".to_string(),
                })?;
            Ok(Action::Flow(FlowAction::Skip(count)))
        }
        "skipafter" => {
            let marker = argument.ok_or_else(|| Error::InvalidActionArgument {
                action: "skipAfter".to_string(),
                message: "missing marker name".to_string(),
            })?;
            Ok(Action::Flow(FlowAction::SkipAfter(marker)))
        }

        // Metadata actions
        "id" => {
            let id: u64 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "id".to_string(),
                    message: "invalid ID".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Id(id)))
        }
        "phase" => {
            let phase: u8 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "phase".to_string(),
                    message: "invalid phase".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Phase(phase)))
        }
        "severity" => {
            let sev: u8 = argument
                .as_ref()
                .and_then(|s| parse_severity(s))
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "severity".to_string(),
                    message: "invalid severity".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Severity(sev)))
        }
        "msg" => {
            let msg = argument.unwrap_or_default();
            // Remove surrounding quotes if present
            let msg = msg.trim_matches(|c| c == '\'' || c == '"');
            Ok(Action::Metadata(MetadataAction::Msg(msg.to_string())))
        }
        "tag" => {
            let tag = argument.unwrap_or_default();
            let tag = tag.trim_matches(|c| c == '\'' || c == '"');
            Ok(Action::Metadata(MetadataAction::Tag(tag.to_string())))
        }
        "rev" => {
            let rev = argument.unwrap_or_default();
            let rev = rev.trim_matches(|c| c == '\'' || c == '"');
            Ok(Action::Metadata(MetadataAction::Rev(rev.to_string())))
        }
        "ver" => {
            let ver = argument.unwrap_or_default();
            let ver = ver.trim_matches(|c| c == '\'' || c == '"');
            Ok(Action::Metadata(MetadataAction::Ver(ver.to_string())))
        }
        "maturity" => {
            let mat: u8 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "maturity".to_string(),
                    message: "invalid maturity".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Maturity(mat)))
        }
        "accuracy" => {
            let acc: u8 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "accuracy".to_string(),
                    message: "invalid accuracy".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Accuracy(acc)))
        }
        "logdata" => {
            let data = argument.unwrap_or_default();
            let data = data.trim_matches(|c| c == '\'' || c == '"');
            Ok(Action::Metadata(MetadataAction::LogData(data.to_string())))
        }
        "status" => {
            let status: u16 = argument
                .as_ref()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::InvalidActionArgument {
                    action: "status".to_string(),
                    message: "invalid status code".to_string(),
                })?;
            Ok(Action::Metadata(MetadataAction::Status(status)))
        }

        // Data actions
        "setvar" => {
            let spec = argument.ok_or_else(|| Error::InvalidActionArgument {
                action: "setvar".to_string(),
                message: "missing variable specification".to_string(),
            })?;
            let setvar = parse_setvar(&spec)?;
            Ok(Action::Data(DataAction::SetVar(setvar)))
        }
        "capture" => Ok(Action::Data(DataAction::Capture)),

        // Logging actions
        "log" => Ok(Action::Logging(LoggingAction::Log)),
        "nolog" => Ok(Action::Logging(LoggingAction::NoLog)),
        "auditlog" => Ok(Action::Logging(LoggingAction::AuditLog)),
        "noauditlog" => Ok(Action::Logging(LoggingAction::NoAuditLog)),
        "sanitisematched" | "sanitizematched" => Ok(Action::Logging(LoggingAction::SanitiseMatched)),

        // Control actions
        "ctl" => {
            let spec = argument.ok_or_else(|| Error::InvalidActionArgument {
                action: "ctl".to_string(),
                message: "missing control specification".to_string(),
            })?;
            let (directive, value) = if let Some(pos) = spec.find('=') {
                (spec[..pos].to_string(), spec[pos + 1..].to_string())
            } else {
                (spec, String::new())
            };
            Ok(Action::Control(ControlAction { directive, value }))
        }

        _ => Err(Error::UnknownAction {
            name: name.to_string(),
        }),
    }
}

/// Parse a setvar specification.
fn parse_setvar(input: &str) -> Result<SetVarSpec> {
    let input = input.trim();

    // Check for delete (!var)
    if input.starts_with('!') {
        let var = &input[1..];
        let (collection, key) = parse_var_name(var)?;
        return Ok(SetVarSpec {
            collection,
            key,
            value: SetVarValue::Delete,
        });
    }

    // Split on = for assignment
    let (var, value_str) = if let Some(pos) = input.find('=') {
        (&input[..pos], Some(&input[pos + 1..]))
    } else {
        (input, None)
    };

    let (collection, key) = parse_var_name(var)?;

    let value = if let Some(val) = value_str {
        if val.starts_with('+') {
            // Increment
            let amount: i64 = val[1..].parse().unwrap_or(1);
            SetVarValue::Increment(amount)
        } else if val.starts_with('-') {
            // Decrement
            let amount: i64 = val[1..].parse().unwrap_or(1);
            SetVarValue::Decrement(amount)
        } else if let Ok(n) = val.parse::<i64>() {
            SetVarValue::Int(n)
        } else {
            SetVarValue::String(val.to_string())
        }
    } else {
        SetVarValue::String("1".to_string())
    };

    Ok(SetVarSpec {
        collection,
        key,
        value,
    })
}

/// Parse a variable name into collection and key.
fn parse_var_name(input: &str) -> Result<(String, String)> {
    if let Some(pos) = input.find('.') {
        Ok((input[..pos].to_lowercase(), input[pos + 1..].to_string()))
    } else {
        // Default to tx collection
        Ok(("tx".to_string(), input.to_string()))
    }
}

/// Parse severity from string or number.
fn parse_severity(s: &str) -> Option<u8> {
    // Try numeric first
    if let Ok(n) = s.parse::<u8>() {
        return Some(n);
    }

    // Try named severities
    match s.to_lowercase().as_str() {
        "emergency" => Some(0),
        "alert" => Some(1),
        "critical" => Some(2),
        "error" => Some(3),
        "warning" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_actions() {
        let actions = parse_actions("id:1,deny,status:403").unwrap();
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn test_parse_action_with_msg() {
        let actions = parse_actions("id:1,msg:'Hello world',deny").unwrap();
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn test_parse_setvar() {
        let actions = parse_actions("setvar:tx.score=+5").unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Data(DataAction::SetVar(spec)) => {
                assert_eq!(spec.collection, "tx");
                assert_eq!(spec.key, "score");
                assert!(matches!(spec.value, SetVarValue::Increment(5)));
            }
            _ => panic!("expected SetVar"),
        }
    }

    #[test]
    fn test_parse_chain() {
        let actions = parse_actions("id:1,phase:2,chain").unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::Flow(FlowAction::Chain))));
    }

    #[test]
    fn test_parse_transformation() {
        let actions = parse_actions("id:1,t:lowercase,t:urlDecode").unwrap();
        let transforms: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::Transformation(_)))
            .collect();
        assert_eq!(transforms.len(), 2);
    }
}
