//! SecRule parser module.
//!
//! This module handles parsing of ModSecurity configuration directives including:
//! - SecRule: The main rule directive
//! - SecAction: Actions without matching
//! - SecMarker: Named markers for skipAfter
//! - SecRuleEngine: Enable/disable rule processing
//! - Include: File inclusion
//!
//! ## SecRule Syntax
//!
//! ```text
//! SecRule VARIABLES "OPERATOR" "ACTIONS"
//! ```
//!
//! Where:
//! - VARIABLES: Comma-separated list of variables to inspect
//! - OPERATOR: Pattern to match (e.g., @rx, @contains)
//! - ACTIONS: Comma-separated list of actions (e.g., id:1,deny,log)

mod lexer;
mod directive;
mod variable;
mod operator;
mod action;

pub use lexer::{Lexer, Token, TokenKind};
pub use directive::{Directive, SecRule, SecAction, SecMarker, RuleEngineMode};
pub use variable::{VariableSpec, VariableName, Selection};
pub use operator::{OperatorSpec, OperatorName};
pub use action::{Action, DisruptiveAction, FlowAction, MetadataAction, DataAction, LoggingAction, ControlAction, SetVarSpec, SetVarValue, parse_actions};

use crate::error::{Error, Result, SourceLocation};
use std::path::Path;

/// Parser for ModSecurity configuration files.
pub struct Parser {
    /// Parsed directives.
    directives: Vec<Directive>,
    /// Current source location for error reporting.
    location: SourceLocation,
    /// Default actions to apply to rules.
    default_actions: Vec<Action>,
}

impl Parser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            location: SourceLocation::default(),
            default_actions: Vec::new(),
        }
    }

    /// Parse a configuration string.
    pub fn parse(&mut self, input: &str) -> Result<()> {
        self.parse_with_location(input, None)
    }

    /// Parse a configuration string with file location.
    pub fn parse_with_location(&mut self, input: &str, file: Option<&Path>) -> Result<()> {
        self.location.file = file.map(|p| p.to_path_buf());
        self.location.line = 1;
        self.location.column = 1;

        let mut lexer = Lexer::new(input);

        while let Some(token) = lexer.next_token() {
            self.location.line = token.line;
            self.location.column = token.column;

            match token.kind {
                TokenKind::Directive(name) => {
                    let directive = self.parse_directive(&name, &mut lexer)?;
                    self.directives.push(directive);
                }
                TokenKind::Comment => {
                    // Skip comments
                }
                TokenKind::Newline => {
                    // Skip blank lines
                }
                _ => {
                    return Err(Error::parse(
                        format!("unexpected token: {:?}", token.kind),
                        self.location.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Parse a configuration file.
    pub fn parse_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::RuleFileLoad {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.parse_with_location(&content, Some(path))
    }

    /// Parse files matching a glob pattern.
    pub fn parse_glob(&mut self, pattern: &str) -> Result<()> {
        let paths = glob::glob(pattern)
            .map_err(|e| Error::parse(format!("invalid glob pattern: {}", e), pattern))?;

        for entry in paths {
            match entry {
                Ok(path) => {
                    if path.is_file() {
                        self.parse_file(&path)?;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "error reading glob entry");
                }
            }
        }

        Ok(())
    }

    /// Get the parsed directives.
    pub fn into_directives(self) -> Vec<Directive> {
        self.directives
    }

    /// Get a reference to the parsed directives.
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// Parse a directive starting from the directive name.
    fn parse_directive(&mut self, name: &str, lexer: &mut Lexer) -> Result<Directive> {
        match name.to_lowercase().as_str() {
            "secrule" => self.parse_secrule(lexer),
            "secaction" => self.parse_secaction(lexer),
            "secmarker" => self.parse_secmarker(lexer),
            "secruleengine" => self.parse_secruleengine(lexer),
            "secdefaultaction" => self.parse_secdefaultaction(lexer),
            "secruleremovebyid" => self.parse_secruleremovebyid(lexer),
            "secrequestbodyaccess" => self.parse_boolean_directive(lexer, "SecRequestBodyAccess"),
            "secresponsebodyaccess" => self.parse_boolean_directive(lexer, "SecResponseBodyAccess"),
            "include" => self.parse_include(lexer),
            _ => {
                // Skip unknown directives with a warning
                tracing::warn!(
                    directive = name,
                    location = %self.location,
                    "unknown directive, skipping"
                );
                self.skip_to_end_of_line(lexer);
                Ok(Directive::Unknown(name.to_string()))
            }
        }
    }

    /// Parse a SecRule directive.
    fn parse_secrule(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        // Parse variables
        let variables_str = self.expect_argument(lexer, "SecRule variables")?;
        let variables = variable::parse_variables(&variables_str)?;

        // Parse operator
        let operator_str = self.expect_quoted_argument(lexer, "SecRule operator")?;
        let operator = operator::parse_operator(&operator_str)?;

        // Parse actions (optional)
        let actions = if self.peek_quoted(lexer) {
            let actions_str = self.expect_quoted_argument(lexer, "SecRule actions")?;
            let mut actions = action::parse_actions(&actions_str)?;
            // Apply default actions
            actions = self.merge_default_actions(actions);
            actions
        } else {
            self.default_actions.clone()
        };

        Ok(Directive::SecRule(SecRule {
            variables,
            operator,
            actions,
            location: self.location.clone(),
        }))
    }

    /// Parse a SecAction directive.
    fn parse_secaction(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let actions_str = self.expect_quoted_argument(lexer, "SecAction")?;
        let actions = action::parse_actions(&actions_str)?;

        Ok(Directive::SecAction(SecAction {
            actions,
            location: self.location.clone(),
        }))
    }

    /// Parse a SecMarker directive.
    fn parse_secmarker(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let name = self.expect_argument(lexer, "SecMarker name")?;
        Ok(Directive::SecMarker(SecMarker { name }))
    }

    /// Parse a SecRuleEngine directive.
    fn parse_secruleengine(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let mode_str = self.expect_argument(lexer, "SecRuleEngine mode")?;
        let mode = match mode_str.to_lowercase().as_str() {
            "on" => RuleEngineMode::On,
            "off" => RuleEngineMode::Off,
            "detectiononly" => RuleEngineMode::DetectionOnly,
            _ => {
                return Err(Error::parse(
                    format!("invalid SecRuleEngine mode: {}", mode_str),
                    self.location.to_string(),
                ));
            }
        };
        Ok(Directive::SecRuleEngine(mode))
    }

    /// Parse a SecDefaultAction directive.
    fn parse_secdefaultaction(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let actions_str = self.expect_quoted_argument(lexer, "SecDefaultAction")?;
        let actions = action::parse_actions(&actions_str)?;
        self.default_actions = actions.clone();
        Ok(Directive::SecDefaultAction(actions))
    }

    /// Parse a SecRuleRemoveById directive.
    fn parse_secruleremovebyid(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let ids_str = self.expect_argument(lexer, "SecRuleRemoveById")?;
        let ids: Vec<u64> = ids_str
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        Ok(Directive::SecRuleRemoveById(ids))
    }

    /// Parse a boolean directive (On/Off).
    fn parse_boolean_directive(&mut self, lexer: &mut Lexer, name: &str) -> Result<Directive> {
        let value_str = self.expect_argument(lexer, name)?;
        let value = match value_str.to_lowercase().as_str() {
            "on" => true,
            "off" => false,
            _ => {
                return Err(Error::parse(
                    format!("invalid {} value: {} (expected On/Off)", name, value_str),
                    self.location.to_string(),
                ));
            }
        };

        match name {
            "SecRequestBodyAccess" => Ok(Directive::SecRequestBodyAccess(value)),
            "SecResponseBodyAccess" => Ok(Directive::SecResponseBodyAccess(value)),
            _ => Ok(Directive::Unknown(name.to_string())),
        }
    }

    /// Parse an Include directive.
    fn parse_include(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let path = self.expect_argument(lexer, "Include path")?;

        // Resolve relative paths
        let resolved_path = if let Some(ref base) = self.location.file {
            if let Some(parent) = base.parent() {
                let full_path = parent.join(&path);
                if full_path.exists() {
                    full_path.to_string_lossy().to_string()
                } else {
                    path
                }
            } else {
                path
            }
        } else {
            path
        };

        // Parse the included file(s)
        self.parse_glob(&resolved_path)?;

        Ok(Directive::Include(resolved_path.into()))
    }

    /// Expect an unquoted argument.
    fn expect_argument(&mut self, lexer: &mut Lexer, context: &str) -> Result<String> {
        lexer.skip_whitespace();

        match lexer.next_token() {
            Some(token) => match token.kind {
                TokenKind::Word(s) | TokenKind::QuotedString(s) => Ok(s),
                _ => Err(Error::parse(
                    format!("expected {} but got {:?}", context, token.kind),
                    self.location.to_string(),
                )),
            },
            None => Err(Error::parse(
                format!("expected {} but got end of input", context),
                self.location.to_string(),
            )),
        }
    }

    /// Expect a quoted argument.
    fn expect_quoted_argument(&mut self, lexer: &mut Lexer, context: &str) -> Result<String> {
        lexer.skip_whitespace();

        match lexer.next_token() {
            Some(token) => match token.kind {
                TokenKind::QuotedString(s) => Ok(s),
                _ => Err(Error::parse(
                    format!("expected quoted {} but got {:?}", context, token.kind),
                    self.location.to_string(),
                )),
            },
            None => Err(Error::parse(
                format!("expected quoted {} but got end of input", context),
                self.location.to_string(),
            )),
        }
    }

    /// Check if next token is a quoted string.
    fn peek_quoted(&self, lexer: &mut Lexer) -> bool {
        lexer.skip_whitespace();
        lexer.peek().map(|c| c == '"' || c == '\'').unwrap_or(false)
    }

    /// Skip to end of current line.
    fn skip_to_end_of_line(&self, lexer: &mut Lexer) {
        while let Some(token) = lexer.next_token() {
            if matches!(token.kind, TokenKind::Newline) {
                break;
            }
        }
    }

    /// Merge default actions with rule-specific actions.
    fn merge_default_actions(&self, rule_actions: Vec<Action>) -> Vec<Action> {
        // Rule actions override defaults
        let mut result = self.default_actions.clone();
        for action in rule_actions {
            // Remove any existing action of the same specific type
            // (need to compare both outer and inner discriminants for nested enums)
            result.retain(|a| !actions_same_type(a, &action));
            result.push(action);
        }
        result
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if two actions are of the same specific type (including inner variants).
fn actions_same_type(a: &Action, b: &Action) -> bool {
    match (a, b) {
        // For Metadata, compare inner variants
        (Action::Metadata(ma), Action::Metadata(mb)) => {
            std::mem::discriminant(ma) == std::mem::discriminant(mb)
        }
        // For other action types, compare outer variants
        _ => std::mem::discriminant(a) == std::mem::discriminant(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let mut parser = Parser::new();
        parser
            .parse(r#"SecRule REQUEST_URI "@contains /admin" "id:1,deny,status:403""#)
            .unwrap();

        assert_eq!(parser.directives.len(), 1);
        match &parser.directives[0] {
            Directive::SecRule(rule) => {
                assert_eq!(rule.variables.len(), 1);
                assert_eq!(rule.variables[0].name, VariableName::RequestUri);
            }
            _ => panic!("expected SecRule"),
        }
    }

    #[test]
    fn test_parse_secruleengine() {
        let mut parser = Parser::new();
        parser.parse("SecRuleEngine On").unwrap();

        assert_eq!(parser.directives.len(), 1);
        match &parser.directives[0] {
            Directive::SecRuleEngine(mode) => {
                assert_eq!(*mode, RuleEngineMode::On);
            }
            _ => panic!("expected SecRuleEngine"),
        }
    }
}
