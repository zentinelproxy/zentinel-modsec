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
pub use directive::{
    Directive, RuleEngineMode, RuleIdSelector, SecAction, SecMarker, SecRule, UpdateTargetById,
};
pub use variable::{VariableSpec, VariableName, Selection};
pub(crate) use variable::parse_single_variable;
pub use operator::{OperatorSpec, OperatorName};
pub use action::{Action, DisruptiveAction, FlowAction, MetadataAction, DataAction, LoggingAction, ControlAction, SetVarSpec, SetVarValue, parse_actions};

use crate::error::{Error, Result, SourceLocation};
use std::collections::HashMap;
use std::path::Path;

/// Parser for ModSecurity configuration files.
pub struct Parser {
    /// Parsed directives.
    directives: Vec<Directive>,
    /// Current source location for error reporting.
    location: SourceLocation,
    /// Default actions to apply to rules, keyed by the phase they configure.
    ///
    /// `SecDefaultAction` is per-phase in ModSecurity -- CRS issues one for
    /// each of the five phases -- so a single flat list would let the last
    /// directive parsed govern every phase.
    default_actions: HashMap<u8, Vec<Action>>,
}

impl Parser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            location: SourceLocation::default(),
            default_actions: HashMap::new(),
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
            "secruleupdatetargetbyid" => self.parse_secruleupdatetargetbyid(lexer),
            "secrequestbodyaccess" => self.parse_boolean_directive(lexer, "SecRequestBodyAccess"),
            "secresponsebodyaccess" => self.parse_boolean_directive(lexer, "SecResponseBodyAccess"),
            "include" => self.parse_include(lexer),
            // Recognized engine-config/metadata directives that have no effect on
            // rule evaluation — skip quietly rather than warning.
            "seccomponentsignature" | "seccollectiontimeout" => {
                self.skip_to_end_of_line(lexer);
                Ok(Directive::Unknown(name.to_string()))
            }
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
        let mut operator = operator::parse_operator(&operator_str)?;
        self.resolve_operator_file_path(&mut operator);

        // Parse actions (optional)
        let actions = if self.peek_quoted(lexer) {
            let actions_str = self.expect_quoted_argument(lexer, "SecRule actions")?;
            let mut actions = action::parse_actions(&actions_str)?;
            // Apply default actions
            actions = self.merge_default_actions(actions);
            actions
        } else {
            // No actions of its own: it still inherits the defaults for the
            // phase it lands in, which with no `phase` action is phase 2.
            self.defaults_for_phase(DEFAULT_PHASE).to_vec()
        };

        Ok(Directive::SecRule(SecRule {
            variables,
            operator,
            actions,
            location: self.location.clone(),
        }))
    }

    /// Resolve a relative data-file argument (`@pmFromFile`/`@ipMatchFromFile`)
    /// against the directory of the file currently being parsed, matching how
    /// ModSecurity/CRS reference their `.data` files.
    fn resolve_operator_file_path(&self, operator: &mut OperatorSpec) {
        if !matches!(
            operator.name,
            OperatorName::PmFromFile | OperatorName::IpMatchFromFile
        ) {
            return;
        }
        if std::path::Path::new(&operator.argument).is_absolute() {
            return;
        }
        if let Some(parent) = self.location.file.as_ref().and_then(|f| f.parent()) {
            let joined = parent.join(&operator.argument);
            if joined.exists() {
                operator.argument = joined.to_string_lossy().into_owned();
            }
        }
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
        self.default_actions
            .insert(phase_of(&actions).unwrap_or(DEFAULT_PHASE), actions.clone());
        Ok(Directive::SecDefaultAction(actions))
    }

    /// Parse a SecRuleRemoveById directive.
    ///
    /// ModSecurity allows multiple IDs and ID ranges in a single directive,
    /// e.g. `SecRuleRemoveById 1 2 "9000-9010"`. IDs may appear as several
    /// arguments and/or space-separated inside one (quoted) argument.
    fn parse_secruleremovebyid(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let mut ids = Vec::new();
        loop {
            let arg = self.expect_argument(lexer, "SecRuleRemoveById")?;
            ids.extend(self.parse_id_selectors(&arg, "SecRuleRemoveById")?);
            if !self.peek_more_arguments(lexer) {
                break;
            }
        }
        Ok(Directive::SecRuleRemoveById(ids))
    }

    /// Parse a SecRuleUpdateTargetById directive.
    ///
    /// Syntax: `SecRuleUpdateTargetById ID TARGET1[|TARGET2|...] [REPLACED_TARGET]`
    /// where ID is a rule ID or ID range (space-separated lists accepted when
    /// quoted), targets may be `!`-prefixed exclusions, and the optional third
    /// argument names an existing target to replace.
    fn parse_secruleupdatetargetbyid(&mut self, lexer: &mut Lexer) -> Result<Directive> {
        let ids_str = self.expect_argument(lexer, "SecRuleUpdateTargetById id")?;
        let ids = self.parse_id_selectors(&ids_str, "SecRuleUpdateTargetById")?;

        let targets_str = self.expect_argument(lexer, "SecRuleUpdateTargetById targets")?;
        let (additions, exclusions) = variable::parse_update_targets(&targets_str)?;
        if additions.is_empty() && exclusions.is_empty() {
            return Err(Error::parse(
                "SecRuleUpdateTargetById requires at least one target",
                self.location.to_string(),
            ));
        }

        let replaced = if self.peek_more_arguments(lexer) {
            Some(self.expect_argument(lexer, "SecRuleUpdateTargetById replaced target")?)
        } else {
            None
        };

        Ok(Directive::SecRuleUpdateTargetById(UpdateTargetById {
            ids,
            additions,
            exclusions,
            replaced,
            location: self.location.clone(),
        }))
    }

    /// Parse a whitespace-separated list of rule IDs and inclusive ID ranges
    /// (`942100` or `942100-942199`).
    fn parse_id_selectors(&self, input: &str, context: &str) -> Result<Vec<RuleIdSelector>> {
        let mut selectors = Vec::new();
        for token in input.split_whitespace() {
            let selector = if let Some((start, end)) = token.split_once('-') {
                let start: u64 = start.trim().parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id range '{token}'"),
                        self.location.to_string(),
                    )
                })?;
                let end: u64 = end.trim().parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id range '{token}'"),
                        self.location.to_string(),
                    )
                })?;
                if start > end {
                    return Err(Error::parse(
                        format!("{context}: invalid rule id range '{token}' (start > end)"),
                        self.location.to_string(),
                    ));
                }
                RuleIdSelector::Range(start, end)
            } else {
                RuleIdSelector::Single(token.parse().map_err(|_| {
                    Error::parse(
                        format!("{context}: invalid rule id '{token}'"),
                        self.location.to_string(),
                    )
                })?)
            };
            selectors.push(selector);
        }
        if selectors.is_empty() {
            return Err(Error::parse(
                format!("{context}: expected at least one rule id"),
                self.location.to_string(),
            ));
        }
        Ok(selectors)
    }

    /// Check whether more arguments follow on the current logical line.
    fn peek_more_arguments(&self, lexer: &mut Lexer) -> bool {
        lexer.skip_whitespace();
        !matches!(lexer.peek(), None | Some('\n') | Some('\r') | Some('#'))
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

        // Resolve relative paths (including globs) against the including file's
        // directory. A glob pattern never `exists()` as a literal path, so it is
        // detected explicitly rather than falling back to a CWD-relative path.
        let resolved_path = if let Some(parent) = self.location.file.as_ref().and_then(|f| f.parent())
        {
            let candidate = parent.join(&path);
            let is_glob = path.contains(['*', '?', '[']);
            if candidate.exists() || is_glob {
                candidate.to_string_lossy().to_string()
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
        let phase = phase_of(&rule_actions).unwrap_or(DEFAULT_PHASE);
        let defaults = self.defaults_for_phase(phase);

        // `block` means "whatever disruptive action the defaults name", so the
        // default's disruptive action has to be captured before the merge below
        // discards it in favour of the rule's own.
        let inherited_disruptive = defaults
            .iter()
            .find(|a| matches!(a, Action::Disruptive(_)))
            .cloned();

        // Rule actions override defaults
        let mut result = defaults.to_vec();
        for action in rule_actions {
            // Remove any existing action of the same specific type
            // (need to compare both outer and inner discriminants for nested enums)
            result.retain(|a| !actions_same_type(a, &action));
            result.push(action);
        }

        // Resolve `block` against the inherited disruptive action. CRS sets
        // `SecDefaultAction "phase:N,log,auditlog,pass"` and then tags nearly
        // every rule `block`, meaning "score me, and let 949110 decide" -- so
        // treating `block` as a deny of its own turns the anomaly-scoring model
        // into block-on-first-match.
        if let Some(pos) = result
            .iter()
            .position(|a| matches!(a, Action::Disruptive(DisruptiveAction::Block)))
        {
            match inherited_disruptive {
                // A default that is itself `block` says nothing; leave it be.
                Some(Action::Disruptive(DisruptiveAction::Block)) | None => {}
                Some(inherited) => result[pos] = inherited,
            }
        }

        result
    }

    /// Defaults configured for a phase, or none if that phase has no
    /// `SecDefaultAction`.
    fn defaults_for_phase(&self, phase: u8) -> &[Action] {
        self.default_actions
            .get(&phase)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// The phase ModSecurity assigns when a rule does not name one.
const DEFAULT_PHASE: u8 = 2;

/// Phase named by a `phase:` action, if any.
fn phase_of(actions: &[Action]) -> Option<u8> {
    actions.iter().find_map(|a| match a {
        Action::Metadata(MetadataAction::Phase(p)) => Some(*p),
        _ => None,
    })
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

    #[test]
    fn test_relative_include_glob_resolves() {
        // `Include rules/*.conf` must resolve relative to the including file,
        // not the process CWD.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("rules");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            sub.join("a.conf"),
            r#"SecRule REQUEST_URI "@contains /a" "id:101,phase:1,deny""#,
        )
        .unwrap();
        std::fs::write(
            sub.join("b.conf"),
            r#"SecRule REQUEST_URI "@contains /b" "id:102,phase:1,deny""#,
        )
        .unwrap();
        let entry = dir.path().join("entry.conf");
        std::fs::write(&entry, "Include rules/*.conf\n").unwrap();

        let mut parser = Parser::new();
        parser.parse_file(&entry).unwrap();
        let secrules = parser
            .directives
            .iter()
            .filter(|d| matches!(d, Directive::SecRule(_)))
            .count();
        assert_eq!(secrules, 2, "both included rule files should be parsed");
    }

    #[test]
    fn test_pmfromfile_relative_path_resolves() {
        // `@pmFromFile patterns.data` must resolve next to the rule file.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("patterns.data"), "evilword\n").unwrap();
        let conf = dir.path().join("rules.conf");
        std::fs::write(
            &conf,
            r#"SecRule ARGS "@pmFromFile patterns.data" "id:201,phase:1,deny""#,
        )
        .unwrap();

        let mut parser = Parser::new();
        parser.parse_file(&conf).unwrap();
        match &parser.directives[0] {
            Directive::SecRule(rule) => {
                let arg = &rule.operator.argument;
                let p = std::path::Path::new(arg);
                assert!(p.is_absolute(), "data path should be resolved to absolute: {arg}");
                assert!(p.exists(), "resolved data path should exist: {arg}");
            }
            _ => panic!("expected SecRule"),
        }
    }

    #[test]
    fn test_normalise_path_transformation_alias() {
        // CRS uses the British spelling t:normalisePath; it must compile.
        let rs = crate::engine::CompiledRuleset::from_string(
            r#"SecRule REQUEST_URI "@contains /etc" "id:301,phase:1,t:normalisePath,deny""#,
        );
        assert!(rs.is_ok(), "normalisePath must be recognized: {:?}", rs.err());
    }
}
