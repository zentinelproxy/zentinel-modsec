//! Compiled ruleset for efficient rule matching.

use crate::error::Result;
use crate::operators::{compile_operator, Operator};
use crate::parser::{Action, MetadataAction, Directive, Parser, VariableSpec, OperatorSpec, OperatorName, FlowAction, RuleEngineMode as ParserRuleEngineMode};
use crate::transformations::TransformationPipeline;

use super::phase::Phase;
use std::collections::HashMap;
use std::sync::Arc;

/// A parsed SecRule ready for execution.
#[derive(Clone)]
pub struct CompiledRule {
    /// Rule ID.
    pub id: Option<String>,
    /// Rule phase.
    pub phase: Phase,
    /// Variable specifications.
    pub variables: Vec<VariableSpec>,
    /// Compiled operator.
    pub operator: Arc<dyn Operator>,
    /// Whether operator is negated.
    pub operator_negated: bool,
    /// Transformation pipeline.
    pub transformations: TransformationPipeline,
    /// Actions to execute on match.
    pub actions: Vec<Action>,
    /// Whether this rule is part of a chain.
    pub is_chain: bool,
    /// Index of next rule in chain (if any).
    pub chain_next: Option<usize>,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("variables", &self.variables)
            .field("operator_negated", &self.operator_negated)
            .field("is_chain", &self.is_chain)
            .finish()
    }
}

/// Rules grouped by phase for efficient processing.
pub struct Rules {
    /// Rules organized by phase.
    by_phase: HashMap<Phase, Vec<CompiledRule>>,
    /// Markers for skipAfter.
    markers: HashMap<String, (Phase, usize)>,
}

impl Rules {
    /// Create empty rules.
    pub fn new() -> Self {
        Self {
            by_phase: HashMap::new(),
            markers: HashMap::new(),
        }
    }

    /// Add a rule to a specific phase.
    pub fn add(&mut self, phase: Phase, rule: CompiledRule) {
        self.by_phase.entry(phase).or_default().push(rule);
    }

    /// Add a marker.
    pub fn add_marker(&mut self, name: String, phase: Phase, index: usize) {
        self.markers.insert(name, (phase, index));
    }

    /// Get rules for a phase.
    pub fn for_phase(&self, phase: Phase) -> &[CompiledRule] {
        self.by_phase.get(&phase).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get marker position.
    pub fn marker(&self, name: &str) -> Option<(Phase, usize)> {
        self.markers.get(name).copied()
    }

    /// Get total rule count.
    pub fn count(&self) -> usize {
        self.by_phase.values().map(|v| v.len()).sum()
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self::new()
    }
}

/// A fully compiled ruleset ready for transaction processing.
pub struct CompiledRuleset {
    /// Compiled rules.
    rules: Rules,
    /// Rule engine mode.
    engine_mode: RuleEngineMode,
}

/// Rule engine operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngineMode {
    /// Rules are enabled and will block.
    On,
    /// Rules are enabled but will only detect.
    DetectionOnly,
    /// Rules are disabled.
    Off,
}

impl Default for RuleEngineMode {
    fn default() -> Self {
        RuleEngineMode::On
    }
}

impl CompiledRuleset {
    /// Create an empty ruleset.
    pub fn new() -> Self {
        Self {
            rules: Rules::new(),
            engine_mode: RuleEngineMode::default(),
        }
    }

    /// Load and compile rules from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let mut parser = Parser::new();
        parser.parse_file(std::path::Path::new(path))?;
        Self::compile(parser.into_directives())
    }

    /// Load and compile rules from a string.
    pub fn from_string(rules: &str) -> Result<Self> {
        let mut parser = Parser::new();
        parser.parse(rules)?;
        Self::compile(parser.into_directives())
    }

    /// Compile parsed directives into a ruleset.
    pub fn compile(directives: Vec<Directive>) -> Result<Self> {
        let mut ruleset = Self::new();
        let mut pending_chain: Option<(Phase, usize)> = None;

        for directive in directives {
            match directive {
                Directive::SecRuleEngine(mode) => {
                    ruleset.engine_mode = match mode {
                        ParserRuleEngineMode::On => RuleEngineMode::On,
                        ParserRuleEngineMode::Off => RuleEngineMode::Off,
                        ParserRuleEngineMode::DetectionOnly => RuleEngineMode::DetectionOnly,
                    };
                }
                Directive::SecRule(rule) => {
                    let phase = extract_phase(&rule.actions);
                    let id = extract_id(&rule.actions);
                    let is_chain = has_chain(&rule.actions);
                    let transformations = extract_transformations(&rule.actions)?;

                    let operator = compile_operator(&rule.operator)?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: rule.variables,
                        operator,
                        operator_negated: rule.operator.negated,
                        transformations,
                        actions: rule.actions,
                        is_chain,
                        chain_next: None,
                    };

                    let rules_for_phase = ruleset.rules.by_phase.entry(phase).or_default();
                    let idx = rules_for_phase.len();
                    rules_for_phase.push(compiled);

                    // Handle chaining
                    if let Some((chain_phase, chain_idx)) = pending_chain.take() {
                        if chain_phase == phase {
                            if let Some(prev_rule) = ruleset.rules.by_phase
                                .get_mut(&chain_phase)
                                .and_then(|r| r.get_mut(chain_idx))
                            {
                                prev_rule.chain_next = Some(idx);
                            }
                        }
                    }

                    if is_chain {
                        pending_chain = Some((phase, idx));
                    }
                }
                Directive::SecAction(sec_action) => {
                    // SecAction is like a rule that always matches
                    let phase = extract_phase(&sec_action.actions);
                    let id = extract_id(&sec_action.actions);
                    let transformations = extract_transformations(&sec_action.actions)?;

                    // Create a rule with unconditional match operator
                    let operator = compile_operator(&OperatorSpec {
                        negated: false,
                        name: OperatorName::UnconditionalMatch,
                        argument: String::new(),
                    })?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: vec![],
                        operator,
                        operator_negated: false,
                        transformations,
                        actions: sec_action.actions,
                        is_chain: false,
                        chain_next: None,
                    };

                    ruleset.rules.add(phase, compiled);
                }
                Directive::SecMarker(marker) => {
                    // Add marker at current position in default phase
                    let phase = Phase::RequestHeaders;
                    let idx = ruleset.rules.by_phase.get(&phase).map(|v| v.len()).unwrap_or(0);
                    ruleset.rules.add_marker(marker.name, phase, idx);
                }
                _ => {
                    // Other directives (SecDefaultAction, etc.) handled elsewhere
                }
            }
        }

        Ok(ruleset)
    }

    /// Get rules for a phase.
    pub fn rules_for_phase(&self, phase: Phase) -> &[CompiledRule] {
        self.rules.for_phase(phase)
    }

    /// Get total rule count.
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Get engine mode.
    pub fn engine_mode(&self) -> RuleEngineMode {
        self.engine_mode
    }

    /// Get marker position.
    pub fn marker(&self, name: &str) -> Option<(Phase, usize)> {
        self.rules.marker(name)
    }
}

impl Default for CompiledRuleset {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract phase from actions, defaulting to Phase 2.
fn extract_phase(actions: &[Action]) -> Phase {
    for action in actions {
        if let Action::Metadata(MetadataAction::Phase(p)) = action {
            return Phase::from_number(*p).unwrap_or(Phase::RequestBody);
        }
    }
    Phase::RequestBody // ModSecurity default
}

/// Extract rule ID from actions.
fn extract_id(actions: &[Action]) -> Option<String> {
    for action in actions {
        if let Action::Metadata(MetadataAction::Id(id)) = action {
            return Some(id.to_string());
        }
    }
    None
}

/// Check if chain action is present.
fn has_chain(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::Flow(FlowAction::Chain)))
}

/// Extract and compile transformation pipeline.
fn extract_transformations(actions: &[Action]) -> Result<TransformationPipeline> {
    let mut names = Vec::new();
    for action in actions {
        if let Action::Transformation(t) = action {
            names.push(t.clone());
        }
    }
    if names.is_empty() {
        Ok(TransformationPipeline::new())
    } else {
        TransformationPipeline::from_names(&names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_rule() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.rule_count(), 1);

        let phase1_rules = ruleset.rules_for_phase(Phase::RequestHeaders);
        assert_eq!(phase1_rules.len(), 1);
        assert_eq!(phase1_rules[0].id, Some("1".to_string()));
    }

    #[test]
    fn test_compile_multiple_phases() {
        let rules = r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            SecRule REQUEST_BODY "@rx attack" "id:2,phase:2,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.rule_count(), 2);

        assert_eq!(ruleset.rules_for_phase(Phase::RequestHeaders).len(), 1);
        assert_eq!(ruleset.rules_for_phase(Phase::RequestBody).len(), 1);
    }

    #[test]
    fn test_engine_mode() {
        let rules = r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#;
        let ruleset = CompiledRuleset::from_string(rules).unwrap();
        assert_eq!(ruleset.engine_mode(), RuleEngineMode::DetectionOnly);
    }
}
