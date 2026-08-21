//! Compiled ruleset for efficient rule matching.

use crate::error::Result;
use crate::operators::{compile_operator, Operator};
use crate::parser::{
    Action, Directive, FlowAction, MetadataAction, OperatorName, OperatorSpec, Parser,
    RuleEngineMode as ParserRuleEngineMode, RuleIdSelector, Selection, UpdateTargetById,
    VariableSpec,
};
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
    /// Original operator specification (retained for runtime macro expansion).
    pub operator_spec: OperatorSpec,
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

        // SecRuleRemoveById and SecRuleUpdateTargetById are applied against
        // the whole ruleset once loading completes (like ModSecurity, where
        // they modify already-defined rules). Removals are collected up front
        // so removed rules are never compiled; target updates are applied
        // after the compile loop.
        let removals: Vec<RuleIdSelector> = directives
            .iter()
            .filter_map(|d| match d {
                Directive::SecRuleRemoveById(ids) => Some(ids.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let mut target_updates: Vec<UpdateTargetById> = Vec::new();
        // When a removed rule is a chain head, its continuation rules (which
        // usually carry no id of their own) must be dropped with it.
        let mut skipping_removed_chain = false;

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

                    if skipping_removed_chain {
                        // Continuation of a removed chained rule.
                        skipping_removed_chain = is_chain;
                        continue;
                    }
                    if id_is_removed(&id, &removals) {
                        skipping_removed_chain = is_chain;
                        continue;
                    }

                    let transformations = extract_transformations(&rule.actions)?;

                    let operator_spec = rule.operator.clone();
                    let operator = compile_operator(&rule.operator)?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: rule.variables,
                        operator,
                        operator_negated: operator_spec.negated,
                        operator_spec,
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
                    let operator_spec = OperatorSpec {
                        negated: false,
                        name: OperatorName::UnconditionalMatch,
                        argument: String::new(),
                    };
                    let operator = compile_operator(&operator_spec)?;

                    let compiled = CompiledRule {
                        id,
                        phase,
                        variables: vec![],
                        operator,
                        operator_negated: false,
                        operator_spec,
                        transformations,
                        actions: sec_action.actions,
                        is_chain: false,
                        chain_next: None,
                    };

                    ruleset.rules.add(phase, compiled);
                }
                Directive::SecRuleUpdateTargetById(update) => {
                    // Applied after every rule is compiled: the directive may
                    // appear before or after the rule it targets, and CRS
                    // exclusion files are conventionally included last.
                    target_updates.push(update.clone());
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

        apply_target_updates(&mut ruleset, &target_updates);

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

/// Check whether a rule's ID is covered by any `SecRuleRemoveById` selector.
///
/// Rules without an ID cannot be targeted by ID, and an ID that does not parse
/// as a number never matches a numeric selector.
fn id_is_removed(id: &Option<String>, removals: &[RuleIdSelector]) -> bool {
    let Some(numeric) = id.as_ref().and_then(|s| s.parse::<u64>().ok()) else {
        return false;
    };
    removals.iter().any(|selector| selector.matches(numeric))
}

/// Apply `SecRuleUpdateTargetById` directives to the compiled rules.
///
/// ModSecurity semantics, as CRS exclusion files rely on them:
///
/// - `SecRuleUpdateTargetById 942100 "!ARGS:password"` adds a target exclusion,
///   so the rule stops inspecting that target. The exclusion is pushed onto
///   every variable of the rule, because the resolver applies exclusions
///   per-variable when expanding collections.
/// - `SecRuleUpdateTargetById 942100 "ARGS:foo"` appends a target.
/// - `SecRuleUpdateTargetById 942100 "ARGS:foo" "ARGS:bar"` replaces the
///   `ARGS:bar` target with `ARGS:foo`.
///
/// The update applies to the rule carrying the ID. For a chained rule that is
/// the chain starter, matching ModSecurity, which identifies a chain by the
/// starter's ID.
fn apply_target_updates(ruleset: &mut CompiledRuleset, updates: &[UpdateTargetById]) {
    if updates.is_empty() {
        return;
    }
    for rules in ruleset.rules.by_phase.values_mut() {
        for rule in rules.iter_mut() {
            let Some(numeric) = rule.id.as_ref().and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            for update in updates {
                if !update.ids.iter().any(|selector| selector.matches(numeric)) {
                    continue;
                }
                if let Some(replaced) = &update.replaced {
                    rule.variables
                        .retain(|var| !variable_matches_target(var, replaced));
                }
                for exclusion in &update.exclusions {
                    for var in rule.variables.iter_mut() {
                        if !var.exclusions.iter().any(|e| e == exclusion) {
                            var.exclusions.push(exclusion.clone());
                        }
                    }
                }
                rule.variables.extend(update.additions.iter().cloned());
            }
        }
    }
}

/// Whether a rule variable refers to the target named by a directive argument
/// such as `ARGS:bar` or `REQUEST_HEADERS`.
fn variable_matches_target(var: &VariableSpec, target: &str) -> bool {
    let (collection, key) = match target.split_once(':') {
        Some((c, k)) => (c, Some(k)),
        None => (target, None),
    };
    if !format!("{:?}", var.name).eq_ignore_ascii_case(collection) {
        return false;
    }
    match (&var.selection, key) {
        (None, None) => true,
        (Some(Selection::Key(existing)), Some(k)) => existing.eq_ignore_ascii_case(k),
        _ => false,
    }
}


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
