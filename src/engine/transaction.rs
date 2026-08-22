//! Transaction processing for ModSecurity.

use std::sync::Arc;

use super::chain::ChainState;
use super::control::{CtlDirective, TransactionControls};
use super::intervention::Intervention;
use super::phase::Phase;
use super::ruleset::{CompiledRule, CompiledRuleset, RuleEngineMode};
use super::scoring::AnomalyScore;
use crate::actions::{
    execute_actions, ActionResult, DisruptiveOutcome, FlowOutcome, SetVarOp, SetVarOperation,
};
use crate::error::Result;
use crate::operators::{compile_operator, Operator};
use crate::parser::OperatorSpec;
use crate::variables::{Collection, RequestData, ResponseData, TxCollection, VariableResolver};

/// Whether a lowercased Content-Type denotes a JSON body.
///
/// Covers the `+json` structured suffix (RFC 6839) as well as `application/json`,
/// so `application/vnd.api+json`, `application/problem+json` and friends are
/// inspected rather than silently falling through to the urlencoded parser.
fn is_json_content_type(ct_lower: &str) -> bool {
    let media_type = ct_lower.split(';').next().unwrap_or("").trim_end();
    media_type == "application/json"
        || media_type == "text/json"
        || media_type.ends_with("+json")
}

/// A ModSecurity transaction for processing a single request.
pub struct Transaction {
    /// Compiled ruleset reference.
    ruleset: Arc<CompiledRuleset>,
    /// Request data.
    request: RequestData,
    /// Response data.
    response: ResponseData,
    /// TX collection (mutable variables).
    tx: TxCollection,
    /// Current phase.
    phase: Phase,
    /// Intervention (if any).
    intervention: Option<Intervention>,
    /// Anomaly score tracker.
    anomaly_score: AnomalyScore,
    /// Default block status.
    default_status: u16,
    /// Matched rules.
    matched_rules: Vec<String>,
    /// Allow flag (skip further processing).
    allowed: bool,
    /// Matched variables for current rule evaluation.
    matched_vars: Vec<(String, String)>,
    /// Regex captures from last match.
    captures: Vec<String>,
    /// Per-transaction `ctl:` overrides.
    controls: TransactionControls,
}

impl Transaction {
    /// Create a new transaction.
    pub fn new(ruleset: Arc<CompiledRuleset>, default_status: u16) -> Self {
        Self {
            ruleset,
            request: RequestData::new(),
            response: ResponseData::new(),
            tx: TxCollection::new(),
            phase: Phase::RequestHeaders,
            intervention: None,
            anomaly_score: AnomalyScore::new(),
            default_status,
            matched_rules: Vec::new(),
            allowed: false,
            matched_vars: Vec::new(),
            captures: Vec::new(),
            controls: TransactionControls::default(),
        }
    }

    /// Process the request URI.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) -> Result<()> {
        self.request.set_uri(uri);
        self.request.set_method(method);
        self.request.set_protocol(protocol);
        Ok(())
    }

    /// Add a request header.
    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.request.add_header(name, value);
        Ok(())
    }

    /// Process request headers (Phase 1).
    pub fn process_request_headers(&mut self) -> Result<()> {
        self.phase = Phase::RequestHeaders;
        self.run_phase(Phase::RequestHeaders)?;
        Ok(())
    }

    /// Append data to request body.
    pub fn append_request_body(&mut self, data: &[u8]) -> Result<()> {
        self.request.append_body(data);
        Ok(())
    }

    /// Process request body (Phase 2).
    pub fn process_request_body(&mut self) -> Result<()> {
        self.phase = Phase::RequestBody;

        let content_type = self
            .request
            .headers
            .get("content-type")
            .and_then(|v| v.first().map(|s| s.to_string()));
        let ct_lower = content_type
            .as_deref()
            .map(|ct| ct.trim_start().to_ascii_lowercase())
            .unwrap_or_default();

        // ctl:requestBodyAccess=Off, typically set in phase 1, suppresses body
        // parsing entirely. Phase 2 rules still run; they just find no ARGS_POST
        // or FILES, which is what disabling body access means.
        if !self.controls.request_body_access() {
            self.run_phase(Phase::RequestBody)?;
            return Ok(());
        }

        // ctl:requestBodyProcessor overrides Content-Type sniffing. CRS relies
        // on this to force a processor when the header is absent or lying.
        if let Some(forced) = self.controls.request_body_processor() {
            match forced {
                "MULTIPART" => {
                    if !self
                        .request
                        .parse_multipart_body(content_type.as_deref().unwrap_or_default())
                    {
                        tracing::warn!(
                            "ctl:requestBodyProcessor=MULTIPART, but the body has no parseable \
                             boundary; body arguments were not extracted"
                        );
                    }
                }
                "URLENCODED" => {
                    self.request.parse_form_body();
                    self.request.body_processor = "URLENCODED".to_string();
                }
                "JSON" => self.process_json_body(),
                // CtlDirective::parse admits no other value.
                other => debug_assert!(false, "unsupported forced body processor: {other}"),
            }
            self.run_phase(Phase::RequestBody)?;
            return Ok(());
        }

        if ct_lower.starts_with("multipart/form-data") {
            // Multipart body processor: populates ARGS_POST, FILES and
            // MULTIPART_PART_HEADERS. Never fall back to the urlencoded
            // parser for multipart payloads — that would produce bogus ARGS.
            if !self
                .request
                .parse_multipart_body(content_type.as_deref().unwrap_or_default())
            {
                tracing::warn!(
                    "multipart/form-data request without a parseable boundary; \
                     body arguments were not extracted"
                );
            }
        } else if is_json_content_type(&ct_lower) {
            // JSON bodies previously fell through to the urlencoded parser,
            // which extracts nothing usable from them -- so ARGS was empty and
            // rules like CRS 942100 (`SecRule ARGS "@detectSQLi"`) had nothing
            // to inspect. An injection payload was blocked in a form body and
            // passed unexamined in a JSON body.
            self.process_json_body();
        } else {
            self.request.parse_form_body();
            if ct_lower.starts_with("application/x-www-form-urlencoded") {
                self.request.body_processor = "URLENCODED".to_string();
            }
        }

        self.run_phase(Phase::RequestBody)?;
        Ok(())
    }

    /// Run the JSON body processor, recording any failure.
    ///
    /// A failure is deliberately not fatal: the request still goes through
    /// phase 2 so that rules testing `REQBODY_ERROR` can act on it, which is
    /// how CRS rule 200002 blocks bodies it could not parse. Dropping the
    /// request here instead would take that decision away from the ruleset.
    fn process_json_body(&mut self) {
        if let Err(e) = self.request.parse_json_body() {
            tracing::debug!(
                error = %e,
                "request body could not be processed as JSON; REQBODY_ERROR is set"
            );
        }
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.response.add_header(name, value);
        Ok(())
    }

    /// Process response headers (Phase 3).
    pub fn process_response_headers(&mut self) -> Result<()> {
        self.phase = Phase::ResponseHeaders;
        self.run_phase(Phase::ResponseHeaders)?;
        Ok(())
    }

    /// Append data to response body.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        self.response.append_body(data);
        Ok(())
    }

    /// Process response body (Phase 4).
    pub fn process_response_body(&mut self) -> Result<()> {
        self.phase = Phase::ResponseBody;
        self.run_phase(Phase::ResponseBody)?;
        Ok(())
    }

    /// Process logging phase (Phase 5).
    pub fn process_logging(&mut self) -> Result<()> {
        self.phase = Phase::Logging;
        self.run_phase(Phase::Logging)?;
        Ok(())
    }

    /// Get current intervention (if any).
    pub fn intervention(&self) -> Option<&Intervention> {
        self.intervention.as_ref()
    }

    /// Check if there's an intervention.
    pub fn has_intervention(&self) -> bool {
        self.intervention.is_some()
    }

    /// Get matched rule IDs.
    pub fn matched_rules(&self) -> &[String] {
        &self.matched_rules
    }

    /// Get the anomaly score.
    pub fn anomaly_score(&self) -> i32 {
        self.anomaly_score.inbound
    }

    /// Get the TX collection.
    pub fn tx(&self) -> &TxCollection {
        &self.tx
    }

    /// Get mutable TX collection.
    pub fn tx_mut(&mut self) -> &mut TxCollection {
        &mut self.tx
    }

    /// The engine mode in force for this transaction.
    ///
    /// `ctl:ruleEngine` overrides the ruleset's configured mode for the
    /// remainder of the transaction; with no override this is the ruleset's
    /// own mode.
    fn engine_mode(&self) -> RuleEngineMode {
        self.controls.engine_mode(self.ruleset.engine_mode())
    }

    /// Run rules for a specific phase.
    fn run_phase(&mut self, phase: Phase) -> Result<()> {
        if self.allowed || self.intervention.is_some() {
            return Ok(());
        }

        // ctl:ruleEngine overrides the ruleset's mode for this transaction, so
        // the effective mode has to be re-read rather than captured once: a
        // rule in an earlier phase may have switched it off.
        if self.engine_mode() == RuleEngineMode::Off {
            return Ok(());
        }

        // Clone rules to avoid borrow conflicts with mutable self
        let rules: Vec<CompiledRule> = self.ruleset.rules_for_phase(phase).to_vec();
        if rules.is_empty() {
            return Ok(());
        }

        let mut chain_state = ChainState::new();
        // A chain is one logical rule: the starter's actions fire only when
        // every link matches, so they are held here until the chain completes.
        let mut pending_chain_actions: Option<ActionResult> = None;
        let mut skip_count: u32 = 0;
        let mut skip_after: Option<String> = None;

        let mut idx = 0;
        while idx < rules.len() {
            // Handle skip
            if skip_count > 0 {
                skip_count -= 1;
                idx += 1;
                continue;
            }

            // Handle skipAfter
            if let Some(ref marker) = skip_after {
                if let Some((marker_phase, marker_idx)) = self.ruleset.marker(marker) {
                    if marker_phase == phase && marker_idx > idx {
                        idx = marker_idx;
                        skip_after = None;
                        continue;
                    }
                }
                // Marker not found or in different phase, continue
                idx += 1;
                continue;
            }

            // A ctl:ruleEngine=Off from an earlier rule stops this phase where
            // it stands, rather than only taking effect from the next phase.
            if self.engine_mode() == RuleEngineMode::Off {
                return Ok(());
            }

            let rule = &rules[idx];

            // ctl:ruleRemoveById excluded this rule for this transaction. Skip
            // it as though it were not in the ruleset -- including its chain
            // links, which cannot fire without their starter.
            if self.controls.is_rule_removed(rule.id.as_deref()) {
                if rule.is_chain {
                    chain_state.reset();
                    pending_chain_actions = None;
                    idx += 1;
                    while idx < rules.len() && rules[idx - 1].is_chain {
                        idx += 1;
                    }
                    continue;
                }
                idx += 1;
                continue;
            }

            // Handle chain continuation
            if chain_state.in_chain && !rule.is_chain && rule.chain_next.is_none() {
                // End of chain, check if previous rules in chain matched
                if !chain_state.chain_matched {
                    chain_state.reset();
                    idx += 1;
                    continue;
                }
            }

            // Evaluate rule
            let (matched, captures) = self.evaluate_rule(rule)?;

            if matched {
                // Execute actions
                let action_result = execute_actions(&rule.actions, None, &captures);

                // Track matched rule
                if let Some(ref id) = rule.id {
                    self.matched_rules.push(id.clone());
                }

                if rule.is_chain {
                    // A link that expects more links after it. Hold the
                    // starter's actions: nothing may fire until the whole
                    // chain has matched.
                    if !chain_state.in_chain {
                        chain_state.start_chain(idx);
                        pending_chain_actions = Some(action_result);
                    }
                    chain_state.continue_chain(true, &captures);
                    idx += 1;
                    continue;
                }

                // Either a standalone rule, or the final link of a chain that
                // has now matched in full. A completed chain executes the
                // starter's actions, not the last link's.
                let action_result = if chain_state.in_chain {
                    chain_state.reset();
                    pending_chain_actions.take().unwrap_or(action_result)
                } else {
                    action_result
                };

                // Apply setvar operations
                for op in &action_result.setvar_ops {
                    self.apply_setvar(op);
                }

                // Apply ctl: overrides before the disruptive action below, so
                // that ctl:ruleEngine=DetectionOnly on the same rule governs
                // whether that rule blocks.
                for ctl in &action_result.control_ops {
                    self.controls.apply(CtlDirective::parse(ctl));
                }

                // Handle flow control
                match action_result.flow {
                    FlowOutcome::Chain => {
                        if !chain_state.in_chain {
                            chain_state.start_chain(idx);
                        }
                        chain_state.continue_chain(true, &captures);
                    }
                    FlowOutcome::Skip(n) => {
                        skip_count = n;
                    }
                    FlowOutcome::SkipAfter(marker) => {
                        skip_after = Some(marker);
                    }
                    FlowOutcome::Continue => {}
                }

                // Handle disruptive action
                if let Some(outcome) = action_result.disruptive {
                    // Only apply if not in detection-only mode
                    let should_block = self.engine_mode() == RuleEngineMode::On;

                    match outcome {
                        DisruptiveOutcome::Deny(status) => {
                            if should_block {
                                let mut intervention = Intervention::deny(status, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Block => {
                            if should_block {
                                let mut intervention = Intervention::deny(self.default_status, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Allow => {
                            self.allowed = true;
                            return Ok(());
                        }
                        DisruptiveOutcome::Redirect(url) => {
                            if should_block {
                                let mut intervention = Intervention::redirect(url, phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Drop => {
                            if should_block {
                                let mut intervention = Intervention::drop(phase, rule.id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Pass => {
                            // Continue processing
                        }
                    }
                }
            } else {
                // Rule didn't match. If it belongs to a chain, the chain as a
                // whole cannot match: drop the starter's held actions and skip
                // past the remaining links so they are never evaluated on
                // their own.
                if chain_state.in_chain || rule.is_chain {
                    chain_state.reset();
                    pending_chain_actions = None;
                    while idx < rules.len() && rules[idx].is_chain {
                        idx += 1;
                    }
                    idx += 1;
                    continue;
                }
            }

            // End chain if this is the last rule in chain
            if chain_state.in_chain && !rule.is_chain {
                chain_state.end_chain();
            }

            idx += 1;
        }

        // Sync anomaly score to TX
        self.anomaly_score.sync_to_tx(&mut self.tx);

        Ok(())
    }

    /// Evaluate a single rule.
    fn evaluate_rule(&self, rule: &CompiledRule) -> Result<(bool, Vec<String>)> {
        let resolver = VariableResolver::new(
            &self.request,
            &self.response,
            &self.tx,
            None,
            &self.matched_vars,
            &self.captures,
        );

        // Resolve variables from all specs.
        //
        // A spec in count mode (`&VAR`) contributes the *number* of matching
        // values as a single value — 0 when the variable is absent — rather than
        // the values themselves. This matches ModSecurity's `&VARIABLE` semantics
        // and is what CRS's `SecRule &TX:x "@eq 0"` initialization relies on.
        // Emitting a value even for an absent count also keeps the spec out of
        // the "resolved to nothing" early-return below, so `&x "@eq 0"` matches.
        // ctl:ruleRemoveTargetById drops individual targets from this rule for
        // this transaction. The check is hoisted so rules with no exclusion --
        // effectively all of them -- pay one comparison rather than a scan per
        // variable.
        let filter_targets = self.controls.has_target_removals(rule.id.as_deref());

        let mut all_values = Vec::new();
        let mut any_excluded = false;
        for spec in &rule.variables {
            let mut resolved = resolver.resolve(spec);
            if filter_targets {
                let before = resolved.len();
                resolved.retain(|(name, _)| {
                    !self
                        .controls
                        .is_target_removed(rule.id.as_deref(), spec, name)
                });
                any_excluded |= resolved.len() != before;
            }
            if spec.count_mode {
                // An exclusion reduces the count, which is what a rule like
                // `SecRule &ARGS:x "@eq 0"` is asking about.
                all_values.push((format!("&{:?}", spec.name), resolved.len().to_string()));
            } else {
                all_values.extend(resolved);
            }
        }

        // Exclusions removed everything this rule had to test. Return before
        // the branch below: a rule stripped down to nothing is not the same as
        // a SecAction with no targets, and running the operator unconditionally
        // could match.
        if any_excluded && all_values.is_empty() {
            return Ok((false, Vec::new()));
        }

        if all_values.is_empty() {
            // A rule with no variable specs at all (i.e. SecAction) runs its
            // operator unconditionally — this is how CRS sets up TX thresholds.
            if rule.variables.is_empty() {
                let result = rule.operator.execute("");
                let matched = if rule.operator_negated { !result.matched } else { result.matched };
                return Ok((matched, result.captures));
            }
            // Variables were specified but resolved to nothing (e.g. absent header).
            return Ok((rule.operator_negated, Vec::new()));
        }

        // If the operator argument references runtime macros (e.g.
        // `@ge %{tx.inbound_anomaly_score_threshold}`), expand them against the
        // current TX state and recompile the operator so the comparison runs
        // against the resolved value. Otherwise use the precompiled operator.
        let dynamic_operator;
        let operator: &dyn Operator = if rule.operator_spec.argument.contains("%{") {
            let expanded = self.expand_operator_macros(&rule.operator_spec.argument);
            dynamic_operator = compile_operator(&OperatorSpec {
                negated: rule.operator_spec.negated,
                name: rule.operator_spec.name,
                argument: expanded,
            })?;
            dynamic_operator.as_ref()
        } else {
            rule.operator.as_ref()
        };

        // Apply transformations and match
        for (_name, value) in all_values {
            let transformed = rule.transformations.apply(&value);
            let result = operator.execute(&transformed);

            let final_match = if rule.operator_negated { !result.matched } else { result.matched };

            if final_match {
                return Ok((true, result.captures));
            }
        }

        Ok((false, Vec::new()))
    }

    /// Expand `%{...}` macros in an operator argument against current TX state.
    ///
    /// Only the `TX`/`tx` collection is resolved (the source of operator-argument
    /// macros in CRS, e.g. thresholds and `tx.allowed_methods`); an unresolved
    /// macro expands to an empty string, matching ModSecurity behaviour.
    fn expand_operator_macros(&self, arg: &str) -> String {
        let re = regex::Regex::new(r"%\{([^}]+)\}").expect("static macro regex is valid");
        re.replace_all(arg, |caps: &regex::Captures| {
            let inner = &caps[1];
            let (collection, name) = match inner.split_once('.') {
                Some((c, n)) => (c.to_ascii_lowercase(), n),
                None => ("tx".to_string(), inner),
            };
            if collection == "tx" {
                self.tx
                    .get(name)
                    .and_then(|v| v.first().map(|s| s.to_string()))
                    .unwrap_or_default()
            } else {
                String::new()
            }
        })
        .into_owned()
    }

    /// Apply a setvar operation.
    fn apply_setvar(&mut self, op: &SetVarOp) {
        // A macro-bearing value (e.g. `+%{tx.critical_anomaly_score}`) is
        // resolved here, where TX state is available, then re-interpreted as a
        // concrete set/increment/decrement.
        if let SetVarOperation::Macro(raw) = &op.operation {
            let expanded = self.expand_operator_macros(raw);
            let resolved = SetVarOp {
                collection: op.collection.clone(),
                name: op.name.clone(),
                operation: interpret_setvar_rhs(&expanded),
            };
            crate::actions::apply_setvar(&mut self.tx, &resolved);
        } else {
            crate::actions::apply_setvar(&mut self.tx, op);
        }

        // Sync anomaly score from TX if relevant
        if op.name == "anomaly_score" {
            self.anomaly_score.sync_from_tx(&self.tx);
        }
    }
}

/// Interpret an already-expanded setvar right-hand side into a concrete
/// operation, honouring a leading `+`/`-` for increment/decrement. An empty or
/// non-numeric increment/decrement (e.g. an unresolved macro) becomes a no-op.
fn interpret_setvar_rhs(value: &str) -> SetVarOperation {
    if let Some(rest) = value.strip_prefix('+') {
        SetVarOperation::Increment(rest.trim().parse().unwrap_or(0))
    } else if let Some(rest) = value.strip_prefix('-') {
        SetVarOperation::Decrement(rest.trim().parse().unwrap_or(0))
    } else {
        SetVarOperation::Set(value.to_string())
    }
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("phase", &self.phase)
            .field("has_intervention", &self.intervention.is_some())
            .field("anomaly_score", &self.anomaly_score.inbound)
            .field("matched_rules", &self.matched_rules)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::Collection;

    fn make_ruleset(rules: &str) -> Arc<CompiledRuleset> {
        Arc::new(CompiledRuleset::from_string(rules).unwrap())
    }

    #[test]
    fn test_basic_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(tx.has_intervention());
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status, 403);
    }

    #[test]
    fn test_no_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/public/index.html", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
    }

    #[test]
    fn test_setvar() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /test" "id:1,phase:1,pass,setvar:TX.score=5"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/test/page", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
        let score = tx.tx().get("score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("5".to_string()));
    }

    #[test]
    fn test_operator_arg_macro_ge_threshold() {
        // @ge with a %{tx.*} argument must compare against the resolved value.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "score 10 >= threshold 5 should block");
    }

    #[test]
    fn test_operator_arg_macro_ge_below_threshold() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=3"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "score 3 < threshold 5 should not block");
    }

    #[test]
    fn test_negated_within_macro_does_not_block_allowed() {
        // Regression for the 911100 case: a negated @within whose argument is a
        // resolvable macro must not block when the value IS in the list.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "GET is allowed, must not block");
    }

    #[test]
    fn test_negated_within_macro_blocks_disallowed() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "POST is not allowed, must block");
    }

    #[test]
    fn test_secaction_sets_tx_and_macro_resolves() {
        // CRS-style: SecAction (no variables) seeds a TX threshold that a later
        // rule's operator macro resolves against.
        let ruleset = make_ruleset(r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let threshold = tx.tx().get("threshold").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(threshold, Some("5".to_string()), "SecAction setvar must apply");
        assert!(tx.has_intervention(), "10 >= 5 should block");
    }

    #[test]
    fn test_request_header_named_selector_matches() {
        // REQUEST_HEADERS:User-Agent must match regardless of header-name case.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", "sqlmap/1.0").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "User-Agent selector should match");
    }

    #[test]
    fn test_setvar_value_macro_accumulates() {
        // CRS-style score accumulation: setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'
        // must add the resolved delta (5), and twice must yield 10.
        let ruleset = make_ruleset(r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
            SecRule REQUEST_URI "@contains /" "id:3,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx.tx().get("anomaly_score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("10".to_string()), "two +5 macro increments should total 10");
    }

    #[test]
    fn test_setvar_value_macro_unresolved_is_noop() {
        // An unresolved macro delta must not silently increment by 1.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.missing}'"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx.tx().get("anomaly_score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("0".to_string()), "unresolved macro increment should be a no-op");
    }

    #[test]
    fn test_detection_only_mode() {
        let ruleset = make_ruleset(r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(Arc::new(
            CompiledRuleset::from_string(r#"
                SecRuleEngine DetectionOnly
                SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            "#).unwrap()
        ), 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        // Should match but not block
        assert!(!tx.has_intervention());
        assert!(tx.matched_rules().contains(&"1".to_string()));
    }
}
