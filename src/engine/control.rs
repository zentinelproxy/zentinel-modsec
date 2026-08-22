//! Per-transaction control directives (`ctl:`).
//!
//! `ctl:` actions override engine behaviour for the remainder of one
//! transaction only. They must never mutate the shared compiled ruleset:
//! rulesets are behind an `Arc` and evaluated concurrently, so a rule removed
//! by one request would vanish for every request in flight.
//!
//! State therefore lives on the [`Transaction`](super::transaction::Transaction)
//! in [`TransactionControls`], is consulted during evaluation, and dies with
//! the transaction.
//!
//! Directives this engine cannot honour are reported at load time rather than
//! accepted and quietly dropped — see [`CtlDirective::Unsupported`] and
//! [`unsupported_controls`]. Silently accepting a security directive that does
//! nothing is the failure this module exists to fix, so reintroducing it for
//! the subset that is not implemented would defeat the point.
//!
//! Reporting is a warning rather than a hard error because CRS ships
//! `ctl:requestBodyProcessor=JSON` and `ctl:auditLogParts`: rejecting those
//! would make CRS unloadable, which is a worse outcome than running it with a
//! known and stated gap.

use std::collections::HashSet;

use crate::parser::{ControlAction, Selection, VariableSpec};

use super::ruleset::RuleEngineMode;

/// An inclusive range of rule IDs, as written by `ctl:ruleRemoveById`.
///
/// ModSecurity accepts both a single ID and a `start-end` range; a single ID
/// is stored as a range whose ends are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIdRange {
    start: u64,
    end: u64,
}

impl RuleIdRange {
    fn contains(&self, id: &str) -> bool {
        match id.trim().parse::<u64>() {
            Ok(n) => n >= self.start && n <= self.end,
            // Non-numeric rule IDs are legal in SecLang but cannot fall inside
            // a numeric range.
            Err(_) => false,
        }
    }
}

/// A parsed `ctl:` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtlDirective {
    /// `ctl:ruleEngine=On|Off|DetectionOnly`
    RuleEngine(RuleEngineMode),
    /// `ctl:ruleRemoveById=ID` or `=START-END`, or several separated by commas.
    RuleRemoveById(Vec<RuleIdRange>),
    /// `ctl:ruleRemoveTargetById=ID;TARGET`
    RuleRemoveTargetById {
        /// ID of the rule the exclusion applies to.
        rule_id: String,
        /// Target to drop from that rule, e.g. `ARGS:token`.
        target: String,
    },
    /// `ctl:requestBodyAccess=On|Off`
    RequestBodyAccess(bool),
    /// `ctl:requestBodyProcessor=URLENCODED|MULTIPART`
    RequestBodyProcessor(String),
    /// A directive this engine does not implement.
    ///
    /// Kept as a distinct variant so it can be reported rather than discarded.
    Unsupported {
        /// The directive name as written.
        directive: String,
        /// The value as written, empty if the directive had none.
        value: String,
        /// Why this engine cannot honour it, for the operator-facing warning.
        reason: &'static str,
    },
}

/// Body processors this engine can actually run.
///
/// `JSON` and `XML` are deliberately absent: no parser for either exists yet,
/// so accepting them would leave request bodies unexamined while the config
/// claims otherwise. CRS sets `ctl:requestBodyProcessor=JSON` from
/// `Content-Type` in phase 1, so this is a real gap, not a hypothetical one.
const SUPPORTED_BODY_PROCESSORS: &[&str] = &["URLENCODED", "MULTIPART"];

impl CtlDirective {
    /// Interpret a parsed `ctl:` action.
    ///
    /// Never fails: anything unrecognised becomes [`CtlDirective::Unsupported`]
    /// carrying the reason, so the caller decides whether to warn or reject.
    pub fn parse(action: &ControlAction) -> Self {
        let directive = action.directive.trim();
        let value = action.value.trim();

        match directive.to_ascii_lowercase().as_str() {
            "ruleengine" => match value.to_ascii_lowercase().as_str() {
                "on" => CtlDirective::RuleEngine(RuleEngineMode::On),
                "off" => CtlDirective::RuleEngine(RuleEngineMode::Off),
                "detectiononly" => CtlDirective::RuleEngine(RuleEngineMode::DetectionOnly),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleEngine accepts only On, Off or DetectionOnly",
                ),
            },

            "ruleremovebyid" => match parse_id_ranges(value) {
                Some(ranges) if !ranges.is_empty() => CtlDirective::RuleRemoveById(ranges),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleRemoveById expects a rule ID or an ID range such as 942100-942999",
                ),
            },

            "ruleremovetargetbyid" => match value.split_once(';') {
                Some((rule_id, target))
                    if !rule_id.trim().is_empty() && !target.trim().is_empty() =>
                {
                    CtlDirective::RuleRemoveTargetById {
                        rule_id: rule_id.trim().to_string(),
                        target: target.trim().to_string(),
                    }
                }
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "ruleRemoveTargetById expects ID;TARGET, for example 942100;ARGS:token",
                ),
            },

            "requestbodyaccess" => match value.to_ascii_lowercase().as_str() {
                "on" => CtlDirective::RequestBodyAccess(true),
                "off" => CtlDirective::RequestBodyAccess(false),
                _ => CtlDirective::unsupported(
                    directive,
                    value,
                    "requestBodyAccess accepts only On or Off",
                ),
            },

            "requestbodyprocessor" => {
                let upper = value.to_ascii_uppercase();
                if SUPPORTED_BODY_PROCESSORS.contains(&upper.as_str()) {
                    CtlDirective::RequestBodyProcessor(upper)
                } else {
                    CtlDirective::unsupported(
                        directive,
                        value,
                        "this engine implements only the URLENCODED and MULTIPART body \
                         processors; JSON and XML bodies would go unexamined",
                    )
                }
            }

            "auditengine" | "auditlogparts" => CtlDirective::unsupported(
                directive,
                value,
                "this engine has no audit log subsystem, so there is nothing to control",
            ),

            _ => CtlDirective::unsupported(directive, value, "unrecognised ctl directive"),
        }
    }

    fn unsupported(directive: &str, value: &str, reason: &'static str) -> Self {
        CtlDirective::Unsupported {
            directive: directive.to_string(),
            value: value.to_string(),
            reason,
        }
    }
}

/// Parse `942100`, `942100-942999`, or a comma-separated mix of the two.
fn parse_id_ranges(value: &str) -> Option<Vec<RuleIdRange>> {
    let mut ranges = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Rule IDs are unsigned, so a '-' can only be a range separator.
        let range = match part.split_once('-') {
            Some((start, end)) => {
                let start: u64 = start.trim().parse().ok()?;
                let end: u64 = end.trim().parse().ok()?;
                if start > end {
                    return None;
                }
                RuleIdRange { start, end }
            }
            None => {
                let id: u64 = part.parse().ok()?;
                RuleIdRange { start: id, end: id }
            }
        };
        ranges.push(range);
    }
    Some(ranges)
}

/// Control state accumulated over the life of one transaction.
///
/// Every field is an override: `None`/empty means "defer to the ruleset".
#[derive(Debug, Default, Clone)]
pub struct TransactionControls {
    engine_mode: Option<RuleEngineMode>,
    removed_rules: Vec<RuleIdRange>,
    /// `(rule id, target)` pairs from `ctl:ruleRemoveTargetById`.
    removed_targets: Vec<(String, String)>,
    request_body_access: Option<bool>,
    request_body_processor: Option<String>,
    /// Unsupported directives already reported, so a rule that fires on every
    /// request does not produce a warning per request.
    reported: HashSet<String>,
}

impl TransactionControls {
    /// Apply a directive to this transaction.
    ///
    /// Later directives win over earlier ones for single-valued settings;
    /// removals accumulate, since `ctl:ruleRemoveById` is additive in
    /// ModSecurity.
    pub fn apply(&mut self, directive: CtlDirective) {
        match directive {
            CtlDirective::RuleEngine(mode) => self.engine_mode = Some(mode),
            CtlDirective::RuleRemoveById(mut ranges) => self.removed_rules.append(&mut ranges),
            CtlDirective::RuleRemoveTargetById { rule_id, target } => {
                self.removed_targets.push((rule_id, target))
            }
            CtlDirective::RequestBodyAccess(on) => self.request_body_access = Some(on),
            CtlDirective::RequestBodyProcessor(p) => self.request_body_processor = Some(p),
            CtlDirective::Unsupported {
                directive,
                value,
                reason,
            } => {
                // Compile-time validation already rejected these for rulesets
                // loaded through the normal path. Reaching here means a ruleset
                // was built some other way, so say so once rather than
                // pretending the directive took effect.
                let key = format!("{directive}={value}");
                if self.reported.insert(key) {
                    tracing::warn!(
                        directive = %directive,
                        value = %value,
                        reason = %reason,
                        "ignoring unsupported ctl directive"
                    );
                }
            }
        }
    }

    /// Engine mode for this transaction, given the ruleset's configured mode.
    pub fn engine_mode(&self, ruleset_mode: RuleEngineMode) -> RuleEngineMode {
        self.engine_mode.unwrap_or(ruleset_mode)
    }

    /// Whether `ctl:ruleRemoveById` has excluded this rule.
    pub fn is_rule_removed(&self, rule_id: Option<&str>) -> bool {
        let Some(id) = rule_id else {
            // A rule with no ID cannot be named by ruleRemoveById.
            return false;
        };
        self.removed_rules.iter().any(|r| r.contains(id))
    }

    /// Whether any target exclusion applies to this rule.
    ///
    /// Checked before the per-variable filter so the common case -- no
    /// exclusions at all -- costs one comparison rather than a scan per
    /// variable.
    pub fn has_target_removals(&self, rule_id: Option<&str>) -> bool {
        match rule_id {
            Some(id) => self.removed_targets.iter().any(|(r, _)| r == id),
            None => false,
        }
    }

    /// Whether this variable was excluded from this rule by
    /// `ctl:ruleRemoveTargetById`.
    pub fn is_target_removed(&self, rule_id: Option<&str>, var: &VariableSpec) -> bool {
        let Some(id) = rule_id else {
            return false;
        };
        self.removed_targets
            .iter()
            .any(|(r, target)| r == id && variable_matches_target(var, target))
    }

    /// Whether the request body should be parsed at all.
    pub fn request_body_access(&self) -> bool {
        self.request_body_access.unwrap_or(true)
    }

    /// Body processor forced by `ctl:requestBodyProcessor`, if any.
    pub fn request_body_processor(&self) -> Option<&str> {
        self.request_body_processor.as_deref()
    }
}

/// Whether a rule variable refers to the target named by a `ctl:` argument
/// such as `ARGS:bar` or `REQUEST_HEADERS`.
///
/// Parses the target with the same parser used for rule variables so
/// collection names round-trip: SecLang writes `REQUEST_HEADERS` where the
/// enum variant renders as `RequestHeaders`, and comparing rendered names
/// would silently never match.
fn variable_matches_target(var: &VariableSpec, target: &str) -> bool {
    let Ok(parsed) = crate::parser::parse_single_variable(target) else {
        return false;
    };
    if var.name != parsed.name {
        return false;
    }
    match (&var.selection, &parsed.selection) {
        (None, None) => true,
        (Some(Selection::Key(existing)), Some(Selection::Key(wanted))) => {
            existing.eq_ignore_ascii_case(wanted.as_str())
        }
        // A rule targeting the whole collection is not excluded by a directive
        // naming one key, and vice versa.
        _ => false,
    }
}

/// Collect the unsupported `ctl:` directives in a set of actions.
///
/// Used at ruleset compile time so an operator learns at startup that a
/// directive will not take effect, rather than discovering it from a
/// bypassed rule in production.
pub fn unsupported_controls(
    actions: &[crate::parser::Action],
) -> Vec<(String, String, &'static str)> {
    let mut found = Vec::new();
    for action in actions {
        if let crate::parser::Action::Control(ctl) = action {
            if let CtlDirective::Unsupported {
                directive,
                value,
                reason,
            } = CtlDirective::parse(ctl)
            {
                found.push((directive, value, reason));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(directive: &str, value: &str) -> ControlAction {
        ControlAction {
            directive: directive.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn rule_engine_values_are_case_insensitive() {
        for (value, expected) in [
            ("Off", RuleEngineMode::Off),
            ("off", RuleEngineMode::Off),
            ("On", RuleEngineMode::On),
            ("DetectionOnly", RuleEngineMode::DetectionOnly),
            ("detectiononly", RuleEngineMode::DetectionOnly),
        ] {
            assert_eq!(
                CtlDirective::parse(&ctl("ruleEngine", value)),
                CtlDirective::RuleEngine(expected),
                "ruleEngine={value}"
            );
        }
    }

    #[test]
    fn directive_names_are_case_insensitive() {
        // CRS writes ctl:ruleRemoveById, but SecLang is not case sensitive here.
        assert!(matches!(
            CtlDirective::parse(&ctl("RULEREMOVEBYID", "1")),
            CtlDirective::RuleRemoveById(_)
        ));
    }

    #[test]
    fn single_ids_ranges_and_lists_all_parse() {
        let single = CtlDirective::parse(&ctl("ruleRemoveById", "942100"));
        assert_eq!(
            single,
            CtlDirective::RuleRemoveById(vec![RuleIdRange {
                start: 942100,
                end: 942100
            }])
        );

        let range = CtlDirective::parse(&ctl("ruleRemoveById", "942100-942999"));
        assert_eq!(
            range,
            CtlDirective::RuleRemoveById(vec![RuleIdRange {
                start: 942100,
                end: 942999
            }])
        );

        let list = CtlDirective::parse(&ctl("ruleRemoveById", "1,5-7"));
        assert_eq!(
            list,
            CtlDirective::RuleRemoveById(vec![
                RuleIdRange { start: 1, end: 1 },
                RuleIdRange { start: 5, end: 7 },
            ])
        );
    }

    #[test]
    fn an_inverted_range_is_rejected_rather_than_silently_empty() {
        // 999-1 matching nothing would look identical to a working exclusion.
        assert!(matches!(
            CtlDirective::parse(&ctl("ruleRemoveById", "999-1")),
            CtlDirective::Unsupported { .. }
        ));
    }

    #[test]
    fn ranges_match_ids_by_number_not_string() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "942100-942999")));

        assert!(controls.is_rule_removed(Some("942100")));
        assert!(controls.is_rule_removed(Some("942500")));
        assert!(controls.is_rule_removed(Some("942999")));
        assert!(!controls.is_rule_removed(Some("943000")));
        // String comparison would place "9421000" inside the range.
        assert!(!controls.is_rule_removed(Some("9421000")));
        assert!(!controls.is_rule_removed(None));
    }

    #[test]
    fn removals_accumulate_but_engine_mode_is_replaced() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "1")));
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveById", "2")));
        assert!(controls.is_rule_removed(Some("1")));
        assert!(controls.is_rule_removed(Some("2")));

        controls.apply(CtlDirective::parse(&ctl("ruleEngine", "Off")));
        controls.apply(CtlDirective::parse(&ctl("ruleEngine", "DetectionOnly")));
        assert_eq!(
            controls.engine_mode(RuleEngineMode::On),
            RuleEngineMode::DetectionOnly
        );
    }

    #[test]
    fn engine_mode_defers_to_the_ruleset_when_unset() {
        let controls = TransactionControls::default();
        assert_eq!(
            controls.engine_mode(RuleEngineMode::DetectionOnly),
            RuleEngineMode::DetectionOnly
        );
    }

    #[test]
    fn remove_target_requires_both_halves() {
        assert_eq!(
            CtlDirective::parse(&ctl("ruleRemoveTargetById", "942100;ARGS:token")),
            CtlDirective::RuleRemoveTargetById {
                rule_id: "942100".to_string(),
                target: "ARGS:token".to_string(),
            }
        );
        for bad in ["942100", "942100;", ";ARGS:token", ""] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl("ruleRemoveTargetById", bad)),
                    CtlDirective::Unsupported { .. }
                ),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn target_matching_uses_seclang_names() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;REQUEST_HEADERS:User-Agent",
        )));

        let var = crate::parser::parse_single_variable("REQUEST_HEADERS:User-Agent").unwrap();
        assert!(controls.is_target_removed(Some("1"), &var));
        // Same target, different rule.
        assert!(!controls.is_target_removed(Some("2"), &var));

        let other = crate::parser::parse_single_variable("REQUEST_HEADERS:Referer").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &other));

        // Header keys are case insensitive.
        let cased = crate::parser::parse_single_variable("REQUEST_HEADERS:user-agent").unwrap();
        assert!(controls.is_target_removed(Some("1"), &cased));
    }

    #[test]
    fn a_whole_collection_target_does_not_match_a_keyed_variable() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveTargetById", "1;ARGS")));

        let keyed = crate::parser::parse_single_variable("ARGS:token").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &keyed));

        let whole = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("1"), &whole));
    }

    #[test]
    fn unimplemented_features_are_reported_not_accepted() {
        // The whole point: a directive this engine cannot honour must not look
        // like it worked.
        for (directive, value) in [
            ("requestBodyProcessor", "JSON"),
            ("requestBodyProcessor", "XML"),
            ("auditEngine", "Off"),
            ("auditLogParts", "+E"),
            ("forceRequestBodyVariable", "On"),
        ] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl(directive, value)),
                    CtlDirective::Unsupported { .. }
                ),
                "ctl:{directive}={value} should be reported as unsupported"
            );
        }
    }

    #[test]
    fn implemented_body_processors_are_accepted() {
        for value in ["URLENCODED", "urlencoded", "MULTIPART"] {
            assert!(
                matches!(
                    CtlDirective::parse(&ctl("requestBodyProcessor", value)),
                    CtlDirective::RequestBodyProcessor(_)
                ),
                "ctl:requestBodyProcessor={value} should be accepted"
            );
        }
    }

    #[test]
    fn body_access_defaults_to_on() {
        let mut controls = TransactionControls::default();
        assert!(controls.request_body_access());

        controls.apply(CtlDirective::parse(&ctl("requestBodyAccess", "Off")));
        assert!(!controls.request_body_access());
    }
}
