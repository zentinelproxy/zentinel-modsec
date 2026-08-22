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
//! directives this engine does not implement, `ctl:auditLogParts` among
//! them: rejecting those would make CRS unloadable, which is a worse
//! outcome than running it with a known and stated gap.

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
    /// `ctl:requestBodyProcessor=URLENCODED|MULTIPART|JSON|XML`
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
const SUPPORTED_BODY_PROCESSORS: &[&str] = &["URLENCODED", "MULTIPART", "JSON", "XML"];

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
                        "requestBodyProcessor accepts only URLENCODED, MULTIPART, \
                         JSON or XML",
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
    /// `(rule id, parsed target)` pairs from `ctl:ruleRemoveTargetById`.
    ///
    /// The target is parsed once when the directive fires rather than once per
    /// resolved value: a rule over a large collection would otherwise re-parse
    /// the same string thousands of times.
    removed_targets: Vec<(String, VariableSpec)>,
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
                // Parse with the same parser used for rule variables so
                // collection names round-trip: SecLang writes REQUEST_HEADERS
                // where the enum variant renders as RequestHeaders.
                match crate::parser::parse_single_variable(&target) {
                    Ok(spec) => self.removed_targets.push((rule_id, spec)),
                    Err(_) => {
                        let key = format!("ruleRemoveTargetById={rule_id};{target}");
                        if self.reported.insert(key) {
                            tracing::warn!(
                                rule_id = %rule_id,
                                target = %target,
                                "ignoring ctl:ruleRemoveTargetById with an unparseable target"
                            );
                        }
                    }
                }
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

    /// Whether one resolved value was excluded from this rule by
    /// `ctl:ruleRemoveTargetById`.
    ///
    /// Exclusion filters *values*, not variable specifications, because the
    /// shape CRS actually uses is a rule targeting a whole collection with an
    /// exclusion naming one member:
    ///
    /// ```text
    /// SecRule ARGS "@detectSQLi" "id:942100,..."
    /// ctl:ruleRemoveTargetById=942100;ARGS:json.token
    /// ```
    ///
    /// Dropping the spec would remove `ARGS` entirely and disable the rule;
    /// leaving it would exclude nothing. Only removing the one resolved value
    /// named `ARGS:json.token` does what the operator asked.
    ///
    /// `resolved_name` is the name the resolver produced, in `COLLECTION:key`
    /// form for collections and a bare name otherwise.
    pub fn is_target_removed(
        &self,
        rule_id: Option<&str>,
        var: &VariableSpec,
        resolved_name: &str,
    ) -> bool {
        let Some(id) = rule_id else {
            return false;
        };
        self.removed_targets
            .iter()
            .any(|(r, target)| r == id && target_matches_resolved(var, target, resolved_name))
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

/// Whether a resolved value falls under the target named by a `ctl:` argument
/// such as `ARGS:bar` or `REQUEST_HEADERS`.
///
/// The target is parsed with the same parser used for rule variables so
/// collection names round-trip: SecLang writes `REQUEST_HEADERS` where the
/// enum variant renders as `RequestHeaders`, and comparing rendered names
/// would silently never match.
fn target_matches_resolved(var: &VariableSpec, target: &VariableSpec, resolved_name: &str) -> bool {
    if var.name != target.name {
        return false;
    }

    match &target.selection {
        // `ctl:...=ID;ARGS` excludes the whole collection from this rule.
        None => true,
        Some(Selection::Key(wanted)) => {
            // The resolver names collection members `COLLECTION:key`. A bare
            // name means a scalar variable, which a keyed target cannot select.
            let Some((_, key)) = resolved_name.split_once(':') else {
                return false;
            };
            if header_keys_are_case_insensitive(var) {
                key.eq_ignore_ascii_case(wanted.as_str())
            } else {
                key == wanted.as_str()
            }
        }
        // A regex selection in a ctl: target is not something ModSecurity
        // accepts here; refuse rather than guess.
        Some(Selection::Regex(_)) => false,
    }
}

/// Whether member keys of this variable's collection compare case-insensitively.
///
/// Only the HTTP header collections do — the resolver looks those up with a
/// lowercased key. Argument names are case-sensitive in ModSecurity, and
/// matching them loosely would silently widen an exclusion beyond what the
/// operator wrote.
fn header_keys_are_case_insensitive(var: &VariableSpec) -> bool {
    matches!(
        var.name,
        crate::parser::VariableName::RequestHeaders | crate::parser::VariableName::ResponseHeaders
    )
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
        assert!(controls.is_target_removed(Some("1"), &var, "REQUEST_HEADERS:User-Agent"));
        // Same target, different rule.
        assert!(!controls.is_target_removed(Some("2"), &var, "REQUEST_HEADERS:User-Agent"));

        let other = crate::parser::parse_single_variable("REQUEST_HEADERS:Referer").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &other, "REQUEST_HEADERS:Referer"));

        // Header keys are case insensitive.
        assert!(controls.is_target_removed(Some("1"), &var, "REQUEST_HEADERS:user-agent"));
    }

    /// The shape CRS actually uses: the rule targets a whole collection and
    /// the exclusion names one member. Matching on the specification alone
    /// cannot express this -- the spec is `ARGS` either way -- so the resolved
    /// value name is what decides.
    #[test]
    fn a_keyed_target_excludes_one_member_of_a_collection_rule() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "942100;ARGS:json.token",
        )));

        let whole_args = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("942100"), &whole_args, "ARGS:json.token"));
        assert!(!controls.is_target_removed(Some("942100"), &whole_args, "ARGS:json.query"));
    }

    /// Argument names are case sensitive in ModSecurity, unlike header names.
    /// Matching them loosely would widen an exclusion past what was written.
    #[test]
    fn argument_keys_are_matched_case_sensitively() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;ARGS:Token",
        )));

        let args = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("1"), &args, "ARGS:Token"));
        assert!(!controls.is_target_removed(Some("1"), &args, "ARGS:token"));
    }

    /// A keyed target cannot select a scalar variable, which has no members.
    #[test]
    fn a_keyed_target_does_not_match_a_scalar_variable() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl(
            "ruleRemoveTargetById",
            "1;REQUEST_URI:x",
        )));

        let uri = crate::parser::parse_single_variable("REQUEST_URI").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &uri, "REQUEST_URI"));
    }

    #[test]
    fn an_unkeyed_target_excludes_the_whole_collection() {
        let mut controls = TransactionControls::default();
        controls.apply(CtlDirective::parse(&ctl("ruleRemoveTargetById", "1;ARGS")));

        // Naming the collection with no key excludes every member of it, for
        // a rule targeting the collection or any single member.
        let whole = crate::parser::parse_single_variable("ARGS").unwrap();
        assert!(controls.is_target_removed(Some("1"), &whole, "ARGS:token"));
        assert!(controls.is_target_removed(Some("1"), &whole, "ARGS:anything"));

        let keyed = crate::parser::parse_single_variable("ARGS:token").unwrap();
        assert!(controls.is_target_removed(Some("1"), &keyed, "ARGS:token"));

        // A different collection is untouched.
        let cookies = crate::parser::parse_single_variable("REQUEST_COOKIES").unwrap();
        assert!(!controls.is_target_removed(Some("1"), &cookies, "REQUEST_COOKIES:token"));
    }

    #[test]
    fn unimplemented_features_are_reported_not_accepted() {
        // The whole point: a directive this engine cannot honour must not look
        // like it worked.
        for (directive, value) in [
            ("requestBodyProcessor", "YAML"),
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
        for value in [
            "URLENCODED",
            "urlencoded",
            "MULTIPART",
            "JSON",
            "json",
            "XML",
            "xml",
        ] {
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
