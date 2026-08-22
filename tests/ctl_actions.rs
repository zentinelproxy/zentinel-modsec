//! Tests for `ctl:` per-transaction control directives.
//!
//! `ctl:` actions parsed cleanly and were then discarded — `execute_actions`
//! matched `Action::Control(_)` with the comment "handled elsewhere", and
//! nowhere else referenced it. A config using `ctl:` looked supported and had
//! no effect.
//!
//! The consequence runs both ways, which is what makes this worth testing in
//! both directions: `ctl:ruleRemoveById` silently *not* suppressing a rule
//! causes false positives, while `ctl:ruleEngine=Off` silently not applying
//! means rules run where an operator expected them not to.
//!
//! Reported as zentinelproxy/zentinel-modsec#19, from the CRS compatibility
//! audit in zentinelproxy/zentinel#340.

use std::sync::Arc;

use zentinel_modsec::ModSecurity;

fn engine(rules: &str) -> ModSecurity {
    ModSecurity::from_string(rules).expect("rules should load")
}

/// Run one request through its own transaction.
fn blocked_on(msc: &ModSecurity, uri: &str) -> bool {
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn blocked(rules: &str, uri: &str) -> bool {
    blocked_on(&engine(rules), uri)
}

/// Which rule IDs matched, regardless of whether they blocked.
fn matched_rules(rules: &str, uri: &str) -> Vec<String> {
    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

// ---------------------------------------------------------------------------
// The two cases reported in the issue, verbatim.
// ---------------------------------------------------------------------------

#[test]
fn rule_remove_by_id_suppresses_the_named_rule() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny\"";

    assert!(
        !blocked(rules, "/"),
        "rule 2 was removed for this transaction and must not block"
    );
}

#[test]
fn rule_engine_off_stops_evaluation_for_the_transaction() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny\"";

    assert!(
        !blocked(rules, "/"),
        "the engine was switched off before rule 2 was reached"
    );
}

/// The control cases: without the `ctl:`, both of the above block. If these
/// fail, the tests above prove nothing.
#[test]
fn the_same_rules_block_without_the_ctl_action() {
    let remove = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny\"";
    assert!(blocked(remove, "/"), "rule 2 should block when not removed");
}

// ---------------------------------------------------------------------------
// Scope: a transaction's overrides must not touch the shared ruleset.
// ---------------------------------------------------------------------------

/// The invariant that makes this safe to ship.
///
/// The ruleset sits behind an `Arc` and is evaluated by many transactions at
/// once. If `ctl:ruleRemoveById` mutated it, one request carrying that action
/// would disable the rule for every other request in flight — a request-driven
/// WAF bypass. This asserts the override dies with its transaction.
#[test]
fn controls_do_not_leak_into_other_transactions() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /disable\" \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\n\
         SecRule REQUEST_URI \"@contains /attack\" \"id:2,phase:1,deny\"";

    let msc = engine(rules);

    // A request that both triggers the exclusion and would otherwise be blocked.
    assert!(
        !blocked_on(&msc, "/disable/attack"),
        "the exclusion should apply within its own transaction"
    );

    // A later, unrelated request must still be blocked by rule 2.
    assert!(
        blocked_on(&msc, "/attack"),
        "rule 2 must still be active for transactions that did not remove it"
    );

    // And the order does not matter: a plain request first, then the exclusion.
    let msc = engine(rules);
    assert!(blocked_on(&msc, "/attack"));
    assert!(!blocked_on(&msc, "/disable/attack"));
    assert!(blocked_on(&msc, "/attack"));
}

/// Concurrent proof of the same property. A shared ruleset is the normal
/// deployment shape, so the exclusion must be invisible to a parallel request.
#[test]
fn controls_are_isolated_across_threads() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /disable\" \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\n\
         SecRule REQUEST_URI \"@contains /attack\" \"id:2,phase:1,deny\"";
    let msc = Arc::new(engine(rules));

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let msc = Arc::clone(&msc);
            std::thread::spawn(move || {
                if i % 2 == 0 {
                    // Removes rule 2 for itself only.
                    assert!(!blocked_on(&msc, "/disable/attack"));
                } else {
                    assert!(blocked_on(&msc, "/attack"));
                }
            })
        })
        .collect();

    for h in handles {
        h.join()
            .expect("no thread should observe another's controls");
    }
}

// ---------------------------------------------------------------------------
// ruleRemoveById details
// ---------------------------------------------------------------------------

#[test]
fn rule_remove_by_id_accepts_a_range() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=942100-942999\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:942500,phase:1,deny\"";

    assert!(!blocked(rules, "/"), "942500 falls inside 942100-942999");
}

#[test]
fn a_range_does_not_remove_rules_outside_it() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=942100-942999\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:943000,phase:1,deny\"";

    assert!(blocked(rules, "/"), "943000 is outside the range");
}

#[test]
fn removal_persists_into_later_phases() {
    // Set in phase 1, applies to a phase 2 rule.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:2,deny\"";

    assert!(!blocked(rules, "/"), "a phase 1 ctl: governs phase 2 rules");
}

#[test]
fn removing_a_chain_starter_removes_the_whole_chain() {
    // The continuation carries no id of its own, so it can only be excluded
    // along with its starter. Left behind, it would be evaluated alone.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveById=2\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny,chain\"\n\
         SecRule REQUEST_METHOD \"@streq GET\"";

    assert!(!blocked(rules, "/"), "the chain was removed in full");
}

// ---------------------------------------------------------------------------
// ruleEngine details
// ---------------------------------------------------------------------------

#[test]
fn detection_only_still_matches_but_does_not_block() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny\"";

    assert!(!blocked(rules, "/"), "DetectionOnly must not block");
    assert!(
        matched_rules(rules, "/").contains(&"2".to_string()),
        "DetectionOnly must still evaluate and record the match"
    );
}

#[test]
fn rule_engine_off_takes_effect_within_the_same_phase() {
    // Rule 2 sits between the switch-off and rule 3, in the same phase.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,pass\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:3,phase:1,deny\"";

    assert!(!blocked(rules, "/"));
    // Rule 1 is the SecAction itself, which necessarily matched in order to
    // apply the ctl:. Nothing after it should have been evaluated.
    let matched = matched_rules(rules, "/");
    assert_eq!(
        matched,
        vec!["1".to_string()],
        "only the switching rule itself should appear, got {matched:?}"
    );
}

#[test]
fn rule_engine_can_be_switched_back_on() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n\
         SecAction \"id:2,phase:1,pass,nolog,ctl:ruleEngine=On\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:3,phase:1,deny\"";

    assert!(blocked(rules, "/"), "the later ctl: should win");
}

// ---------------------------------------------------------------------------
// ruleRemoveTargetById
// ---------------------------------------------------------------------------

#[test]
fn remove_target_excludes_only_the_named_target() {
    // Rule 2 inspects two headers; only User-Agent is excluded, so a match in
    // Referer must still block.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;REQUEST_HEADERS:User-Agent\"\n\
         SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer \"@contains evil\" \"id:2,phase:1,deny\"";

    let msc = engine(rules);

    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("User-Agent", "evil").unwrap();
    tx.process_request_headers().unwrap();
    assert!(
        !tx.has_intervention(),
        "User-Agent was excluded from rule 2"
    );

    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Referer", "evil").unwrap();
    tx.process_request_headers().unwrap();
    assert!(
        tx.has_intervention(),
        "Referer was not excluded and must still block"
    );
}

#[test]
fn removing_every_target_leaves_nothing_to_match() {
    // A rule stripped of all its targets must not fall through to running its
    // operator unconditionally, which is how SecAction behaves.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;REQUEST_URI\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,deny\"";

    assert!(!blocked(rules, "/"));
}

/// An excluded target is not the same as an absent one, and the difference
/// matters for negated operators.
///
/// A rule whose variable resolves to nothing matches when its operator is
/// negated -- `!@rx foo` against an absent header is "does not contain foo",
/// which is true. If exclusion reused that path, `ctl:ruleRemoveTargetById`
/// against a negated rule would make it *start* blocking: the exact opposite
/// of what excluding a target means.
#[test]
fn excluding_a_target_from_a_negated_rule_does_not_make_it_match() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;REQUEST_HEADERS:X-Token\"\n\
         SecRule REQUEST_HEADERS:X-Token \"!@rx ^expected$\" \"id:2,phase:1,deny\"";

    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("X-Token", "wrong").unwrap();
    tx.process_request_headers().unwrap();

    assert!(
        !tx.has_intervention(),
        "excluding the only target must silence the rule, not trigger it"
    );
}

/// The counterpart, to show the rule is otherwise live: with no exclusion the
/// same request blocks.
#[test]
fn the_negated_rule_blocks_when_its_target_is_not_excluded() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_HEADERS:X-Token \"!@rx ^expected$\" \"id:2,phase:1,deny\"";

    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("X-Token", "wrong").unwrap();
    tx.process_request_headers().unwrap();

    assert!(tx.has_intervention());
}

#[test]
fn remove_target_applies_only_to_the_named_rule() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=2;REQUEST_URI\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:3,phase:1,deny\"";

    assert!(
        blocked(rules, "/"),
        "rule 3 was not named and is unaffected"
    );
}

// ---------------------------------------------------------------------------
// Request body controls
// ---------------------------------------------------------------------------

#[test]
fn request_body_access_off_suppresses_body_arguments() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyAccess=Off\"\n\
         SecRule ARGS_POST:q \"@contains evil\" \"id:2,phase:2,deny\"";

    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"q=evil").unwrap();
    tx.process_request_body().unwrap();

    assert!(
        !tx.has_intervention(),
        "with body access off there are no ARGS_POST to match"
    );
}

#[test]
fn request_body_access_defaults_to_on() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS_POST:q \"@contains evil\" \"id:2,phase:2,deny\"";

    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"q=evil").unwrap();
    tx.process_request_body().unwrap();

    assert!(
        tx.has_intervention(),
        "without the ctl: the body is parsed as usual"
    );
}

#[test]
fn forced_urlencoded_processor_parses_a_body_with_no_content_type() {
    // The point of forcing a processor: the header is absent, so sniffing
    // would extract nothing.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED\"\n\
         SecRule ARGS_POST:q \"@contains evil\" \"id:2,phase:2,deny\"";

    let msc = engine(rules);
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"q=evil").unwrap();
    tx.process_request_body().unwrap();

    assert!(
        tx.has_intervention(),
        "the forced processor should have extracted ARGS_POST"
    );
}

// ---------------------------------------------------------------------------
// Unsupported directives
// ---------------------------------------------------------------------------

/// A `ctl:` this engine cannot honour must not break rule loading.
///
/// CRS ships `ctl:requestBodyProcessor=JSON` and `ctl:auditLogParts`, so
/// rejecting them would make CRS unloadable. They are reported at load time
/// instead; what matters here is that the rest of the rule still works.
#[test]
fn an_unsupported_ctl_does_not_prevent_rules_from_loading() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         SecRule REQUEST_URI \"@contains /attack\" \"id:2,phase:1,deny\"";

    assert!(blocked(rules, "/attack"), "rule 2 must still be enforced");
    assert!(!blocked(rules, "/safe"));
}

#[test]
fn an_unsupported_ctl_does_not_disable_the_engine() {
    // A directive that cannot be honoured must fail closed: rules keep running.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:auditEngine=Off\"\n\
         SecAction \"id:2,phase:1,pass,nolog,ctl:someFutureThing=42\"\n\
         SecRule REQUEST_URI \"@contains /attack\" \"id:3,phase:1,deny\"";

    assert!(blocked(rules, "/attack"));
}
