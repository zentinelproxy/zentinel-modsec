//! Tests for `chain` semantics.
//!
//! A chain is one logical rule: its actions live on the starter and must fire
//! only when *every* link matches. Two bugs broke that.
//!
//! 1. The starter's disruptive action executed as soon as the starter's own
//!    condition matched, without waiting for the rest of the chain — so a
//!    chained CRS rule blocked on a partial match (false positive).
//! 2. Continuation rules carry no `phase` action, and the phase was derived
//!    per-rule, defaulting to phase 2. A chain starting in phase 1 therefore
//!    had its continuation filed under a different phase, leaving the chain
//!    permanently incomplete and the continuation evaluable on its own.
//!
//! Reported as part of zentinelproxy/zentinel#340.

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, uri: &str, method: &str) -> bool {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

/// Blocks only a GET of an admin path — both conditions required.
const CHAIN: &str = "SecRuleEngine On\n\
     SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,chain\"\n\
     SecRule REQUEST_METHOD \"@streq GET\"";

#[test]
fn chain_blocks_when_every_link_matches() {
    assert!(blocked(CHAIN, "/admin", "GET"));
}

#[test]
fn chain_does_not_block_when_a_later_link_fails() {
    // The starter matches (/admin) but the method does not. Before the fix
    // this blocked anyway, which is how a chained CRS rule produces a false
    // positive.
    assert!(!blocked(CHAIN, "/admin", "POST"));
}

#[test]
fn chain_does_not_block_when_the_starter_fails() {
    assert!(!blocked(CHAIN, "/public", "GET"));
}

#[test]
fn continuation_is_not_evaluated_as_a_standalone_rule() {
    // If the starter fails, the continuation must be skipped entirely rather
    // than evaluated on its own. Here the continuation would match any GET.
    assert!(!blocked(CHAIN, "/public", "GET"));
}

#[test]
fn three_link_chain_requires_all_three() {
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,chain\"\n\
         SecRule REQUEST_METHOD \"@streq GET\" \"chain\"\n\
         SecRule REQUEST_HEADERS:Host \"@streq example.com\"";

    assert!(blocked(rules, "/admin", "GET"));
    assert!(!blocked(rules, "/admin", "POST"));
    assert!(!blocked(rules, "/public", "GET"));
}

#[test]
fn setvar_on_the_starter_only_applies_when_the_chain_completes() {
    // The starter sets an anomaly score; a later rule denies on that score.
    // A partial chain match must leave the score untouched.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,pass,nolog,setvar:tx.score=5,chain\"\n\
         SecRule REQUEST_METHOD \"@streq GET\"\n\
         SecRule TX:score \"@ge 5\" \"id:2,phase:1,deny\"";

    assert!(blocked(rules, "/admin", "GET"), "complete chain should set the score");
    assert!(
        !blocked(rules, "/admin", "POST"),
        "partial chain match must not apply the starter's setvar"
    );
}

#[test]
fn rules_after_a_failed_chain_still_run() {
    // Skipping a failed chain's links must not skip past unrelated rules.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,chain\"\n\
         SecRule REQUEST_METHOD \"@streq POST\"\n\
         SecRule REQUEST_URI \"@contains admin\" \"id:2,phase:1,deny\"";

    // The chain fails on the method, but rule 2 still matches and blocks.
    assert!(blocked(rules, "/admin", "GET"));
}
