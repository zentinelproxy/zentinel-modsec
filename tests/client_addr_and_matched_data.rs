//! Tests for client/server address variables and matched-variable reporting.
//!
//! Four things parsed to valid variable names and then resolved to nothing,
//! for the same underlying reason: no caller could populate them, or nothing
//! ever wrote them.
//!
//! - `REMOTE_ADDR` / `REMOTE_PORT` read fields on `RequestData` that
//!   `Transaction` exposed no setter for, so they were always empty. Every
//!   IP-based rule — `@ipMatch`, CRS IP reputation, allow and deny lists —
//!   evaluated against an empty string and could never match.
//! - `SERVER_ADDR` had no resolver arm at all.
//! - `MATCHED_VAR` / `MATCHED_VARS` read a field that was declared,
//!   initialised, passed to the resolver, and never written.
//! - `MATCHED_VAR_NAME` / `MATCHED_VARS_NAMES` had no resolver arm.
//!
//! Part of zentinelproxy/zentinel#340.

use zentinel_modsec::ModSecurity;

/// Run a request with a client address set, returning whether it was blocked.
fn blocked_from(rules: &str, client_ip: &str, client_port: u16) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.set_client_addr(client_ip, client_port);
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

// ---------------------------------------------------------------------------
// Client and server address
// ---------------------------------------------------------------------------

#[test]
fn remote_addr_can_be_matched_with_ipmatch() {
    // The rule an operator would actually write for an internal-only endpoint.
    let rules = "SecRuleEngine On\n\
         SecRule REMOTE_ADDR \"!@ipMatch 10.0.0.0/8\" \"id:1,phase:1,deny\"";

    assert!(
        !blocked_from(rules, "10.1.2.3", 4000),
        "an address inside the allowed range must pass"
    );
    assert!(
        blocked_from(rules, "203.0.113.7", 4000),
        "an address outside it must be blocked"
    );
}

#[test]
fn remote_addr_is_matched_exactly() {
    let rules = "SecRuleEngine On\n\
         SecRule REMOTE_ADDR \"@streq 192.0.2.1\" \"id:1,phase:1,deny\"";

    assert!(blocked_from(rules, "192.0.2.1", 1234));
    assert!(!blocked_from(rules, "192.0.2.2", 1234));
}

#[test]
fn remote_port_is_available() {
    let rules = "SecRuleEngine On\n\
         SecRule REMOTE_PORT \"@eq 8443\" \"id:1,phase:1,deny\"";

    assert!(blocked_from(rules, "192.0.2.1", 8443));
    assert!(!blocked_from(rules, "192.0.2.1", 443));
}

/// Without a client address set, an IP rule must not match rather than
/// matching an empty string by accident.
#[test]
fn an_unset_client_address_does_not_match_an_ip_rule() {
    let rules = "SecRuleEngine On\n\
         SecRule REMOTE_ADDR \"@ipMatch 10.0.0.0/8\" \"id:1,phase:1,deny\"";

    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();

    assert!(!tx.has_intervention());
}

#[test]
fn server_addr_port_and_name_are_available() {
    let rules = "SecRuleEngine On\n\
         SecRule SERVER_ADDR \"@streq 198.51.100.9\" \"id:1,phase:1,pass,nolog,setvar:tx.a=1\"\n\
         SecRule SERVER_PORT \"@eq 8080\" \"id:2,phase:1,pass,nolog,setvar:tx.b=1\"\n\
         SecRule SERVER_NAME \"@streq edge-1\" \"id:3,phase:1,pass,nolog,setvar:tx.c=1\"\n\
         SecRule TX:a \"@streq 1\" \"id:4,phase:1,chain,deny\"\n\
         SecRule TX:b \"@streq 1\" \"chain\"\n\
         SecRule TX:c \"@streq 1\"";

    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.set_server_addr("198.51.100.9", 8080);
    tx.set_server_name("edge-1");
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();

    assert!(
        tx.has_intervention(),
        "all three server variables should have resolved"
    );
}

// ---------------------------------------------------------------------------
// Matched variables
// ---------------------------------------------------------------------------

fn transaction_matching_uri(rules: &str, uri: &str) -> zentinel_modsec::Transaction {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

/// The gap this closes: `matched_rules()` says a rule fired, which is not
/// enough to tell a true positive from a false one.
#[test]
fn matched_data_reports_the_variable_and_value() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:q \"@contains evil\" \"id:942100,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/search?q=something-evil-here");

    assert!(tx.has_intervention());
    let data = tx.matched_data();
    assert_eq!(data.len(), 1, "one match expected, got {data:?}");
    assert_eq!(data[0].rule_id.as_deref(), Some("942100"));
    assert_eq!(data[0].variable, "ARGS:q");
    // The variable's value, matching what MATCHED_VAR resolves to...
    assert_eq!(data[0].value, "something-evil-here");
    // ...and separately the portion the operator actually hit.
    assert_eq!(data[0].matched_portion.as_deref(), Some("evil"));
}

#[test]
fn matched_data_names_the_specific_collection_member() {
    // The rule targets the whole collection; the report must say which member
    // matched, not just "ARGS".
    let rules = "SecRuleEngine On\n\
         SecRule ARGS \"@contains evil\" \"id:1,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/s?safe=fine&payload=evil");

    let data = tx.matched_data();
    assert_eq!(data.len(), 1);
    assert_eq!(
        data[0].variable, "ARGS:payload",
        "the matching member should be named, got {:?}",
        data[0].variable
    );
}

#[test]
fn matched_var_is_readable_from_a_later_rule() {
    // MATCHED_VAR previously resolved to nothing, so a rule reading it could
    // never fire.
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:q \"@contains evil\" \"id:1,phase:1,pass,nolog\"\n\
         SecRule MATCHED_VAR \"@contains evil\" \"id:2,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/search?q=evil-input");
    assert!(
        tx.has_intervention(),
        "rule 2 should have seen what rule 1 matched"
    );
}

#[test]
fn matched_var_name_is_readable_from_a_later_rule() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:token \"@contains bad\" \"id:1,phase:1,pass,nolog\"\n\
         SecRule MATCHED_VAR_NAME \"@streq ARGS:token\" \"id:2,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/x?token=bad-value");
    assert!(tx.has_intervention());
}

/// `MATCHED_VARS` is scoped to the current rule in ModSecurity. If it
/// accumulated across rules, a later rule would read an earlier rule's match
/// and fire on evidence that has nothing to do with it.
#[test]
fn matched_vars_does_not_leak_between_rules() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:a \"@contains first\" \"id:1,phase:1,pass,nolog\"\n\
         SecRule ARGS:b \"@contains second\" \"id:2,phase:1,pass,nolog\"\n\
         SecRule MATCHED_VAR \"@contains first\" \"id:3,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/x?a=first-hit&b=second-hit");
    assert!(
        !tx.has_intervention(),
        "rule 3 should see rule 2's match, not rule 1's"
    );
}

#[test]
fn a_transaction_with_no_matches_reports_none() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:q \"@contains evil\" \"id:1,phase:1,deny\"";

    let tx = transaction_matching_uri(rules, "/search?q=harmless");
    assert!(tx.matched_data().is_empty());
}

/// A SecAction matches unconditionally and has no variable, so it must report
/// no matched data rather than an empty-named entry.
#[test]
fn a_secaction_contributes_no_matched_variable() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog\"";

    let tx = transaction_matching_uri(rules, "/");
    assert!(tx.matched_data().is_empty());
    assert_eq!(tx.matched_rules(), ["1"]);
}

#[test]
fn matched_data_accumulates_across_several_rules() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:a \"@contains x\" \"id:1,phase:1,pass,nolog\"\n\
         SecRule ARGS:b \"@contains y\" \"id:2,phase:1,pass,nolog\"";

    let tx = transaction_matching_uri(rules, "/q?a=xx&b=yy");
    let data = tx.matched_data();
    assert_eq!(data.len(), 2, "got {data:?}");
    assert_eq!(data[0].rule_id.as_deref(), Some("1"));
    assert_eq!(data[0].variable, "ARGS:a");
    assert_eq!(data[1].rule_id.as_deref(), Some("2"));
    assert_eq!(data[1].variable, "ARGS:b");
}
