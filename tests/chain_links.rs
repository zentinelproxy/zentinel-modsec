//! Chain links other than the starter lost their actions, and `capture`
//! never filled TX:0..9.
//!
//! * The `setvar` that CRS puts on the *last* link (the anomaly score) never
//!   ran, so ~70 CRS rules detected an attack and scored 0. libmodsecurity runs
//!   every link's `setvar` as soon as that link matches
//!   (src/rule_with_actions.cc, executeActionsIndependentOfChainedRuleResult);
//!   these tests pin that behaviour.
//! * `matched_rules()` listed a chain's starter even when the chain failed.
//! * `capture` did not expose the match, so `setvar:tx.x=%{tx.0}` stored an
//!   empty value (CRS 920420).

use zentinel_modsec::ModSecurity;

fn run(rules: &str, uri: &str) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn tx_var(tx: &zentinel_modsec::engine::Transaction, name: &str) -> String {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

#[test]
fn setvar_on_the_last_chain_link_runs() {
    // The CRS shape: the score is on the final link.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:10,phase:2,pass,nolog,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"setvar:'tx.score=+5'\"";
    assert_eq!(tx_var(&run(rules, "/attack"), "score"), "5");
    // A chain that does not complete scores nothing.
    assert_eq!(tx_var(&run(rules, "/benign"), "score"), "-");
}

#[test]
fn every_links_setvar_runs_when_the_link_matches() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:11,phase:2,pass,nolog,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"setvar:'tx.mid=1',chain\"\n\
        SecRule REQUEST_PROTOCOL \"@streq HTTP/1.1\" \"setvar:'tx.last=1'\"";
    let tx = run(rules, "/attack");
    assert_eq!(tx_var(&tx, "mid"), "1");
    assert_eq!(tx_var(&tx, "last"), "1");

    // libmodsecurity does not undo a link's setvar when a later link fails.
    let rules_fail = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:12,phase:2,pass,nolog,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"setvar:'tx.mid=1',chain\"\n\
        SecRule REQUEST_PROTOCOL \"@streq HTTP/9\" \"setvar:'tx.last=1'\"";
    let tx = run(rules_fail, "/attack");
    assert_eq!(tx_var(&tx, "mid"), "1");
    assert_eq!(tx_var(&tx, "last"), "-");
}

#[test]
fn a_starters_setvar_is_visible_to_the_next_link() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:15,phase:2,pass,nolog,setvar:'tx.seen=yes',chain\"\n\
        SecRule TX:seen \"@streq yes\" \"setvar:'tx.second=1'\"";
    assert_eq!(tx_var(&run(rules, "/attack"), "second"), "1");
}

#[test]
fn a_failed_chain_is_not_reported_as_matched() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:13,phase:2,pass,chain\"\n\
        SecRule REQUEST_METHOD \"@streq POST\"";
    assert!(!run(rules, "/attack")
        .matched_rules()
        .contains(&"13".to_string()));
    let ok = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:14,phase:2,pass,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\"";
    assert!(run(ok, "/attack")
        .matched_rules()
        .contains(&"14".to_string()));
}

#[test]
fn capture_exposes_the_match_and_groups_as_tx_0_to_9() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx ^/(\\w+)/(\\w+)\" \"id:60,phase:2,pass,nolog,capture,setvar:'tx.whole=%{tx.0}',setvar:'tx.g1=%{tx.1}',setvar:'tx.g2=%{tx.2}'\"";
    let tx = run(rules, "/abc/def?x=1");
    assert_eq!(tx_var(&tx, "whole"), "/abc/def");
    assert_eq!(
        (tx_var(&tx, "g1"), tx_var(&tx, "g2")),
        ("abc".into(), "def".into())
    );
}

#[test]
fn crs_920420_shape_a_captured_value_is_tested_by_the_next_link() {
    // starter: capture + setvar of %{tx.0}; link 2 tests it against a list.
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.allowed=|text/plain| |application/json|'\"\n\
        SecRule REQUEST_HEADERS:Content-Type \"@rx ^[^;\\s]+\" \"id:2,phase:1,pass,nolog,capture,setvar:'tx.ct=|%{tx.0}|',chain\"\n\
        SecRule TX:ct \"!@within %{tx.allowed}\" \"t:lowercase,setvar:'tx.score=+5'\"";
    let run_ct = |ct: &str| {
        let msc = ModSecurity::from_string(rules).unwrap();
        let mut tx = msc.new_transaction();
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", ct).unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx_var(&tx, "score")
    };
    assert_eq!(
        run_ct("application/json; charset=utf-8"),
        "-",
        "allowed type scores nothing"
    );
    assert_eq!(
        run_ct("Text/Plain"),
        "-",
        "lowercase transformation applies to the TX value"
    );
    assert_eq!(run_ct("application/x-weird"), "5", "unknown type scores");
}

#[test]
fn macros_resolve_request_headers_and_the_matched_variable() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:70,phase:2,pass,nolog,setvar:'tx.host=%{request_headers.host}',setvar:'tx.mv=%{matched_var}',setvar:'tx.mvn=%{matched_var_name}'\"\n\
        SecRule REQUEST_HEADERS:Host \"!@endsWith %{request_headers.host}\" \"id:71,phase:2,pass,nolog,setvar:'tx.mismatch=1'\"";
    let tx = run(rules, "/attack");
    assert_eq!(tx_var(&tx, "host"), "example.com");
    assert_eq!(tx_var(&tx, "mv"), "/attack");
    assert_eq!(tx_var(&tx, "mvn"), "REQUEST_URI");
    // The header is compared with itself, so the negated operator is false.
    assert_eq!(tx_var(&tx, "mismatch"), "-");
}

/// A request with the given extra headers (Host is always present).
fn run_with_headers(rules: &str, headers: &[&str]) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    for h in headers {
        tx.add_request_header(h, "test").unwrap();
    }
    tx.process_request_headers().unwrap();
    tx
}

#[test]
fn setvar_and_capture_run_once_for_every_matched_variable() {
    // libmodsecurity runs the operator against every value and the rule's
    // setvar for each one that matches: three header names, three increments,
    // and TX:0 ends as the last match.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_HEADERS_NAMES \"@rx ^.*$\" \"id:80,phase:1,pass,nolog,capture,t:lowercase,setvar:'tx.hits=+1',setvar:'tx.last=%{tx.0}'\"";
    let tx = run_with_headers(rules, &["X-A", "X-B"]);
    assert_eq!(tx_var(&tx, "hits"), "3");
    assert_eq!(tx_var(&tx, "last"), "x-b");
}

#[test]
fn a_setvar_name_with_a_macro_makes_one_variable_per_match() {
    // CRS 920450: the starter records every request header under its own name
    // and the chained `@within` looks for a restricted one among them, whatever
    // its position.
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:'tx.restricted=/lock-token/ /if/'\"\n\
        SecRule REQUEST_HEADERS_NAMES \"@rx ^.*$\" \"id:80,phase:1,pass,nolog,capture,t:lowercase,setvar:'tx.header_name_80_%{tx.0}=/%{tx.0}/',chain\"\n\
        SecRule TX:/^header_name_80_/ \"@within %{tx.restricted}\" \"setvar:'tx.score=+5'\"";
    for headers in [
        &["If", "Accept"][..],
        &["Accept", "If"],
        &["Accept", "Lock-Token", "X-Other"],
    ] {
        let tx = run_with_headers(rules, headers);
        assert_eq!(tx_var(&tx, "score"), "5", "{headers:?}");
        assert!(
            tx.matched_rules().contains(&"80".to_string()),
            "{headers:?}"
        );
    }
    let tx = run_with_headers(rules, &["Accept", "Range"]);
    assert_eq!(tx_var(&tx, "score"), "-");
    assert_eq!(tx_var(&tx, "header_name_80_range"), "/range/");
}
