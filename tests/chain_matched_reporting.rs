//! A chain that fails part-way did not match: it must leave nothing in
//! `matched_rules()` or `matched_data()` (zentinelproxy/zentinel-modsec#59).

use zentinel_modsec::ModSecurity;

/// The shape of CRS 920170: a GET without a body must not report the rule.
const RULE_920170: &str = "SecRuleEngine On\n\
    SecRule REQUEST_METHOD \"@rx ^(?:GET|HEAD)$\" \"id:920170,phase:1,block,chain\"\n\
    SecRule REQUEST_HEADERS:Content-Length \"!@rx ^0?$\" \"setvar:'tx.score=+5'\"";

fn run(rules: &str, headers: &[(&str, &str)]) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "GET",
        "HTTP/1.1",
    )
    .unwrap();
    tx.add_request_header("host", "example.com").unwrap();
    for (name, value) in headers {
        tx.add_request_header(name, value).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn an_incomplete_chain_is_not_in_matched_rules() {
    let tx = run(RULE_920170, &[]);
    assert!(tx.matched_rules().is_empty(), "{:?}", tx.matched_rules());
}

#[test]
fn an_incomplete_chain_leaves_no_matched_data() {
    let tx = run(RULE_920170, &[]);
    assert!(tx.matched_data().is_empty(), "{:?}", tx.matched_data());
}

#[test]
fn a_complete_chain_reports_every_link_under_the_starters_id() {
    let tx = run(RULE_920170, &[("content-length", "12")]);
    assert_eq!(tx.matched_rules(), ["920170"]);
    let data = tx.matched_data();
    assert_eq!(data.len(), 2, "{data:?}");
    assert!(data.iter().all(|d| d.rule_id.as_deref() == Some("920170")));
    assert_eq!(data[0].variable, "REQUEST_METHOD");
    assert_eq!(data[0].value, "GET");
    assert_eq!(data[1].value, "12");
}

#[test]
fn a_failed_chain_does_not_hide_a_later_rules_data() {
    let rules = format!(
        "{RULE_920170}\n\
         SecRule REQUEST_METHOD \"@streq GET\" \"id:2,phase:1,pass\""
    );
    let tx = run(&rules, &[]);
    assert_eq!(tx.matched_rules(), ["2"]);
    let data = tx.matched_data();
    assert_eq!(data.len(), 1, "{data:?}");
    assert_eq!(data[0].rule_id.as_deref(), Some("2"));
}

#[test]
fn a_three_link_chain_failing_on_the_last_link_leaves_nothing() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"id:3,phase:1,pass,chain\"\n\
        SecRule REQUEST_HEADERS:Host \"@streq example.com\" \"chain\"\n\
        SecRule REQUEST_URI \"@contains nothing-here\"";
    let tx = run(rules, &[]);
    assert!(tx.matched_rules().is_empty());
    assert!(tx.matched_data().is_empty(), "{:?}", tx.matched_data());
}
