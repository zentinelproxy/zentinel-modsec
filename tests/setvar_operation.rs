//! A `setvar` right-hand side is an assignment, an addition or a subtraction
//! according to how it is written in the rule, not according to what its
//! macros expand to.
//!
//! libmodsecurity fixes the operation when it parses the rule: `=+` and `=-`
//! are tokens of their own (`seclang-scanner.ll:489-490`, mapped to
//! `sumAndSetOperation` and `substractAndSetOperation` at
//! `seclang-parser.yy:3145-3152`), and only the operand after them is expanded
//! at run time (`actions/set_var.cc:38-123`). The operand is read with `stoi`
//! and is 0 when that throws (`set_var.cc:93-100`).
//!
//! The engine used to expand the whole right-hand side first and read the sign
//! afterwards, so a captured `-7` turned `setvar:tx.x=%{tx.0}` into a
//! decrement.

use zentinel_modsec::engine::Transaction;
use zentinel_modsec::ModSecurity;

/// Run `rules` against a request for `uri`.
fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

fn tx_var(tx: &Transaction, name: &str) -> String {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

/// Rules that capture `capture` from the URI into `TX:0`, start `tx.n` at 10,
/// then run `setvar` on it.
fn with_capture(capture: &str, setvar: &str) -> String {
    format!(
        "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@rx {capture}\" \"id:1,phase:1,pass,nolog,capture,setvar:tx.n=10\"\n\
         SecRule REQUEST_URI \"@rx {capture}\" \"id:2,phase:1,pass,nolog,capture,setvar:{setvar}\""
    )
}

#[test]
fn a_captured_negative_number_is_assigned_not_subtracted() {
    // `%{tx.0}` is `-7`. Assignment: the variable holds the text `-7`.
    let rules = with_capture("-7$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&rules, "/x-7"), "n"), "-7");
}

#[test]
fn a_captured_positive_sign_is_assigned_not_added() {
    let rules = with_capture("[+]7$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&rules, "/x+7"), "n"), "+7");
}

#[test]
fn add_and_subtract_macros_still_do_arithmetic() {
    // The sign of the operand is the operand's own: 10 + (-7), 10 - (-7).
    let add = with_capture("-7$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x-7"), "n"), "3");
    let sub = with_capture("-7$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/x-7"), "n"), "17");
    // And an unsigned operand, the CRS shape.
    let add = with_capture("7$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x7"), "n"), "17");
    let sub = with_capture("7$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/x7"), "n"), "3");
}

#[test]
fn a_literal_sign_is_unchanged() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.a=10,setvar:tx.a=+5,setvar:tx.b=10,setvar:tx.b=-5,setvar:tx.c=-5\"";
    let tx = run(rules, "/x");
    assert_eq!(tx_var(&tx, "a"), "15");
    assert_eq!(tx_var(&tx, "b"), "5");
    // `=-5` on an unset variable subtracts from 0, it does not assign -5.
    assert_eq!(tx_var(&tx, "c"), "-5");
}

#[test]
fn a_non_numeric_operand_counts_as_zero() {
    // `stoi` throws on `abc`, and libmodsecurity takes 0: n stays 10.
    let add = with_capture("abc$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/xabc"), "n"), "10");
    let sub = with_capture("abc$", "tx.n=-%{tx.0}");
    assert_eq!(tx_var(&run(&sub, "/xabc"), "n"), "10");
    // As an assignment the text is kept as it is.
    let set = with_capture("abc$", "tx.n=%{tx.0}");
    assert_eq!(tx_var(&run(&set, "/xabc"), "n"), "abc");
}

#[test]
fn an_operand_is_read_up_to_its_first_non_digit() {
    // `stoi("5abc")` is 5.
    let add = with_capture("5abc$", "tx.n=+%{tx.0}");
    assert_eq!(tx_var(&run(&add, "/x5abc"), "n"), "15");
    // The operand may also be built from macros and text.
    let sub = with_capture("[0-9]+", "tx.n=-%{tx.0}0");
    assert_eq!(tx_var(&run(&sub, "/x3"), "n"), "-20");
}

#[test]
fn an_empty_operand_counts_as_zero() {
    // A macro that expands to nothing.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.n=10,setvar:tx.n=+%{tx.nosuch},setvar:tx.m=10,setvar:tx.m=-%{tx.nosuch}\"";
    let tx = run(rules, "/x");
    assert_eq!(tx_var(&tx, "n"), "10");
    assert_eq!(tx_var(&tx, "m"), "10");
}

#[test]
fn the_crs_score_shape_is_unchanged() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx x\" \"id:1,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5,setvar:tx.score=+%{tx.critical_anomaly_score},setvar:tx.score=+%{tx.critical_anomaly_score}\"";
    assert_eq!(tx_var(&run(rules, "/x"), "score"), "10");
}

#[test]
fn capture_clears_the_slots_the_match_did_not_fill() {
    // The first rule fills TX:1 and TX:2, the second only TX:1. In
    // libmodsecurity v3 TX:2 would keep the first rule's value
    // (`operators/rx.cc:104-113` stores, and never removes); this engine
    // clears it, so a later rule cannot read a leftover.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@rx (a)(b)\" \"id:1,phase:1,pass,nolog,capture\"\n\
        SecRule REQUEST_URI \"@rx (a)\" \"id:2,phase:1,pass,nolog,capture,setvar:tx.one=%{tx.1},setvar:tx.two=%{tx.2}\"";
    let tx = run(rules, "/ab");
    assert_eq!(tx_var(&tx, "one"), "a");
    assert_eq!(tx_var(&tx, "two"), "");
}
