//! TX variables belong to the rules that set them: finishing a phase leaves
//! them as they are.
//!
//! libmodsecurity creates the TX collection with the transaction
//! (`collection/collections.cc`) and changes it only through actions and
//! operators. It has no notion of an anomaly score; that is a CRS convention
//! carried entirely by `setvar`.
//!
//! The engine used to write `tx.anomaly_score` and seven per-category scores
//! (`tx.sql_injection_score`, `tx.xss_score`, ...) at the end of every phase
//! from a tracker of its own that only followed `tx.anomaly_score`, so a score
//! a rule had accumulated in one phase was 0 in the next.

use zentinel_modsec::engine::Transaction;
use zentinel_modsec::variables::{Collection, MutableCollection};
use zentinel_modsec::ModSecurity;

const SCORE_VARIABLES: [&str; 8] = [
    "anomaly_score",
    "sql_injection_score",
    "xss_score",
    "rfi_score",
    "lfi_score",
    "rce_score",
    "php_injection_score",
    "session_fixation_score",
];

fn transaction(rules: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx
}

fn tx_var(tx: &Transaction, name: &str) -> Option<String> {
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
}

#[test]
fn scores_set_in_one_phase_are_read_in_the_next() {
    let setvars: String = SCORE_VARIABLES
        .iter()
        .map(|name| format!(",setvar:tx.{name}=+5"))
        .collect();
    let rules = format!(
        "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog{setvars}\"\n\
         SecRule TX:sql_injection_score \"@ge 5\" \"id:2,phase:2,deny,status:403\""
    );
    let mut tx = transaction(&rules);

    tx.process_request_headers().unwrap();
    for name in SCORE_VARIABLES {
        assert_eq!(tx_var(&tx, name).as_deref(), Some("5"), "{name}");
    }

    tx.process_request_body().unwrap();
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert!(tx.has_intervention());
}

#[test]
fn a_score_keeps_accumulating_across_phases() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,setvar:tx.xss_score=+5\"\n\
         SecAction \"id:2,phase:2,pass,nolog,setvar:tx.xss_score=+5\"\n\
         SecAction \"id:3,phase:3,pass,nolog,setvar:tx.anomaly_score=+%{tx.xss_score}\"";
    let mut tx = transaction(rules);
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.process_response_headers().unwrap();
    assert_eq!(tx_var(&tx, "xss_score").as_deref(), Some("10"));
    assert_eq!(tx_var(&tx, "anomaly_score").as_deref(), Some("10"));
    assert_eq!(tx.anomaly_score(), 10);
}

#[test]
fn a_phase_does_not_create_score_variables() {
    // `&TX:anomaly_score "@eq 0"` is how a ruleset tests for a variable it
    // has not set yet.
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog\"\n\
         SecRule &TX:anomaly_score \"@eq 0\" \"id:2,phase:2,pass,nolog\"";
    let mut tx = transaction(rules);
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    for name in SCORE_VARIABLES {
        assert_eq!(tx_var(&tx, name), None, "{name}");
    }
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    assert_eq!(tx.anomaly_score(), 0);
}

#[test]
fn anomaly_score_reads_the_tx_variable() {
    let mut tx = transaction("SecRuleEngine On");
    tx.tx_mut().set("anomaly_score".into(), "8".into());
    assert_eq!(tx.anomaly_score(), 8);
    tx.process_request_headers().unwrap();
    assert_eq!(tx.anomaly_score(), 8);
    tx.tx_mut().delete("anomaly_score");
    assert_eq!(tx.anomaly_score(), 0);
}
