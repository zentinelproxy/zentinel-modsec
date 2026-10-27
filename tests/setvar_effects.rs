//! `Transaction::setvar_effects()`: what each rule did to a collection.
//!
//! The engine records the effects without interpreting them. The last test
//! shows the consumer side with stock CRS: the rules behind an anomaly-score
//! block are the ones with a positive `Increment` of an `*anomaly_score_pl*`
//! key.

use std::path::PathBuf;
use zentinel_modsec::engine::{SetVarChange, SetVarEffect, Transaction};
use zentinel_modsec::ModSecurity;

fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-Tag", "blue").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn effect(rule_id: &str, key: &str, op: SetVarChange) -> SetVarEffect {
    SetVarEffect {
        rule_id: rule_id.to_string(),
        collection: "tx".to_string(),
        key: key.to_string(),
        op,
    }
}

#[test]
fn set_increment_decrement_and_delete_are_recorded_in_order() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:2,pass,nolog,setvar:'tx.name=abc',setvar:'tx.count=5',setvar:'tx.score=+3'\"\n\
        SecRule REQUEST_URI \"@contains go\" \"id:2,phase:2,pass,nolog,setvar:'tx.score=-1',setvar:'!tx.name'\"";
    let tx = run(rules, "/go");
    assert_eq!(
        tx.setvar_effects(),
        [
            effect("1", "name", SetVarChange::Set("abc".into())),
            // A numeric assignment is a Set, as in the engine's own TX.
            effect("1", "count", SetVarChange::Set("5".into())),
            effect("1", "score", SetVarChange::Increment(3)),
            effect("2", "score", SetVarChange::Decrement(1)),
            effect("2", "name", SetVarChange::Delete),
        ]
    );
}

#[test]
fn nothing_is_recorded_unless_asked() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:2,pass,nolog,setvar:'tx.score=+3'\"";
    let msc = ModSecurity::from_string(rules).unwrap();
    let mut tx = msc.new_transaction();
    tx.process_uri("/go", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.setvar_effects().is_empty());
    assert_eq!(tx.matched_rules(), ["1"]);
}

#[test]
fn rules_that_do_not_match_record_nothing() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:1,phase:2,pass,nolog,setvar:'tx.score=+3'\"";
    assert!(run(rules, "/stay").setvar_effects().is_empty());
}

#[test]
fn a_chain_links_effects_belong_to_the_starter() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:10,phase:2,pass,nolog,chain,setvar:'tx.seen=1'\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"chain,setvar:'tx.mid=+1'\"\n\
        SecRule REQUEST_HEADERS:Host \"@streq example.com\" \"setvar:'tx.inbound_anomaly_score_pl1=+5'\"";
    let tx = run(rules, "/go");
    assert_eq!(
        tx.setvar_effects(),
        [
            effect("10", "seen", SetVarChange::Set("1".into())),
            effect("10", "mid", SetVarChange::Increment(1)),
            effect(
                "10",
                "inbound_anomaly_score_pl1",
                SetVarChange::Increment(5)
            ),
        ]
    );
    assert_eq!(tx.matched_rules(), ["10"]);
}

#[test]
fn a_failed_chain_keeps_the_effects_of_the_links_that_ran() {
    // libmodsecurity runs a link's setvar when that link matches, so the
    // starter's effect is real even though the chain never completes. Whoever
    // reads the list can tell: the rule is absent from `matched_rules()`.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains go\" \"id:10,phase:2,pass,nolog,chain,setvar:'tx.seen=1'\"\n\
        SecRule REQUEST_METHOD \"@streq POST\" \"setvar:'tx.score=+5'\"";
    let tx = run(rules, "/go");
    assert_eq!(
        tx.setvar_effects(),
        [effect("10", "seen", SetVarChange::Set("1".into()))]
    );
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn a_rule_matching_several_values_records_an_effect_for_each() {
    // The operator runs against every header name; setvar runs for each match
    // (as libmodsecurity does), and each run is an effect. A macro in the
    // variable name is recorded expanded.
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_HEADERS_NAMES \"@rx ^x-.*$\" \"id:30,phase:1,pass,nolog,capture,t:lowercase,setvar:'tx.hits=+1',setvar:'tx.seen_%{tx.0}=1'\"";
    let msc = ModSecurity::from_string(rules).unwrap();
    let mut tx = msc.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("X-A", "1").unwrap();
    tx.add_request_header("X-B", "2").unwrap();
    tx.process_request_headers().unwrap();
    assert_eq!(
        tx.setvar_effects(),
        [
            effect("30", "hits", SetVarChange::Increment(1)),
            effect("30", "seen_x-a", SetVarChange::Set("1".into())),
            effect("30", "hits", SetVarChange::Increment(1)),
            effect("30", "seen_x-b", SetVarChange::Set("1".into())),
        ]
    );
}

#[test]
fn macros_are_recorded_expanded() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:900,phase:1,pass,nolog,setvar:'tx.critical_anomaly_score=5'\"\n\
        SecRule REQUEST_URI \"@rx ^/(\\w+)\" \"id:20,phase:2,pass,nolog,capture,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
        setvar:'tx.path=%{tx.1}',\
        setvar:'tx.tag=%{request_headers.x-tag}',\
        setvar:'tx.down=-%{tx.critical_anomaly_score}'\"";
    let tx = run(rules, "/go");
    assert_eq!(
        tx.setvar_effects(),
        [
            effect(
                "900",
                "critical_anomaly_score",
                SetVarChange::Set("5".into())
            ),
            effect(
                "20",
                "inbound_anomaly_score_pl1",
                SetVarChange::Increment(5)
            ),
            effect("20", "path", SetVarChange::Set("go".into())),
            effect("20", "tag", SetVarChange::Set("blue".into())),
            effect("20", "down", SetVarChange::Decrement(5)),
        ]
    );
}

/// The consumer side, on stock CRS: findings behind an anomaly-score block.
/// The engine knows nothing about `anomaly_score_pl`; this filter does.
#[test]
fn stock_crs_xss_scores_are_increments_of_the_anomaly_score_variable() {
    if std::env::var_os("SKIP_CRS_CONFORMANCE").is_some() {
        return;
    }
    let dir = std::env::var("CRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test-rules/crs"));
    assert!(
        dir.join("crs-setup.conf").is_file(),
        "OWASP CRS checkout not found at {} (see tests/crs_conformance.rs); \
         SKIP_CRS_CONFORMANCE=1 skips this test locally.",
        dir.display()
    );
    let d = std::fs::canonicalize(&dir).unwrap();
    let d = d.display();
    let cfg = format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\n\
         Include \"{d}/crs-setup.conf\"\nInclude \"{d}/rules/*.conf\"\n"
    );
    let msc = ModSecurity::from_string(&cfg).expect("CRS should load");

    let mut tx = msc.new_transaction();
    tx.set_record_setvar_effects(true);
    tx.process_uri("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "GET", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    )
    .unwrap();
    tx.add_request_header("Accept", "text/html").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    assert!(tx.has_intervention(), "the XSS request should be blocked");

    let scoring: Vec<&SetVarEffect> = tx
        .setvar_effects()
        .iter()
        .filter(|e| {
            e.key.contains("anomaly_score_pl")
                && matches!(e.op, SetVarChange::Increment(n) if n > 0)
        })
        .collect();
    let ids: Vec<&str> = scoring.iter().map(|e| e.rule_id.as_str()).collect();
    println!("scoring rules: {ids:?}");
    assert!(
        ids.iter().any(|id| id.starts_with("941")),
        "expected a 941xxx rule among {ids:?}"
    );
    // CRS adds the severity's score through a macro; it is recorded expanded.
    assert!(scoring.iter().all(|e| e.collection == "tx"));
    assert!(scoring
        .iter()
        .any(|e| matches!(e.op, SetVarChange::Increment(5))));

    // The record accounts for the variable's value: the sum of the increments
    // is the score the blocking rule saw.
    use zentinel_modsec::variables::Collection;
    let recorded: i64 = tx
        .setvar_effects()
        .iter()
        .filter(|e| e.key == "inbound_anomaly_score_pl1")
        .map(|e| match e.op {
            SetVarChange::Increment(n) => n,
            SetVarChange::Decrement(n) => -n,
            _ => 0,
        })
        .sum();
    let actual: i64 = tx
        .tx()
        .get("inbound_anomaly_score_pl1")
        .and_then(|v| v.first().and_then(|s| s.parse().ok()))
        .unwrap_or(0);
    assert!(recorded > 0);
    assert_eq!(recorded, actual);
}
