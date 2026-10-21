//! `Transaction::scoring_rules()`: the findings behind an anomaly-score block.

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

#[test]
fn scoring_rules_lists_the_rules_that_raised_the_anomaly_score() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:900990,phase:1,pass,nolog,setvar:'tx.inbound_anomaly_score_pl1=0'\"\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:941100,phase:2,pass,nolog,setvar:'tx.inbound_anomaly_score_pl1=+5'\"\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:941101,phase:2,pass,nolog,setvar:'tx.sql_injection_score=+5'\"\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:941102,phase:2,pass,nolog,chain\"\n\
        SecRule REQUEST_METHOD \"@streq GET\" \"setvar:'tx.inbound_anomaly_score_pl2=+3'\"\n\
        SecRule REQUEST_URI \"@contains attack\" \"id:941103,phase:2,pass,nolog,chain\"\n\
        SecRule REQUEST_METHOD \"@streq POST\" \"setvar:'tx.inbound_anomaly_score_pl1=+5'\"";
    // Only increments of an anomaly-score variable count: not the setup
    // action (=0), not a category score, not a chain that did not complete.
    // A chain's score is attributed to its starter.
    assert_eq!(run(rules, "/attack").scoring_rules(), ["941100", "941102"]);
    assert!(run(rules, "/benign").scoring_rules().is_empty());
}
