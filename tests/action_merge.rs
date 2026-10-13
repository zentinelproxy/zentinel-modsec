//! Several actions of one kind on a rule (`t:a,t:b`, `setvar:x,setvar:y`,
//! `tag:`, `ctl:`) were merged into the last one only, because the merge of
//! rule actions into `SecDefaultAction` defaults compared actions by variant
//! and dropped every earlier action of the same variant -- including earlier
//! actions of the same rule. CRS has ~80 rules with several `t:` after
//! `t:none` and ~50 with several `setvar:`.

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
fn several_setvar_on_one_rule_all_run() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains x\" \"id:20,phase:2,pass,nolog,setvar:'tx.a=1',setvar:'tx.b=2',setvar:'tx.c=3'\"";
    let tx = run(rules, "/x");
    assert_eq!(
        (tx_var(&tx, "a"), tx_var(&tx, "b"), tx_var(&tx, "c")),
        ("1".into(), "2".into(), "3".into())
    );
}

#[test]
fn several_transformations_all_apply() {
    // The payload decodes only if both t:urlDecodeUni and t:lowercase apply:
    // "%41TTACK" -> "ATTACK" -> "attack". Keeping only the last t: (lowercase)
    // would leave the "%41" undecoded and miss.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:q \"@contains attack\" \"id:21,phase:2,pass,nolog,t:none,t:urlDecodeUni,t:lowercase,setvar:'tx.hit=1'\"";
    assert_eq!(tx_var(&run(rules, "/?q=%2541TTACK"), "hit"), "1");
}

#[test]
fn several_tags_are_all_kept() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains x\" \"id:22,phase:2,pass,nolog,tag:'one',tag:'two'\"";
    // Loading with two tags must succeed and the rule must still run.
    assert!(run(rules, "/x").matched_rules().contains(&"22".to_string()));
}

#[test]
fn several_ctl_actions_all_run() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains x\" \"id:30,phase:1,pass,nolog,ctl:ruleRemoveById=31,ctl:ruleRemoveById=32\"\n\
        SecRule REQUEST_URI \"@contains x\" \"id:31,phase:2,pass,nolog,setvar:'tx.r31=1'\"\n\
        SecRule REQUEST_URI \"@contains x\" \"id:32,phase:2,pass,nolog,setvar:'tx.r32=1'\"";
    let tx = run(rules, "/x");
    assert_eq!(tx_var(&tx, "r31"), "-");
    assert_eq!(tx_var(&tx, "r32"), "-");
}

#[test]
fn nolog_overrides_a_default_log_but_not_other_actions() {
    let rules = "SecRuleEngine On\n\
        SecDefaultAction \"phase:2,log,auditlog,pass\"\n\
        SecRule REQUEST_URI \"@contains x\" \"id:40,phase:2,nolog,setvar:'tx.n=1',setvar:'tx.m=2'\"";
    let tx = run(rules, "/x");
    assert_eq!(
        (tx_var(&tx, "n"), tx_var(&tx, "m")),
        ("1".into(), "2".into())
    );
}
