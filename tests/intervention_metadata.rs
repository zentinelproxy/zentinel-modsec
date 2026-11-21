//! An intervention reports the metadata of the rule that caused it: `id`,
//! `msg`, `tag`, `severity`. For a chain that is the starter, whose actions
//! the chain runs, not the link that completed it.

use zentinel_modsec::{Intervention, ModSecurity};

fn intervention(rules: &str, uri: &str) -> Intervention {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.intervention()
        .cloned()
        .expect("the request should be denied")
}

#[test]
fn a_denying_rule_reports_its_metadata() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \"id:1,phase:2,pass,msg:'passing',tag:'other'\"\n\
        SecRule ARGS:a \"@streq x\" \
        \"id:2,phase:2,deny,status:403,msg:'denied here',severity:2,tag:'attack',tag:'local'\"\n";
    let intervention = intervention(rules, "/?a=x");

    assert_eq!(intervention.metadata.len(), 1);
    let metadata = &intervention.metadata[0];
    assert_eq!(metadata.id.as_deref(), Some("2"));
    assert_eq!(metadata.msg.as_deref(), Some("denied here"));
    assert_eq!(metadata.severity, Some(2));
    assert_eq!(metadata.tags, ["attack", "local"]);
}

#[test]
fn a_denying_chain_reports_the_metadata_of_its_starter() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq x\" \
        \"id:3,phase:2,deny,status:403,msg:'chain starter',tag:'starter',chain\"\n\
        SecRule ARGS:b \"@streq y\" \"t:none\"\n";
    let intervention = intervention(rules, "/?a=x&b=y");

    assert_eq!(intervention.metadata.len(), 1);
    let metadata = &intervention.metadata[0];
    assert_eq!(metadata.id.as_deref(), Some("3"));
    assert_eq!(metadata.msg.as_deref(), Some("chain starter"));
    assert_eq!(metadata.tags, ["starter"]);
}
